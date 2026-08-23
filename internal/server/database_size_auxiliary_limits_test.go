package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDatabaseAuxiliarySizeLimitParsing(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				"{0}users size.unchecked=disabled size.pr=noEstimate size.pr=7 size.prtotal=hard",
				"{1}anonymous size.unchecked=unlimited size.pr=unlimited size.prtotal=disabled",
			),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatalf("load auxiliary size limits: %v", err)
	}
	if len(limits) != 2 {
		t.Fatalf("limits = %#v", limits)
	}
	users := limits[0]
	if !users.uncheckedSet || users.unchecked != 0 ||
		!users.pageEstimateSet || !users.pageNoEstimate ||
		!users.pageSizeSet || users.pageSize != 7 ||
		!users.pageTotalSet || users.pageTotal != 0 {
		t.Fatalf("users limits = %#v", users)
	}
	anonymous := limits[1]
	if anonymous.unchecked != -1 || anonymous.pageSize != -1 ||
		anonymous.pageTotal != -2 {
		t.Fatalf("anonymous limits = %#v", anonymous)
	}

	for _, value := range []string{
		"users size.unchecked=hard",
		"users size.pr=disabled",
		"users size.prtotal=noEstimate",
		"users size.unchecked=-2",
	} {
		invalid := entry.Clone()
		invalid.ReplaceValues("olcLimits", stringValues(value))
		if _, err := loadDatabaseSearchSizeLimits(invalid); err == nil {
			t.Fatalf("invalid olcLimits %q was accepted", value)
		}
	}
}

func TestDatabaseUnsupportedLimitSelectorsFailClosed(t *testing.T) {
	for _, selector := range []string{
		`group="cn=limit-admins,dc=example,dc=com"`,
		`dn.regex="^uid=.*"`,
		`dn.this.subtree="ou=people,dc=example,dc=com"`,
	} {
		entry := directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcLimits",
				Values:      stringValues(selector + " size=2"),
			}},
		}
		_, err := loadDatabaseSearchSizeLimits(entry)
		if err == nil || !strings.Contains(err.Error(), "is not supported") {
			t.Fatalf("selector %q error = %v", selector, err)
		}
	}

	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values:      stringValues(`dn.regex=".*" size=2`),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil || len(limits) != 1 || limits[0].selector != databaseSearchLimitAny {
		t.Fatalf("universal regex limit = %#v, %v", limits, err)
	}
}

func TestDatabaseUnsupportedLimitSelectorOnlineRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	config, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("bind cn=config: %v", err)
	}
	const databaseDN = "olcDatabase={1}mdb,cn=config"
	const valid = "anonymous size.soft=2 size.hard=2"
	modify := ldap.NewModifyRequest(databaseDN, nil)
	modify.Replace("olcLimits", []string{valid})
	if err := config.Modify(modify); err != nil {
		t.Fatalf("install valid limit: %v", err)
	}

	for _, invalid := range []string{
		`group="cn=limit-admins,dc=example,dc=com" size=3`,
		`dn.regex="^uid=.*" size=3`,
		`dn.this.subtree="ou=people,dc=example,dc=com" size=3`,
	} {
		modify = ldap.NewModifyRequest(databaseDN, nil)
		modify.Replace("olcLimits", []string{invalid})
		modifyErr := config.Modify(modify)
		var ldapErr *ldap.Error
		if !errors.As(modifyErr, &ldapErr) ||
			ldapErr.ResultCode != ldap.LDAPResultConstraintViolation ||
			!strings.Contains(ldapErr.Err.Error(), "olcLimits selector") ||
			!strings.Contains(ldapErr.Err.Error(), "is not supported") {
			t.Fatalf("unsupported selector Modify error = %v", modifyErr)
		}
		stored, err := config.Search(ldap.NewSearchRequest(
			databaseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"olcLimits"},
			nil,
		))
		if err != nil || len(stored.Entries) != 1 ||
			!slices.Equal(stored.Entries[0].GetAttributeValues("olcLimits"), []string{valid}) {
			t.Fatalf("olcLimits after rollback = %#v, %v", stored, err)
		}
	}

	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer anonymous.Close()
	result, err := anonymous.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	assertAuxiliaryLDAPError(t, err, ldap.LDAPResultSizeLimitExceeded, "")
	if len(result.Entries) != 2 {
		t.Fatalf("entries after rollback = %d, want 2", len(result.Entries))
	}
}

func TestFrontendDatabaseLimitsInheritPerField(t *testing.T) {
	frontend := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		soft:            10,
		softSet:         true,
		hard:            20,
		hardSet:         true,
		unchecked:       30,
		uncheckedSet:    true,
		pageSize:        4,
		pageSizeSet:     true,
		pageTotal:       40,
		pageTotalSet:    true,
		pageNoEstimate:  true,
		pageEstimateSet: true,
		timeSoft:        5,
		timeSoftSet:     true,
		timeHard:        10,
		timeHardSet:     true,
		databaseDefault: true,
	}
	local := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		soft:            7,
		softSet:         true,
		pageSize:        2,
		pageSizeSet:     true,
		timeHard:        9,
		timeHardSet:     true,
		databaseDefault: true,
	}
	databases := []runtimeDatabase{
		{name: "{-1}frontend", searchSizeLimits: []databaseSearchSizeLimit{frontend}},
		{name: "{1}mdb", searchSizeLimits: []databaseSearchSizeLimit{local}},
	}
	applyFrontendDatabaseDefaults(databases)
	runtime := &runtimeState{databases: databases}
	defaults := effectiveDatabaseSearchExecutionLimits(
		runtime,
		databases[1],
		"uid=user,dc=example,dc=com",
		100,
		0,
		0,
	)
	if defaults.size != 7 || defaults.time != 5 ||
		defaults.unchecked != 30 || defaults.pageSize != 2 ||
		defaults.pageTotal != 40 || !defaults.pageNoEstimate {
		t.Fatalf("inherited defaults = %#v", defaults)
	}
	explicit := effectiveDatabaseSearchExecutionLimits(
		runtime,
		databases[1],
		"uid=user,dc=example,dc=com",
		100,
		15,
		8,
	)
	if explicit.size != 15 || explicit.time != 8 {
		t.Fatalf("inherited hard limits = %#v", explicit)
	}
}

func TestDatabaseLimitHardValuesNormalizeLikeOpenLDAP(t *testing.T) {
	for _, test := range []struct {
		name      string
		value     string
		request   int
		want      int
		pageTotal int
	}{
		{
			name:      "hard below soft",
			value:     "users size.soft=6 size.hard=3 time.soft=6 time.hard=3",
			request:   5,
			want:      5,
			pageTotal: 6,
		},
		{
			name:      "unlimited soft",
			value:     "users size.soft=unlimited size.hard=5 time.soft=unlimited time.hard=5",
			request:   6,
			want:      6,
			pageTotal: 100,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcLimits",
					Values:      stringValues(test.value),
				}},
			}
			rules, err := loadDatabaseSearchSizeLimits(entry)
			if err != nil {
				t.Fatal(err)
			}
			limits := effectiveDatabaseSearchExecutionLimits(
				&runtimeState{},
				runtimeDatabase{searchSizeLimits: rules},
				"uid=user,dc=example,dc=com",
				100,
				test.request,
				test.request,
			)
			if limits.size != test.want || limits.time != test.want ||
				limits.pageTotal != test.want {
				t.Fatalf("normalized limits = %#v", limits)
			}
			defaults := effectiveDatabaseSearchExecutionLimits(
				&runtimeState{},
				runtimeDatabase{searchSizeLimits: rules},
				"uid=user,dc=example,dc=com",
				100,
				0,
				0,
			)
			if defaults.pageTotal != test.pageTotal {
				t.Fatalf("normalized default limits = %#v", defaults)
			}
		})
	}
}

func TestDelegatedLimitPrevalidatesStandardControls(t *testing.T) {
	runtime := &runtimeState{}
	for _, test := range []struct {
		name     string
		control  ldapwire.Control
		wantCode ldapwire.ResultCode
	}{
		{
			name: "malformed paging",
			control: ldapwire.Control{
				OID:      pagedResultsControlOID,
				HasValue: true,
				Value:    []byte{0x30, 0x01, 0x02},
			},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "unknown critical",
			control: ldapwire.Control{
				OID:      "1.3.6.1.4.1.99999.404",
				Critical: true,
			},
			wantCode: ldapwire.ResultUnavailableCriticalExtension,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, privateSearch, failure := prevalidateSearchRequestControls(
				runtime,
				[]ldapwire.Control{test.control},
			)
			if privateSearch || failure == nil || failure.Code != test.wantCode {
				t.Fatalf("prevalidation = private %t failure %#v", privateSearch, failure)
			}
		})
	}

	private := ldapwire.Control{OID: pcachePrivateDBControl, Critical: true}
	malformedPaging := ldapwire.Control{
		OID:      pagedResultsControlOID,
		HasValue: true,
		Value:    []byte{0x30, 0x01, 0x02},
	}
	_, privateSearch, failure := prevalidateSearchRequestControls(
		runtime,
		[]ldapwire.Control{private, malformedPaging},
	)
	if !privateSearch || failure != nil {
		t.Fatalf("privateDB prevalidation = private %t failure %#v", privateSearch, failure)
	}

	entry := directory.Entry{
		DN: "olcDatabase={1}ldap,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values:      stringValues("users size.unchecked=disabled"),
		}},
	}
	rules, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeDatabase{
		name:             "{1}ldap",
		ldapBackend:      &ldapBackendRuntimeConfiguration{},
		searchSizeLimits: rules,
	}
	state := &connectionState{
		runtime: &runtimeState{databases: []runtimeDatabase{database}},
		boundDN: "uid=user,dc=example,dc=com",
	}
	instance := &Server{config: Config{MaxSearchEntries: 100}}
	request := ldapwire.SearchRequest{BaseDN: "dc=example,dc=com"}
	if got := instance.delegatedSearchPreflight(
		state,
		database,
		request,
		[]ldapwire.Control{malformedPaging},
	); got == nil || got.Code != ldapwire.ResultProtocolError {
		t.Fatalf("malformed paging preflight = %#v", got)
	}
	unknownCritical := ldapwire.Control{
		OID:      "1.3.6.1.4.1.99999.405",
		Critical: true,
	}
	if got := instance.delegatedSearchPreflight(
		state,
		database,
		request,
		[]ldapwire.Control{unknownCritical},
	); got == nil || got.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("unknown critical preflight = %#v", got)
	}
	if got := instance.delegatedSearchPreflight(
		state,
		database,
		request,
		[]ldapwire.Control{private, malformedPaging},
	); got != nil {
		t.Fatalf("privateDB delegated preflight = %#v", got)
	}
	if got := instance.delegatedSearchPreflight(
		state,
		database,
		request,
		nil,
	); got == nil || got.Code != ldapwire.ResultAdminLimitExceeded {
		t.Fatalf("valid delegated limit preflight = %#v", got)
	}
}

func TestDatabaseAuxiliarySizeLimitFirstRuleAndRoot(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcLimits", Values: stringValues(
				"{0}users size.unchecked=2 size.pr=3 size.prtotal=4",
				"{1}users size.unchecked=99 size.pr=99 size.prtotal=99",
			)},
			{Description: "olcSizeLimit", Values: stringValues(
				"size.soft=8 size.hard=10 size.unchecked=12 size.pr=noEstimate size.prtotal=hard",
			)},
		},
	}
	rules, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatal(err)
	}
	defaults, present, err := loadDatabaseDefaultSizeLimit(entry)
	if err != nil || !present {
		t.Fatalf("load size defaults = %#v, %t, %v", defaults, present, err)
	}
	root, err := directory.ParseDN("cn=admin,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeDatabase{
		name:             "{1}mdb",
		rootDN:           &root,
		searchSizeLimits: append(rules, defaults),
	}
	runtime := &runtimeState{databases: []runtimeDatabase{database}}
	selected := effectiveDatabaseSearchExecutionLimits(
		runtime,
		database,
		"uid=alice,dc=example,dc=com",
		50,
		0,
		0,
	)
	if selected.size != 8 || selected.unchecked != 2 ||
		selected.pageSize != 3 || selected.pageTotal != 4 ||
		!selected.pageNoEstimate {
		t.Fatalf("selected limits = %#v", selected)
	}
	rootLimits := effectiveDatabaseSearchExecutionLimits(
		runtime,
		database,
		root.String(),
		50,
		0,
		0,
	)
	if !rootLimits.root || rootLimits.unchecked != -1 ||
		rootLimits.pageSize != -1 || rootLimits.pageTotal != 50 {
		t.Fatalf("root limits = %#v", rootLimits)
	}
}

func TestDatabaseSizeUnlimitedCannotExceedServerLimit(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcSizeLimit",
			Values: stringValues(
				"size.soft=unlimited size.hard=unlimited size.prtotal=unlimited",
			),
		}},
	}
	defaults, present, err := loadDatabaseDefaultSizeLimit(entry)
	if err != nil || !present {
		t.Fatalf("load unlimited defaults = %#v, %t, %v", defaults, present, err)
	}
	database := runtimeDatabase{searchSizeLimits: []databaseSearchSizeLimit{defaults}}
	for _, requested := range []int{0, 100} {
		limits := effectiveDatabaseSearchExecutionLimits(
			&runtimeState{},
			database,
			"uid=user,dc=example,dc=com",
			7,
			requested,
			0,
		)
		if limits.size != 7 || limits.pageTotal != 7 {
			t.Fatalf("requested %d limits = %#v, want size/page total 7", requested, limits)
		}
	}
}

func TestDatabasePositiveUncheckedAppliesBeforeLocalSearch(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPagedPeople(t, store, 4)
	setDatabaseAuxiliaryLimits(t, store, "users size.unchecked=2")

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	user := bindAuxiliaryLimitUser(t, address)
	defer user.Close()

	base, err := user.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(base.Entries) != 1 {
		t.Fatalf("base search = %#v, %v", base, err)
	}
	_, err = user.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=does-not-exist)",
		[]string{"uid"},
		nil,
	))
	assertAuxiliaryLDAPError(t, err, ldap.LDAPResultAdminLimitExceeded, "")

	root := bindPagedRootClient(t, address)
	defer root.Close()
	rootResult, err := root.Search(newPagedPeopleSearch(0, nil))
	if err != nil || len(rootResult.Entries) != 5 {
		t.Fatalf("root bypass search = %#v, %v", rootResult, err)
	}
}

func TestDelegatedPositiveUncheckedIsRejectedAndLogged(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}ldap,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values:      stringValues("users size.unchecked=4"),
		}},
	}
	rules, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeDatabase{
		name:             "{1}ldap",
		suffixes:         []directory.DN{suffix},
		ldapBackend:      &ldapBackendRuntimeConfiguration{},
		searchSizeLimits: rules,
	}
	var logs bytes.Buffer
	instance := &Server{config: Config{
		MaxSearchEntries: 100,
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
	}}
	state := &connectionState{
		runtime: &runtimeState{databases: []runtimeDatabase{database}},
		boundDN: "uid=user,dc=example,dc=com",
	}
	failure := instance.delegatedSearchLimitFailure(
		state,
		database,
		ldapwire.SearchRequest{BaseDN: suffix.String()},
		nil,
	)
	if failure == nil || failure.Code != ldapwire.ResultAdminLimitExceeded ||
		failure.DiagnosticMessage != "candidate estimate unavailable for delegated backend" {
		t.Fatalf("delegated failure = %#v", failure)
	}
	if text := logs.String(); !strings.Contains(text, "unverifiable candidate limit") ||
		!strings.Contains(text, "size_unchecked=4") {
		t.Fatalf("delegated boundary log = %q", text)
	}
	relay := runtimeDatabase{relay: &relayRuntimeConfiguration{targetDatabaseIndex: 1}}
	relayRuntime := &runtimeState{databases: []runtimeDatabase{relay, database}}
	if !databaseSearchCandidatesAreDelegated(relayRuntime, relay) {
		t.Fatal("relay to delegated backend was treated as a local candidate set")
	}
}

func TestDatabasePagedSizeLimitsAndCookieContinuation(t *testing.T) {
	t.Run("page size", func(t *testing.T) {
		address, stop := startAuxiliaryPagedLimitServer(
			t,
			"users size.pr=2 size.prtotal=unlimited",
			100,
		)
		defer stop()
		client := bindAuxiliaryLimitUser(t, address)
		defer client.Close()
		_, err := client.Search(newPagedPeopleSearch(0, ldap.NewControlPaging(3)))
		assertAuxiliaryLDAPError(
			t,
			err,
			ldap.LDAPResultAdminLimitExceeded,
			"illegal pagedResults page size",
		)
	})

	t.Run("disabled", func(t *testing.T) {
		address, stop := startAuxiliaryPagedLimitServer(
			t,
			"users size.prtotal=disabled",
			100,
		)
		defer stop()
		client := bindAuxiliaryLimitUser(t, address)
		defer client.Close()
		_, err := client.Search(newPagedPeopleSearch(0, ldap.NewControlPaging(1)))
		assertAuxiliaryLDAPError(
			t,
			err,
			ldap.LDAPResultAdminLimitExceeded,
			"pagedResults control not allowed",
		)
	})

	t.Run("hard total continuation", func(t *testing.T) {
		address, stop := startAuxiliaryPagedLimitServer(
			t,
			"users size.soft=5 size.hard=5 size.pr=2 size.prtotal=hard",
			100,
		)
		defer stop()
		client := bindAuxiliaryLimitUser(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		request := newPagedPeopleSearch(0, control)
		count := 0
		for page := 0; page < 2; page++ {
			result, err := client.Search(request)
			if err != nil {
				t.Fatalf("page %d: %v", page+1, err)
			}
			if len(result.Entries) != 2 {
				t.Fatalf("page %d entries = %d, want 2", page+1, len(result.Entries))
			}
			count += len(result.Entries)
			response := pagedResponseControl(t, result)
			if len(response.Cookie) == 0 {
				t.Fatalf("page %d did not return a continuation cookie", page+1)
			}
			control.SetCookie(bytes.Clone(response.Cookie))
		}
		result, err := client.Search(request)
		assertAuxiliaryLDAPError(t, err, ldap.LDAPResultSizeLimitExceeded, "")
		if result == nil || len(result.Entries) != 1 {
			t.Fatalf("terminal page = %#v, want 1 entry", result)
		}
		count += len(result.Entries)
		if count != 5 {
			t.Fatalf("entries before total limit = %d, want 5", count)
		}
	})

	t.Run("unlimited remains server capped", func(t *testing.T) {
		address, stop := startAuxiliaryPagedLimitServer(
			t,
			"users size.soft=2 size.hard=2 size.pr=2 size.prtotal=unlimited",
			5,
		)
		defer stop()
		client := bindAuxiliaryLimitUser(t, address)
		defer client.Close()
		result, err := client.SearchWithPaging(newPagedPeopleSearch(0, nil), 2)
		assertAuxiliaryLDAPError(t, err, ldap.LDAPResultSizeLimitExceeded, "")
		if len(result.Entries) != 5 {
			t.Fatalf("server-capped paged entries = %d, want 5", len(result.Entries))
		}
	})

	t.Run("no estimate", func(t *testing.T) {
		address, stop := startAuxiliaryPagedLimitServer(
			t,
			"users size.pr=noEstimate size.pr=2 size.prtotal=unlimited",
			100,
		)
		defer stop()
		client := bindAuxiliaryLimitUser(t, address)
		defer client.Close()
		result, err := client.Search(newPagedPeopleSearch(0, ldap.NewControlPaging(2)))
		if err != nil {
			t.Fatal(err)
		}
		if estimate := pagedResponseControl(t, result).PagingSize; estimate != 0 {
			t.Fatalf("paged estimate = %d, want 0", estimate)
		}
	})
}

func TestApplyDatabaseSearchLimitsUsesPagedTotalForEveryBackend(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				"users size.soft=2 size.hard=2 size.prtotal=unlimited time=3",
			),
		}},
	}
	rules, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeDatabase{
		name:             "{1}mdb",
		suffixes:         []directory.DN{suffix},
		searchSizeLimits: rules,
	}
	state := &connectionState{
		runtime: &runtimeState{databases: []runtimeDatabase{database}},
		boundDN: "uid=user,dc=example,dc=com",
	}
	request := ldapwire.SearchRequest{
		BaseDN: suffix.String(),
		Filter: directory.Filter{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		},
	}
	unpaged := applyDatabaseSearchLimits(
		state,
		ldapwire.Message{Request: request},
		5,
	).Request.(ldapwire.SearchRequest)
	if unpaged.SizeLimit != 2 || unpaged.TimeLimit != 3 {
		t.Fatalf("unpaged applied limits = %#v", unpaged)
	}
	paged := applyDatabaseSearchLimits(
		state,
		ldapwire.Message{
			Request: request,
			Controls: []ldapwire.Control{{
				OID:      pagedResultsControlOID,
				HasValue: true,
				Value:    ldapwire.EncodePagedResultsValue(2, nil),
			}},
		},
		5,
	).Request.(ldapwire.SearchRequest)
	if paged.SizeLimit != 5 || paged.TimeLimit != 3 {
		t.Fatalf("paged applied limits = %#v", paged)
	}
}

func TestOpenLDAPReferenceAuxiliarySizeLimitDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	for _, test := range []struct {
		name       string
		limit      string
		pageSize   uint32
		wantCode   uint16
		wantText   string
		wantPaging bool
	}{
		{
			name:     "positive unchecked",
			limit:    "anonymous size.unchecked=1",
			wantCode: ldap.LDAPResultAdminLimitExceeded,
		},
		{
			name:     "paged results disabled",
			limit:    "anonymous size.prtotal=disabled",
			pageSize: 1,
			wantCode: ldap.LDAPResultAdminLimitExceeded,
			wantText: "pagedResults control not allowed",
		},
		{
			name:     "illegal page size",
			limit:    "anonymous size.pr=1 size.prtotal=unlimited",
			pageSize: 2,
			wantCode: ldap.LDAPResultAdminLimitExceeded,
			wantText: "illegal pagedResults page size",
		},
		{
			name:       "no estimate",
			limit:      "anonymous size.pr=noEstimate size.pr=1 size.prtotal=unlimited",
			pageSize:   1,
			wantCode:   ldap.LDAPResultSuccess,
			wantPaging: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				"",
				"limits "+test.limit,
				"",
			)
			defer stopReference()
			localAddress, stopLocal := startAuxiliaryDifferentialServer(
				t,
				test.limit,
			)
			defer stopLocal()

			reference := observeAuxiliaryLimitSearch(
				t,
				referenceURI,
				test.pageSize,
			)
			local := observeAuxiliaryLimitSearch(
				t,
				"ldap://"+localAddress,
				test.pageSize,
			)
			for _, observed := range []struct {
				name  string
				value auxiliaryLimitObservation
			}{
				{name: "OpenLDAP 2.6.13", value: reference},
				{name: "ldap-go", value: local},
			} {
				if observed.value.code != test.wantCode ||
					observed.value.diagnostic != test.wantText {
					t.Fatalf(
						"%s result = %#v, want code %d diagnostic %q",
						observed.name,
						observed.value,
						test.wantCode,
						test.wantText,
					)
				}
				if observed.value.paging != test.wantPaging {
					t.Fatalf("%s paging = %t, want %t", observed.name, observed.value.paging, test.wantPaging)
				}
				if test.wantPaging && observed.value.estimate != 0 {
					t.Fatalf("%s estimate = %d, want 0", observed.name, observed.value.estimate)
				}
			}
		})
	}

	t.Run("hard total cookie continuation", func(t *testing.T) {
		const limit = "anonymous size.soft=5 size.hard=5 size.pr=2 size.prtotal=hard"
		referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"",
			"limits "+limit,
			auxiliaryLimitOpenLDAPExtraData,
		)
		defer stopReference()
		localAddress, stopLocal := startAuxiliaryDifferentialServer(t, limit)
		defer stopLocal()

		reference := observeAuxiliaryLimitPagingSequence(t, referenceURI, 2)
		local := observeAuxiliaryLimitPagingSequence(
			t,
			"ldap://"+localAddress,
			2,
		)
		if !slices.Equal(local.codes, reference.codes) ||
			!slices.Equal(local.entries, reference.entries) ||
			!slices.Equal(local.cookies, reference.cookies) {
			t.Fatalf("paging sequence local=%#v reference=%#v", local, reference)
		}
		if !slices.Equal(reference.codes, []uint16{
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSizeLimitExceeded,
		}) || !slices.Equal(reference.entries, []int{2, 2, 1}) ||
			!slices.Equal(reference.cookies, []bool{true, true, false}) {
			t.Fatalf("OpenLDAP 2.6.13 paging sequence = %#v", reference)
		}
	})

	for _, test := range []struct {
		name        string
		limit       string
		requestSize int
		wantEntries int
	}{
		{
			name:        "hard below soft normalizes to soft",
			limit:       "anonymous size.soft=6 size.hard=3",
			requestSize: 5,
			wantEntries: 5,
		},
		{
			name:        "hard with unlimited soft becomes unlimited",
			limit:       "anonymous size.soft=unlimited size.hard=5",
			requestSize: 6,
			wantEntries: 6,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				"",
				"limits "+test.limit,
				auxiliaryLimitOpenLDAPExtraData,
			)
			defer stopReference()
			localAddress, stopLocal := startAuxiliaryDifferentialServer(t, test.limit)
			defer stopLocal()

			referenceCode, referenceEntries := observeAuxiliarySizedSearch(
				t,
				referenceURI,
				test.requestSize,
			)
			localCode, localEntries := observeAuxiliarySizedSearch(
				t,
				"ldap://"+localAddress,
				test.requestSize,
			)
			if referenceCode != ldap.LDAPResultSizeLimitExceeded ||
				referenceEntries != test.wantEntries ||
				localCode != referenceCode || localEntries != referenceEntries {
				t.Fatalf(
					"normalized limit local=(%d,%d) reference=(%d,%d), want (%d,%d)",
					localCode,
					localEntries,
					referenceCode,
					referenceEntries,
					ldap.LDAPResultSizeLimitExceeded,
					test.wantEntries,
				)
			}
		})
	}
}

type auxiliaryLimitObservation struct {
	code       uint16
	diagnostic string
	paging     bool
	estimate   uint32
}

type auxiliaryLimitPagingSequence struct {
	codes   []uint16
	entries []int
	cookies []bool
}

func observeAuxiliaryLimitPagingSequence(
	t *testing.T,
	uri string,
	pageSize uint32,
) auxiliaryLimitPagingSequence {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial paging sequence endpoint %s: %v", uri, err)
	}
	defer client.Close()
	control := ldap.NewControlPaging(pageSize)
	request := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		[]ldap.Control{control},
	)
	var observed auxiliaryLimitPagingSequence
	for page := 0; page < 8; page++ {
		result, searchErr := client.Search(request)
		code := uint16(ldap.LDAPResultSuccess)
		if searchErr != nil {
			var ldapErr *ldap.Error
			if !errors.As(searchErr, &ldapErr) {
				t.Fatalf("paging sequence %s page %d: %v", uri, page+1, searchErr)
			}
			code = ldapErr.ResultCode
		}
		observed.codes = append(observed.codes, code)
		entryCount := 0
		if result != nil {
			entryCount = len(result.Entries)
		}
		observed.entries = append(observed.entries, entryCount)
		var cookie []byte
		if result != nil {
			if response, ok := ldap.FindControl(
				result.Controls,
				ldap.ControlTypePaging,
			).(*ldap.ControlPaging); ok {
				cookie = response.Cookie
			}
		}
		hasCookie := len(cookie) > 0
		observed.cookies = append(observed.cookies, hasCookie)
		if searchErr != nil || !hasCookie {
			return observed
		}
		control.SetCookie(bytes.Clone(cookie))
	}
	t.Fatalf("paging sequence %s did not terminate", uri)
	return observed
}

func observeAuxiliaryLimitSearch(
	t *testing.T,
	uri string,
	pageSize uint32,
) auxiliaryLimitObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial auxiliary limit reference %s: %v", uri, err)
	}
	defer client.Close()
	var controls []ldap.Control
	if pageSize > 0 {
		controls = []ldap.Control{ldap.NewControlPaging(pageSize)}
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		controls,
	))
	observation := auxiliaryLimitObservation{code: ldap.LDAPResultSuccess}
	if err != nil {
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) {
			t.Fatalf("search %s: %v", uri, err)
		}
		observation.code = ldapErr.ResultCode
		observation.diagnostic = ldapErr.Err.Error()
	}
	if result != nil {
		if control, ok := ldap.FindControl(
			result.Controls,
			ldap.ControlTypePaging,
		).(*ldap.ControlPaging); ok {
			observation.paging = true
			observation.estimate = control.PagingSize
		}
	}
	return observation
}

func observeAuxiliarySizedSearch(
	t *testing.T,
	uri string,
	sizeLimit int,
) (uint16, int) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial sized search endpoint %s: %v", uri, err)
	}
	defer client.Close()
	result, searchErr := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		nil,
	))
	code := uint16(ldap.LDAPResultSuccess)
	if searchErr != nil {
		var ldapErr *ldap.Error
		if !errors.As(searchErr, &ldapErr) {
			t.Fatalf("sized search %s: %v", uri, searchErr)
		}
		code = ldapErr.ResultCode
	}
	entries := 0
	if result != nil {
		entries = len(result.Entries)
	}
	return code, entries
}

func setDatabaseAuxiliaryLimits(t *testing.T, store storage.Store, values ...string) {
	t.Helper()
	dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLimits", stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set database auxiliary limits: %v", err)
	}
}

func startAuxiliaryPagedLimitServer(
	t *testing.T,
	limit string,
	serverLimit int,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPagedPeople(t, store, 6)
	setDatabaseAuxiliaryLimits(t, store, limit)
	return startServer(t, store, Config{
		RootDN:           "cn=admin,dc=example,dc=com",
		RootPassword:     []byte("admin-secret"),
		MaxSearchEntries: serverLimit,
	})
}

func startAuxiliaryDifferentialServer(
	t *testing.T,
	limit string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPagedPeople(t, store, 6)
	setDatabaseAuxiliaryLimits(t, store, limit)
	dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues("to * by * read"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("allow differential fixture reads: %v", err)
	}
	return startServer(t, store, Config{MaxSearchEntries: 100})
}

const auxiliaryLimitOpenLDAPExtraData = `
dn: uid=dave,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: dave
cn: Dave
sn: Dave

dn: uid=eve,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: eve
cn: Eve
sn: Eve

dn: uid=frank,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: frank
cn: Frank
sn: Frank

dn: uid=grace,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: grace
cn: Grace
sn: Grace
`

func bindAuxiliaryLimitUser(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial auxiliary limit server: %v", err)
	}
	if err := client.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	); err != nil {
		client.Close()
		t.Fatalf("bind auxiliary limit user: %v", err)
	}
	return client
}

func assertAuxiliaryLDAPError(
	t *testing.T,
	err error,
	code uint16,
	diagnostic string,
) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != code {
		t.Fatalf("LDAP error = %v, want code %d", err, code)
	}
	if got := ldapErr.Err.Error(); got != diagnostic {
		t.Fatalf("LDAP diagnostic = %q, want %q", got, diagnostic)
	}
}
