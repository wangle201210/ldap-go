package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDatabaseSearchTimeLimits(t *testing.T) {
	registry := dnIdentityDatabaseLimitRegistry(t)
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				`{0}anonymous time=4`,
				`{1}dn.self.subtree="dbLimitFoldAlias=People,dbLimitFoldAlias=Tenant" time.soft=7 time.hard=9`,
				`{2}users time.soft=5 time.hard=unlimited`,
			),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimitsWithNormalizer(entry, registry)
	if err != nil {
		t.Fatalf("load database time limits: %v", err)
	}
	database := runtimeDatabase{
		name:             "{1}mdb",
		dnNormalizer:     registry,
		searchSizeLimits: limits,
	}
	runtime := &runtimeState{schema: registry}

	for _, test := range []struct {
		name, boundDN string
		request       int
		want          int
	}{
		{name: "anonymous soft", request: 0, want: 4},
		{name: "anonymous hard", request: 10, want: 4},
		{
			name:    "subtree soft",
			boundDN: "uid=alice,dbLimitFoldName=people,dbLimitFoldName=tenant",
			request: 0,
			want:    7,
		},
		{
			name:    "request below hard",
			boundDN: "uid=alice,dbLimitFoldName=people,dbLimitFoldName=tenant",
			request: 8,
			want:    8,
		},
		{
			name:    "request above hard",
			boundDN: "uid=alice,dbLimitFoldName=people,dbLimitFoldName=tenant",
			request: 20,
			want:    9,
		},
		{
			name:    "unlimited users hard",
			boundDN: "uid=other,dc=example,dc=com",
			request: 20,
			want:    20,
		},
		{
			name:    "users soft",
			boundDN: "uid=other,dc=example,dc=com",
			request: 0,
			want:    5,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := effectiveDatabaseSearchTimeLimit(
				runtime,
				database,
				test.boundDN,
				test.request,
			); got != test.want {
				t.Fatalf("effective time limit = %d, want %d", got, test.want)
			}
		})
	}
}

func TestDatabaseSearchTimeLimitRootAndDispatch(t *testing.T) {
	registry := dnIdentityDatabaseLimitRegistry(t)
	suffix := dnIdentityDatabaseLimitDN(t, registry, "dbLimitFoldName=Tenant")
	root := dnIdentityDatabaseLimitDN(
		t,
		registry,
		"uid=admin,dbLimitFoldName=Tenant",
	)
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values:      stringValues(`users time.soft=3 time.hard=6`),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimitsWithNormalizer(entry, registry)
	if err != nil {
		t.Fatalf("load database time limits: %v", err)
	}
	database := runtimeDatabase{
		name:             "{1}mdb",
		suffixes:         []directory.DN{suffix},
		dnNormalizer:     registry,
		rootDN:           &root,
		searchSizeLimits: limits,
	}
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
	message := ldapwire.Message{ID: 1, Request: ldapwire.SearchRequest{
		BaseDN:    suffix.String(),
		Scope:     directory.ScopeWholeSubtree,
		TimeLimit: 20,
		Filter:    directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	}}

	state := &connectionState{
		runtime: runtime,
		boundDN: "uid=user,dbLimitFoldAlias=tenant",
	}
	clamped := applyDatabaseSearchLimits(state, message, 100)
	if got := clamped.Request.(ldapwire.SearchRequest).TimeLimit; got != 6 {
		t.Fatalf("dispatched user time limit = %d, want 6", got)
	}
	state.boundDN = "uid=admin,dbLimitFoldAlias=tenant"
	rootMessage := applyDatabaseSearchLimits(state, message, 100)
	if got := rootMessage.Request.(ldapwire.SearchRequest).TimeLimit; got != 20 {
		t.Fatalf("dispatched root time limit = %d, want 20", got)
	}
}

func TestDatabaseSearchTimeLimitValidation(t *testing.T) {
	for _, value := range []string{
		`users time.soft=soft`,
		`users time.hard=-2`,
		`users time=invalid`,
	} {
		entry := directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcLimits",
				Values:      stringValues(value),
			}},
		}
		if _, err := loadDatabaseSearchSizeLimits(entry); err == nil ||
			!strings.Contains(err.Error(), "time") {
			t.Fatalf("olcLimits %q error = %v", value, err)
		}
	}
}

func TestDatabaseDefaultTimeLimit(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		soft  int
		hard  int
	}{
		{name: "integer", value: "12", soft: 12},
		{name: "unlimited", value: "unlimited", soft: -1},
		{name: "soft and hard", value: "time.soft=7 time.hard=9", soft: 7, hard: 9},
		{name: "hard follows soft", value: "time.soft=8 time.hard=soft", soft: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcTimeLimit",
					Values:      stringValues(test.value),
				}},
			}
			limit, present, err := loadDatabaseDefaultTimeLimit(entry)
			if err != nil || !present {
				t.Fatalf("loadDatabaseDefaultTimeLimit() = %#v, %t, %v", limit, present, err)
			}
			if limit.selector != databaseSearchLimitAny ||
				!limit.timeSoftSet || !limit.timeHardSet ||
				limit.timeSoft != test.soft || limit.timeHard != test.hard {
				t.Fatalf("default time limit = %#v", limit)
			}
		})
	}

	for _, value := range []string{"", "time.soft=soft", "size=4", "7 extra"} {
		entry := directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcTimeLimit",
				Values:      stringValues(value),
			}},
		}
		if _, _, err := loadDatabaseDefaultTimeLimit(entry); err == nil {
			t.Fatalf("invalid olcTimeLimit %q was accepted", value)
		}
	}
}

func TestDatabaseExplicitTimeLimitPrecedesDefault(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcLimits", Values: stringValues(`users time=3`)},
			{Description: "olcTimeLimit", Values: stringValues("9")},
		},
	}
	limits, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatalf("load explicit limits: %v", err)
	}
	defaultLimit, present, err := loadDatabaseDefaultTimeLimit(entry)
	if err != nil || !present {
		t.Fatalf("load default limit = %#v, %t, %v", defaultLimit, present, err)
	}
	database := runtimeDatabase{searchSizeLimits: append(limits, defaultLimit)}
	if got := effectiveDatabaseSearchTimeLimit(
		&runtimeState{},
		database,
		"uid=user,dc=example,dc=com",
		0,
	); got != 3 {
		t.Fatalf("explicit user time limit = %d, want 3", got)
	}
	if got := effectiveDatabaseSearchTimeLimit(
		&runtimeState{},
		database,
		"",
		0,
	); got != 9 {
		t.Fatalf("default anonymous time limit = %d, want 9", got)
	}
}

func TestDatabaseDefaultSizeLimitAndCrossFieldFallback(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcLimits", Values: stringValues(`users time=3`)},
			{Description: "olcSizeLimit", Values: stringValues(
				"size.soft=11 size.hard=15 size.unchecked=unlimited size.pr=noEstimate size.prtotal=hard",
			)},
		},
	}
	limits, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatalf("load explicit limits: %v", err)
	}
	defaultLimit, present, err := loadDatabaseDefaultSizeLimit(entry)
	if err != nil || !present {
		t.Fatalf("load default size limit = %#v, %t, %v", defaultLimit, present, err)
	}
	database := runtimeDatabase{searchSizeLimits: append(limits, defaultLimit)}
	runtime := &runtimeState{}
	if got := effectiveDatabaseSearchLimit(
		runtime,
		database,
		"uid=user,dc=example,dc=com",
		100,
		0,
	); got != 11 {
		t.Fatalf("default size soft limit = %d, want 11", got)
	}
	if got := effectiveDatabaseSearchLimit(
		runtime,
		database,
		"uid=user,dc=example,dc=com",
		100,
		20,
	); got != 15 {
		t.Fatalf("default size hard limit = %d, want 15", got)
	}
	if got := effectiveDatabaseSearchTimeLimit(
		runtime,
		database,
		"uid=user,dc=example,dc=com",
		0,
	); got != 3 {
		t.Fatalf("explicit time limit = %d, want 3", got)
	}

	message := ldapwire.Message{Request: ldapwire.SearchRequest{
		BaseDN:    "dc=example,dc=com",
		Scope:     directory.ScopeWholeSubtree,
		SizeLimit: 20,
		TimeLimit: 20,
		Filter:    directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	}}
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	database.suffixes = []directory.DN{suffix}
	runtime.databases = []runtimeDatabase{database}
	clamped := applyDatabaseSearchLimits(&connectionState{
		runtime: runtime,
		boundDN: "uid=user,dc=example,dc=com",
	}, message, 100).Request.(ldapwire.SearchRequest)
	if clamped.SizeLimit != 15 || clamped.TimeLimit != 3 {
		t.Fatalf("dispatched limits = size %d time %d", clamped.SizeLimit, clamped.TimeLimit)
	}
}

func TestDatabaseDefaultSizeLimitValidation(t *testing.T) {
	for _, value := range []string{
		"",
		"size.soft=soft",
		"size.prtotal=-2",
		"size.unknown=3",
		"7 extra",
	} {
		entry := directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcSizeLimit",
				Values:      stringValues(value),
			}},
		}
		if _, _, err := loadDatabaseDefaultSizeLimit(entry); err == nil {
			t.Fatalf("invalid olcSizeLimit %q was accepted", value)
		}
	}
}

func TestFrontendDatabaseSearchDefaultsAreInheritedPerLimitKind(t *testing.T) {
	frontendSize := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		soft:            17,
		softSet:         true,
		hardSet:         true,
		databaseDefault: true,
	}
	frontendTime := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		timeSoft:        11,
		timeSoftSet:     true,
		timeHardSet:     true,
		databaseDefault: true,
	}
	localTime := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		timeSoft:        5,
		timeSoftSet:     true,
		timeHardSet:     true,
		databaseDefault: true,
	}
	databases := []runtimeDatabase{
		{name: "{-1}frontend", searchSizeLimits: []databaseSearchSizeLimit{frontendSize, frontendTime}},
		{name: "{1}mdb", searchSizeLimits: []databaseSearchSizeLimit{localTime}},
		{name: "{2}mdb"},
	}
	applyFrontendDatabaseDefaults(databases)
	runtime := &runtimeState{databases: databases}
	for _, test := range []struct {
		index    int
		wantSize int
		wantTime int
	}{
		{index: 1, wantSize: 17, wantTime: 5},
		{index: 2, wantSize: 17, wantTime: 11},
	} {
		database := databases[test.index]
		if got := effectiveDatabaseSearchLimit(
			runtime,
			database,
			"uid=user,dc=example,dc=com",
			100,
			0,
		); got != test.wantSize {
			t.Fatalf("database %d inherited size = %d, want %d", test.index, got, test.wantSize)
		}
		if got := effectiveDatabaseSearchTimeLimit(
			runtime,
			database,
			"uid=user,dc=example,dc=com",
			0,
		); got != test.wantTime {
			t.Fatalf("database %d inherited time = %d, want %d", test.index, got, test.wantTime)
		}
	}
}

func TestRuntimeDatabaseLoadsFrontendSearchDefaults(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
					{Description: "olcSizeLimit", Values: stringValues("13")},
					{Description: "olcTimeLimit", Values: stringValues("7")},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	}); err != nil {
		t.Fatalf("seed runtime databases: %v", err)
	}
	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	var database *runtimeDatabase
	for index := range databases {
		if databaseType(databases[index].name) == "mdb" {
			database = &databases[index]
			break
		}
	}
	if database == nil {
		t.Fatal("mdb runtime database is missing")
	}
	runtime := &runtimeState{databases: databases}
	if got := effectiveDatabaseSearchLimit(
		runtime,
		*database,
		"uid=user,dc=example,dc=com",
		100,
		0,
	); got != 13 {
		t.Fatalf("runtime inherited size = %d, want 13", got)
	}
	if got := effectiveDatabaseSearchTimeLimit(
		runtime,
		*database,
		"uid=user,dc=example,dc=com",
		0,
	); got != 7 {
		t.Fatalf("runtime inherited time = %d, want 7", got)
	}
}

func TestOpenLDAPDatabaseTimeLimitSourceContract(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 for pinned source contracts")
	}
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE is required")
	}
	contents, err := os.ReadFile(filepath.Join(source, "servers", "slapd", "limits.c"))
	if err != nil {
		t.Fatalf("read OpenLDAP limits.c: %v", err)
	}
	text := string(contents)
	for _, anchor := range []string{"time.soft=", "time.hard=", "SLAP_MAX_LIMIT"} {
		if !strings.Contains(text, anchor) {
			t.Fatalf("OpenLDAP limits.c lacks %q", anchor)
		}
	}
}

func TestOpenLDAPReferenceDatabaseTimeLimitDoesNotInterruptOverlayDelay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{`retcode
retcode-parent "ou=RetCodes,dc=example,dc=com"
retcode-sleep 2`},
		"",
		"limits anonymous time=1",
		"",
	)
	defer stop()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP): %v", err)
	}
	defer client.Close()
	client.SetTimeout(5 * time.Second)
	started := time.Now()
	_, err = client.Search(ldap.NewSearchRequest(
		"ou=RetCodes,dc=example,dc=com",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	if code := ldapBackendResultCode(err); code != ldap.LDAPResultSuccess {
		t.Fatalf("OpenLDAP delayed Search result = %d (%v)", code, err)
	}
	if elapsed := time.Since(started); elapsed < 1900*time.Millisecond || elapsed > 3500*time.Millisecond {
		t.Fatalf("OpenLDAP delayed Search elapsed = %v, want about two seconds", elapsed)
	}
}
