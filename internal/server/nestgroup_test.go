package server

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestNestGroupSearchIntegration(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}
	address, stop := startServer(t, store, config)
	running := true
	var data, configuration *ldap.Conn
	defer func() {
		if data != nil {
			data.Close()
		}
		if configuration != nil {
			configuration.Close()
		}
		if running {
			stop()
		}
	}()

	connect := func() {
		data = bindConstraintClient(
			t,
			address,
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		)
		configuration = bindConstraintClient(
			t,
			address,
			"cn=config",
			"config-secret",
		)
	}
	connect()
	for _, person := range []struct {
		dn, uid, cn string
	}{
		{dn: nestGroupBobDN, uid: "bob", cn: "Bob User"},
		{dn: nestGroupCarolDN, uid: "carol", cn: "Carol User"},
	} {
		request := ldap.NewAddRequest(person.dn, nil)
		request.Attribute("objectClass", []string{"inetOrgPerson"})
		request.Attribute("uid", []string{person.uid})
		request.Attribute("cn", []string{person.cn})
		request.Attribute("sn", []string{"User"})
		if err := data.Add(request); err != nil {
			t.Fatalf("Add(%s): %v", person.dn, err)
		}
	}

	if got := addLDAPGoNestGroupOverlay(t, configuration); got != (nestGroupLDAPGoConfigurationOutcome{}) {
		t.Fatalf("add nestgroup configuration = %#v", got)
	}
	addNestGroupReferenceEntries(t, data)
	assertOpenLDAPNestGroupCore(t, observeNestGroupCore(t, data, "ldap://"+address))

	overlayDN := "olcOverlay={2}nestgroup,olcDatabase={1}mdb,cn=config"
	disable := ldap.NewModifyRequest(overlayDN, nil)
	disable.Replace("olcDisabled", []string{"TRUE"})
	if err := configuration.Modify(disable); err != nil {
		t.Fatalf("disable nestgroup: %v", err)
	}
	assertNestGroupTestValues(t, ldapStringValues(nestGroupEntryValues(
		t,
		data,
		nestGroupTopDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)), nestGroupLeafADN, nestGroupMidDN)
	assertNestGroupFilterCount(t, data, nestGroupTopDN, nestGroupAliceDN, 0)

	invalid := ldap.NewModifyRequest(overlayDN, nil)
	invalid.Replace("olcDisabled", []string{"sometimes"})
	if code := overlayLDAPResultCode(t, configuration.Modify(invalid)); code != ldap.LDAPResultConstraintViolation {
		t.Fatalf("invalid olcDisabled result = %d", code)
	}
	assertNestGroupFilterCount(t, data, nestGroupTopDN, nestGroupAliceDN, 0)

	enable := ldap.NewModifyRequest(overlayDN, nil)
	enable.Replace("olcDisabled", []string{"FALSE"})
	if err := configuration.Modify(enable); err != nil {
		t.Fatalf("enable nestgroup: %v", err)
	}
	assertNestGroupFilterCount(t, data, nestGroupTopDN, nestGroupAliceDN, 1)

	if err := configuration.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("delete nestgroup: %v", err)
	}
	assertNestGroupFilterCount(t, data, nestGroupTopDN, nestGroupAliceDN, 0)
	readd := ldap.NewAddRequest(overlayDN, nil)
	readd.Attribute("objectClass", []string{"olcOverlayConfig", "olcNestGroupConfig"})
	readd.Attribute("olcOverlay", []string{"{2}nestgroup"})
	readd.Attribute("olcNestGroupBase", []string{nestGroupGroupsDN})
	readd.Attribute("olcNestGroupFlags", nestGroupAllFlags())
	if err := configuration.Add(readd); err != nil {
		t.Fatalf("re-add nestgroup: %v", err)
	}
	assertNestGroupFilterCount(t, data, nestGroupTopDN, nestGroupAliceDN, 1)

	data.Close()
	configuration.Close()
	data, configuration = nil, nil
	stop()
	running = false
	address, stop = startServer(t, store, config)
	running = true
	connect()
	assertNestGroupFilterCount(t, data, nestGroupTopDN, nestGroupAliceDN, 1)
	values := nestGroupEntryValues(
		t,
		data,
		nestGroupTopDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	if len(values) != 7 {
		t.Fatalf("restarted projected member count = %d, want 7: %q", len(values), values)
	}
}

func ldapStringValues(values []string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}

func TestNestGroupRuntimeConfiguration(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "olcOverlay={2}nestgroup,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcNestGroupConfig")},
			{Description: "olcOverlay", Values: stringValues("{2}nestgroup")},
			{Description: "olcNestGroupBase", Values: stringValues(
				"ou=groups,dc=example,dc=com",
				"ou=other,dc=example,dc=com",
			)},
			{Description: "olcNestGroupFlags", Values: stringValues(
				"member-values",
				"member-filter",
				"memberof-values",
				"memberof-filter",
			)},
		},
	}
	configuration, err := loadNestGroupRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadNestGroupRuntimeConfiguration(): %v", err)
	}
	if configuration.memberAttribute != "member" ||
		configuration.memberOfAttribute != "memberOf" ||
		configuration.disabled ||
		len(configuration.bases) != 2 ||
		configuration.flags != nestGroupMemberValues|nestGroupMemberFilter|
			nestGroupMemberOfValues|nestGroupMemberOfFilter {
		t.Fatalf("configuration = %#v", configuration)
	}
	disabled := entry.Clone()
	disabled.ReplaceValues("olcDisabled", stringValues("TRUE"))
	configuration, err = loadNestGroupRuntimeConfiguration(disabled)
	if err != nil || !configuration.disabled {
		t.Fatalf("disabled configuration = %#v, %v", configuration, err)
	}
	if err := validateNestGroupSchema(registry, []nestGroupRuntimeConfiguration{configuration}); err != nil {
		t.Fatalf("validateNestGroupSchema(): %v", err)
	}

	custom := entry.Clone()
	custom.ReplaceValues("olcNestGroupMember", stringValues("uniqueMember"))
	custom.ReplaceValues("olcNestGroupMemberOf", stringValues("uniqueMember"))
	configuration, err = loadNestGroupRuntimeConfiguration(custom)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNestGroupSchema(registry, []nestGroupRuntimeConfiguration{configuration}); err != nil {
		t.Fatalf("NameAndOptionalUID attributes rejected: %v", err)
	}

	tests := []struct {
		name   string
		change func(*directory.Entry)
		code   ldapwire.ResultCode
	}{
		{
			name: "invalid disabled",
			change: func(candidate *directory.Entry) {
				candidate.ReplaceValues("olcDisabled", stringValues("sometimes"))
			},
			code: ldapwire.ResultConstraintViolation,
		},
		{
			name: "combined flags",
			change: func(candidate *directory.Entry) {
				candidate.ReplaceValues("olcNestGroupFlags", stringValues("member-values member-filter"))
			},
			code: ldapwire.ResultOther,
		},
		{
			name: "unknown flag",
			change: func(candidate *directory.Entry) {
				candidate.ReplaceValues("olcNestGroupFlags", stringValues("unknown"))
			},
			code: ldapwire.ResultOther,
		},
		{
			name: "duplicate base",
			change: func(candidate *directory.Entry) {
				candidate.ReplaceValues("olcNestGroupBase", stringValues(
					"ou=groups,dc=example,dc=com",
					"OU=Groups,DC=Example,DC=COM",
				))
			},
			code: ldapwire.ResultAttributeOrValueExists,
		},
		{
			name: "malformed base",
			change: func(candidate *directory.Entry) {
				candidate.ReplaceValues("olcNestGroupBase", stringValues("not a dn"))
			},
			code: ldapwire.ResultInvalidAttributeSyntax,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := entry.Clone()
			test.change(&candidate)
			_, err := loadNestGroupRuntimeConfiguration(candidate)
			result, ok := nestGroupConfigurationResult(err)
			if !ok || result.Code != test.code {
				t.Fatalf("error = %v, result = %#v", err, result)
			}
		})
	}

	invalidAttribute := configuration
	invalidAttribute.memberAttribute = "cn"
	err = validateNestGroupSchema(registry, []nestGroupRuntimeConfiguration{invalidAttribute})
	result, ok := nestGroupConfigurationResult(err)
	if !ok || result.Code != ldapwire.ResultOther {
		t.Fatalf("invalid member syntax = %v, %#v", err, result)
	}
}

func TestDatabaseSearchSizeLimits(t *testing.T) {
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				`{0}dn.exact="uid=limited,ou=people,dc=example,dc=com" size.soft=2 size.hard=2`,
			),
		}},
	}
	limits, err := loadDatabaseSearchSizeLimits(entry)
	if err != nil {
		t.Fatalf("loadDatabaseSearchSizeLimits(): %v", err)
	}
	if len(limits) != 1 || limits[0].soft != 2 || limits[0].hard != 2 {
		t.Fatalf("limits = %#v", limits)
	}
	root, err := directory.ParseDN("cn=admin,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeDatabase{
		rootDN:           &root,
		searchSizeLimits: limits,
	}
	runtime := &runtimeState{databases: []runtimeDatabase{database}}
	for _, test := range []struct {
		name         string
		boundDN      string
		requestLimit int
		want         int
	}{
		{name: "soft default", boundDN: "uid=limited,ou=people,dc=example,dc=com", want: 2},
		{name: "smaller client limit", boundDN: "uid=limited,ou=people,dc=example,dc=com", requestLimit: 1, want: 1},
		{name: "hard clamps client", boundDN: "uid=limited,ou=people,dc=example,dc=com", requestLimit: 3, want: 2},
		{name: "database root bypass", boundDN: root.String(), requestLimit: 3, want: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := effectiveDatabaseSearchLimit(
				runtime,
				database,
				test.boundDN,
				1000,
				test.requestLimit,
			)
			if got != test.want {
				t.Fatalf("effective limit = %d, want %d", got, test.want)
			}
		})
	}

	invalid := entry.Clone()
	invalid.ReplaceValues("olcLimits", stringValues(
		`dn.exact="uid=limited,ou=people,dc=example,dc=com" size.soft=invalid`,
	))
	if _, err := loadDatabaseSearchSizeLimits(invalid); err == nil {
		t.Fatal("invalid search size limit was accepted")
	}
}

func TestNestGroupRequestGraphExpansion(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	rule, err := acl.ParseRule("to * by * read")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := acl.NewPolicy([]acl.Rule{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	partition := configuredDatabasePartition("{1}mdb")
	entries := []directory.Entry{
		nestGroupTestEntry("uid=alice,ou=people,dc=example,dc=com", "inetOrgPerson", "uid", "alice"),
		nestGroupTestEntry("uid=bob,ou=people,dc=example,dc=com", "inetOrgPerson", "uid", "bob"),
		nestGroupTestGroup("cn=leaf,ou=groups,dc=example,dc=com", "uid=alice,ou=people,dc=example,dc=com", "uid=bob,ou=people,dc=example,dc=com"),
		nestGroupTestGroup("cn=mid,ou=groups,dc=example,dc=com", "cn=leaf,ou=groups,dc=example,dc=com"),
		nestGroupTestGroup("cn=top,ou=groups,dc=example,dc=com", "cn=mid,ou=groups,dc=example,dc=com", "cn=leaf,ou=groups,dc=example,dc=com"),
		nestGroupTestGroup("cn=cycle-a,ou=groups,dc=example,dc=com", "cn=cycle-b,ou=groups,dc=example,dc=com", "uid=alice,ou=people,dc=example,dc=com"),
		nestGroupTestGroup("cn=cycle-b,ou=groups,dc=example,dc=com", "cn=cycle-a,ou=groups,dc=example,dc=com", "uid=bob,ou=people,dc=example,dc=com"),
	}
	entries[0].ReplaceValues("memberOf", stringValues("cn=leaf,ou=groups,dc=example,dc=com"))
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.PutIn(partition, entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	base, _ := directory.ParseDN("ou=groups,dc=example,dc=com")
	database := runtimeDatabase{
		name:        "{1}mdb",
		partition:   partition,
		configDNKey: "olcdatabase={1}mdb,cn=config",
		nestGroups: []nestGroupRuntimeConfiguration{{
			id:                "test",
			memberAttribute:   "member",
			memberOfAttribute: "memberOf",
			bases:             []directory.DN{base},
			flags:             nestGroupMemberValues | nestGroupMemberOfValues,
		}},
	}
	runtime := &runtimeState{
		schema:    registry,
		access:    policy,
		databases: []runtimeDatabase{database},
	}
	server := &Server{}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		cache := newNestGroupProjectionCache(
			context.Background(),
			server,
			runtime,
			reader,
			"",
			nestGroupProjectionRequest{attributes: []string{"member", "memberOf"}},
		)
		plan, err := cache.plan(database)
		if err != nil {
			return err
		}
		if len(plan.entries) != len(entries) || len(plan.instances) != 1 {
			t.Fatalf("graph size = %d/%d", len(plan.entries), len(plan.instances))
		}

		top, _ := directory.ParseDN("cn=top,ou=groups,dc=example,dc=com")
		projected, err := cache.project(database, plan.entries[top.Key()].entry)
		if err != nil {
			return err
		}
		assertNestGroupTestValues(t, projected.Values("member"),
			"cn=leaf,ou=groups,dc=example,dc=com",
			"cn=mid,ou=groups,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
			"uid=bob,ou=people,dc=example,dc=com",
		)

		cycle, _ := directory.ParseDN("cn=cycle-a,ou=groups,dc=example,dc=com")
		projected, err = cache.project(database, plan.entries[cycle.Key()].entry)
		if err != nil {
			return err
		}
		assertNestGroupTestValues(t, projected.Values("member"),
			"cn=cycle-a,ou=groups,dc=example,dc=com",
			"cn=cycle-b,ou=groups,dc=example,dc=com",
			"uid=alice,ou=people,dc=example,dc=com",
			"uid=bob,ou=people,dc=example,dc=com",
		)

		alice, _ := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
		projected, err = cache.project(database, plan.entries[alice.Key()].entry)
		if err != nil {
			return err
		}
		assertNestGroupTestValues(t, projected.Values("memberOf"),
			"cn=leaf,ou=groups,dc=example,dc=com",
			"cn=mid,ou=groups,dc=example,dc=com",
			"cn=top,ou=groups,dc=example,dc=com",
		)
		return nil
	}); err != nil {
		t.Fatalf("graph expansion: %v", err)
	}
}

func TestLoadRuntimeDatabasesNestGroupMultipleInstances(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		nestGroupConfigurationEntry(
			"olcOverlay={0}nestgroup,olcDatabase={-1}frontend,cn=config",
			"{0}nestgroup",
			"ou=global,dc=example,dc=com",
		),
		nestGroupConfigurationEntry(
			"olcOverlay={0}nestgroup,olcDatabase={1}mdb,cn=config",
			"{0}nestgroup",
			"ou=groups,dc=example,dc=com",
		),
		nestGroupConfigurationEntry(
			"olcOverlay={1}nestgroup,olcDatabase={1}mdb,cn=config",
			"{1}nestgroup",
			"ou=other,dc=example,dc=com",
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	var frontend, data *runtimeDatabase
	for index := range databases {
		switch databaseType(databases[index].name) {
		case "frontend":
			frontend = &databases[index]
		case "mdb":
			data = &databases[index]
		}
	}
	if frontend == nil || len(frontend.nestGroups) != 1 {
		t.Fatalf("frontend nestgroup instances = %#v", frontend)
	}
	if data == nil || len(data.nestGroups) != 2 {
		t.Fatalf("database nestgroup instances = %#v", data)
	}
	if got := nestGroupConfigurationsForDatabase(databases, *data); len(got) != 3 {
		t.Fatalf("effective nestgroup instances = %d, want 3", len(got))
	}
	data.nestGroups[0].disabled = true
	frontend.nestGroups[0].disabled = true
	if got := nestGroupConfigurationsForDatabase(databases, *data); len(got) != 1 {
		t.Fatalf("effective enabled nestgroup instances = %d, want 1", len(got))
	}
}

func nestGroupConfigurationEntry(dn, overlay, base string) directory.Entry {
	return directory.Entry{DN: dn, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcNestGroupConfig")},
		{Description: "olcOverlay", Values: stringValues(overlay)},
		{Description: "olcNestGroupBase", Values: stringValues(base)},
		{Description: "olcNestGroupFlags", Values: stringValues("member-values", "member-filter")},
	}}
}

func nestGroupTestEntry(dn, objectClass, attribute, value string) directory.Entry {
	return directory.Entry{DN: dn, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues(objectClass)},
		{Description: attribute, Values: stringValues(value)},
	}}
}

func nestGroupTestGroup(dn string, members ...string) directory.Entry {
	entry := nestGroupTestEntry(dn, "groupOfNames", "cn", strings.SplitN(dn, ",", 2)[0][3:])
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "member",
		Values:      stringValues(members...),
	})
	return entry
}

func assertNestGroupTestValues(t *testing.T, got [][]byte, want ...string) {
	t.Helper()
	actual := make([]string, len(got))
	for index := range got {
		actual[index] = strings.ToLower(string(got[index]))
	}
	for index := range want {
		want[index] = strings.ToLower(want[index])
	}
	sort.Strings(actual)
	sort.Strings(want)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("values = %q, want %q", actual, want)
	}
}
