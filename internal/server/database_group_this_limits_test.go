package server

import (
	"context"
	"errors"
	"net"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDatabaseGroupLimitUsesInternalSchemaAwareMembership(t *testing.T) {
	for _, test := range []struct {
		name       string
		selector   string
		class      string
		attribute  string
		member     string
		wantMember bool
		hideMember bool
	}{
		{
			name:       "distinguished name member",
			selector:   "group",
			class:      "groupOfNames",
			attribute:  "member",
			member:     "UID=alice,OU=people,DC=example,DC=com",
			wantMember: true,
		},
		{
			name:       "name and optional UID without UID",
			selector:   "group/groupOfUniqueNames/uniqueMember",
			class:      "groupOfUniqueNames",
			attribute:  "uniqueMember",
			member:     "UID=alice,OU=people,DC=example,DC=com",
			wantMember: true,
		},
		{
			name:       "name and optional UID distinguishes UID",
			selector:   "group/groupOfUniqueNames/uniqueMember",
			class:      "groupOfUniqueNames",
			attribute:  "uniqueMember",
			member:     "uid=alice,ou=people,dc=example,dc=com#'0101'B",
			wantMember: false,
		},
		{
			name:       "member hidden by ACL remains a policy member",
			selector:   "group",
			class:      "groupOfNames",
			attribute:  "member",
			member:     "uid=alice,ou=people,dc=example,dc=com",
			wantMember: true,
			hideMember: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			seedPagedPeople(t, store, 6)
			const groupDN = "cn=limit-admins,dc=example,dc=com"
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if err := writer.Put(directory.Entry{
					DN: groupDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues(test.class)},
						{Description: "cn", Values: stringValues("limit-admins")},
						{Description: test.attribute, Values: stringValues(test.member)},
					},
				}, false); err != nil {
					return err
				}
				if !test.hideMember {
					return nil
				}
				databaseDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
				if err != nil {
					return err
				}
				configuration, err := writer.Get(databaseDN)
				if err != nil {
					return err
				}
				configuration.ReplaceValues("olcAccess", stringValues(
					`{0}to dn.exact="`+groupDN+`" attrs=member by * none`,
					"{1}to attrs=userPassword by self =xw by anonymous auth by * none",
					"{2}to * by self write by users read by * none",
				))
				return writer.Put(configuration, true)
			}); err != nil {
				t.Fatalf("seed limit group: %v", err)
			}
			setDatabaseAuxiliaryLimits(
				t,
				store,
				test.selector+`="`+groupDN+`" size.soft=2 size.hard=2`,
				"users size.soft=4 size.hard=4",
			)
			address, stop := startServer(t, store, Config{MaxSearchEntries: 100})
			defer stop()
			client := bindAuxiliaryLimitUser(t, address)
			defer client.Close()

			result, err := client.Search(ldap.NewSearchRequest(
				"ou=people,dc=example,dc=com",
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=inetOrgPerson)",
				[]string{"uid"},
				nil,
			))
			var ldapErr *ldap.Error
			if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultSizeLimitExceeded {
				t.Fatalf("search error = %v", err)
			}
			want := 4
			if test.wantMember {
				want = 2
			}
			if len(result.Entries) != want {
				t.Fatalf("entries = %d, want %d", len(result.Entries), want)
			}
		})
	}
}

func TestDatabaseGroupLimitSelectsGroupDatabaseByDN(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	peopleSuffix, err := registry.NormalizeDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	groupSuffix, err := registry.NormalizeDN("dc=groups,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	const (
		boundDN = "uid=alice,ou=people,dc=example,dc=com"
		groupDN = "cn=limit-admins,dc=groups,dc=test"
	)
	rules, err := loadDatabaseSearchSizeLimitsWithNormalizer(directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				`group="`+groupDN+`" size.soft=2 size.hard=2`,
				"users size.soft=5 size.hard=5",
			),
		}},
	}, registry)
	if err != nil {
		t.Fatal(err)
	}
	peopleDatabase := runtimeDatabase{
		name:             "{1}mdb",
		partition:        configuredDatabasePartition("{1}mdb"),
		suffixes:         []directory.DN{peopleSuffix},
		dnNormalizer:     registry,
		searchSizeLimits: rules,
	}
	groupDatabase := runtimeDatabase{
		name:         "{2}mdb",
		partition:    configuredDatabasePartition("{2}mdb"),
		suffixes:     []directory.DN{groupSuffix},
		dnNormalizer: registry,
	}
	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{peopleDatabase, groupDatabase},
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.PutIn(groupDatabase.partition, directory.Entry{
			DN: groupDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("groupOfNames")},
				{Description: "cn", Values: stringValues("limit-admins")},
				{Description: "member", Values: stringValues(boundDN)},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	requestDN, err := registry.NormalizeDN("ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	var limits databaseSearchExecutionLimits
	err = store.View(t.Context(), func(reader storage.Reader) error {
		var limitErr error
		limits, limitErr = (&Server{}).effectiveDatabaseSearchLimitsForRequest(
			runtime,
			peopleDatabase,
			boundDN,
			requestDN,
			reader,
			100,
			0,
			0,
		)
		return limitErr
	})
	if err != nil || limits.size != 2 {
		t.Fatalf("cross-database group limits = %#v, %v", limits, err)
	}
	runtime.databases[1].ldapBackend = &ldapBackendRuntimeConfiguration{}
	err = store.View(t.Context(), func(reader storage.Reader) error {
		_, limitErr := (&Server{}).effectiveDatabaseSearchLimitsForRequest(
			runtime,
			peopleDatabase,
			boundDN,
			requestDN,
			reader,
			100,
			0,
			0,
		)
		return limitErr
	})
	if !errors.Is(err, errDatabaseSearchLimitGroupUnverifiable) {
		t.Fatalf("delegated group database error = %v", err)
	}
}

func TestDatabaseGroupLimitReachesSockOverlayShortCircuit(t *testing.T) {
	requireSockRuntimeUnix(t)
	fixture := startSockRuntimeFixture(t, func(
		connection net.Conn,
		request sockRuntimeCapturedRequest,
	) error {
		if request.command != "SEARCH" {
			return nil
		}
		return writeAll(connection, []byte(
			"RESULT\ncode: 0\nmatched:\ninfo:\n\n",
		))
	})
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSockOverlayRuntimeConfiguration(
		t,
		store,
		fixture.path,
		[]string{"search"},
		nil,
	)
	const groupDN = "cn=limit-admins,dc=example,dc=com"
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: groupDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("groupOfNames")},
				{Description: "cn", Values: stringValues("limit-admins")},
				{Description: "member", Values: stringValues(aliceDN)},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	setDatabaseAuxiliaryLimits(
		t,
		store,
		`group="`+groupDN+`" size.soft=2 size.hard=2`,
		"users size.soft=5 size.hard=5",
	)
	address, stop := startServer(t, store, Config{MaxSearchEntries: 100})
	defer stop()
	client := bindAuxiliaryLimitUser(t, address)
	defer client.Close()
	if _, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		nil,
	)); err != nil {
		t.Fatalf("short-circuit group search: %v", err)
	}
	assertSockRuntimeField(t, fixture.take(t), "sizelimit", "2")
}

func TestDatabaseThisLimitMatchesSearchTargetDN(t *testing.T) {
	rules, err := loadDatabaseSearchSizeLimits(directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcLimits",
			Values: stringValues(
				`dn.this.exact="ou=exact,dc=example,dc=com" size=1`,
				`dn.this.onelevel="ou=one,dc=example,dc=com" size=2`,
				`dn.this.subtree="ou=sub,dc=example,dc=com" size=3`,
				`dn.this.children="ou=children,dc=example,dc=com" size=4`,
				`dn.this.regex="^uid=regex,ou=people,dc=example,dc=com$" size=8`,
				"users size=9",
			),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeDatabase{searchSizeLimits: rules}
	instance := &Server{}
	for _, test := range []struct {
		target string
		want   int
	}{
		{target: "ou=exact,dc=example,dc=com", want: 1},
		{target: "uid=a,ou=one,dc=example,dc=com", want: 2},
		{target: "ou=sub,dc=example,dc=com", want: 3},
		{target: "uid=a,ou=sub,dc=example,dc=com", want: 3},
		{target: "ou=children,dc=example,dc=com", want: 9},
		{target: "uid=a,ou=children,dc=example,dc=com", want: 4},
		{target: "uid=regex,ou=people,dc=example,dc=com", want: 8},
	} {
		target, parseErr := directory.ParseDN(test.target)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		limits, limitErr := instance.effectiveDatabaseSearchLimitsForRequest(
			&runtimeState{},
			database,
			"uid=bound,dc=example,dc=com",
			target,
			nil,
			100,
			0,
			0,
		)
		if limitErr != nil || limits.size != test.want {
			t.Fatalf("target %q limits = %#v, %v; want size %d", test.target, limits, limitErr, test.want)
		}
	}
}

func TestOpenLDAPReferenceDatabaseGroupAndThisLimitDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)

	t.Run("dn.this exact", func(t *testing.T) {
		const limit = `dn.this.exact="ou=people,dc=example,dc=com" size.soft=1 size.hard=1`
		referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"",
			"limits "+limit,
			"",
		)
		defer stopReference()
		localAddress, stopLocal := startAuxiliaryDifferentialServer(t, limit)
		defer stopLocal()

		referenceCode, referenceEntries := observeAuxiliarySizedSearch(t, referenceURI, 0)
		localCode, localEntries := observeAuxiliarySizedSearch(t, "ldap://"+localAddress, 0)
		if referenceCode != ldap.LDAPResultSizeLimitExceeded || referenceEntries != 1 ||
			localCode != referenceCode || localEntries != referenceEntries {
			t.Fatalf(
				"dn.this local=(%d,%d) reference=(%d,%d)",
				localCode,
				localEntries,
				referenceCode,
				referenceEntries,
			)
		}
	})

	t.Run("dn.this regex", func(t *testing.T) {
		const limit = `dn.this.regex="^ou=people,dc=example,dc=com$" size.soft=1 size.hard=1`
		referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"",
			"limits "+limit,
			"",
		)
		defer stopReference()
		localAddress, stopLocal := startAuxiliaryDifferentialServer(t, limit)
		defer stopLocal()

		referenceCode, referenceEntries := observeAuxiliarySizedSearch(t, referenceURI, 0)
		localCode, localEntries := observeAuxiliarySizedSearch(t, "ldap://"+localAddress, 0)
		if referenceCode != ldap.LDAPResultSizeLimitExceeded || referenceEntries != 1 ||
			localCode != referenceCode || localEntries != referenceEntries {
			t.Fatalf(
				"dn.this regex local=(%d,%d) reference=(%d,%d)",
				localCode,
				localEntries,
				referenceCode,
				referenceEntries,
			)
		}
	})

	t.Run("group member", func(t *testing.T) {
		const (
			limitUserDN = "uid=limit-user,ou=people,dc=example,dc=com"
			groupDN     = "cn=limit-admins,dc=example,dc=com"
			limit       = `group="` + groupDN + `" size.soft=1 size.hard=1`
		)
		referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"",
			"limits "+limit,
			`
dn: uid=limit-user,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: limit-user
cn: Limit User
sn: User
userPassword: limit-secret

dn: cn=limit-admins,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: limit-admins
member: uid=limit-user,ou=people,dc=example,dc=com
`,
		)
		defer stopReference()

		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		seedPagedPeople(t, store, 3)
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			for _, entry := range []directory.Entry{
				{
					DN: limitUserDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("inetOrgPerson")},
						{Description: "uid", Values: stringValues("limit-user")},
						{Description: "cn", Values: stringValues("Limit User")},
						{Description: "sn", Values: stringValues("User")},
						{Description: "userPassword", Values: stringValues("limit-secret")},
					},
				},
				{
					DN: groupDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("groupOfNames")},
						{Description: "cn", Values: stringValues("limit-admins")},
						{Description: "member", Values: stringValues(limitUserDN)},
					},
				},
			} {
				if err := writer.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		setDatabaseAuxiliaryLimits(t, store, limit)
		localAddress, stopLocal := startServer(t, store, Config{MaxSearchEntries: 100})
		defer stopLocal()

		referenceCode, referenceEntries := observeBoundLimitSearch(
			t,
			referenceURI,
			limitUserDN,
			"limit-secret",
		)
		localCode, localEntries := observeBoundLimitSearch(
			t,
			"ldap://"+localAddress,
			limitUserDN,
			"limit-secret",
		)
		if referenceCode != ldap.LDAPResultSizeLimitExceeded || referenceEntries != 1 ||
			localCode != referenceCode || localEntries != referenceEntries {
			t.Fatalf(
				"group local=(%d,%d) reference=(%d,%d)",
				localCode,
				localEntries,
				referenceCode,
				referenceEntries,
			)
		}
	})
}

func observeBoundLimitSearch(
	t *testing.T,
	uri,
	bindDN,
	password string,
) (uint16, int) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind(bindDN, password); err != nil {
		t.Fatalf("bind %s: %v", uri, err)
	}
	result, searchErr := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
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
			t.Fatal(searchErr)
		}
		code = ldapErr.ResultCode
	}
	entries := 0
	if result != nil {
		entries = len(result.Entries)
	}
	return code, entries
}
