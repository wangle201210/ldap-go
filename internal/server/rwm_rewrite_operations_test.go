package server

import (
	"fmt"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type rwmRewriteFixture struct {
	store        storage.Store
	server       *Server
	address      string
	suffix       string
	userDN       string
	password     string
	rootDN       string
	rootPassword string
	configDN     string
	attribute    string
}

func startRWMRewriteFixture(t *testing.T, backend string, named bool) rwmRewriteFixture {
	t.Helper()
	fixture := rwmRewriteFixture{store: storage.NewMemory()}
	t.Cleanup(func() { _ = fixture.store.Close() })
	remoteSuffix := "dc=example,dc=com"
	if backend == "relay" {
		seedRWMRelayConfiguration(t, fixture.store)
		fixture.suffix = "dc=virtual,dc=test"
		fixture.userDN = "uid=alice,ou=people," + fixture.suffix
		fixture.password = "alice-secret"
		fixture.rootDN, fixture.rootPassword = "cn=admin,"+fixture.suffix, "secret"
		fixture.configDN, fixture.attribute = rwmOverlayConfigDN, "olcRwmRewrite"
	} else {
		provider := storage.NewMemory()
		t.Cleanup(func() { _ = provider.Close() })
		seedLDAPBackendProvider(t, provider)
		address, stop := startServer(t, provider, Config{RootDN: ldapBackendTestAdminDN, RootPassword: []byte(ldapBackendTestAdminSecret)})
		t.Cleanup(stop)
		remoteSuffix = ldapBackendTestSuffix
		fixture.password = ldapBackendTestUserPassword
		fixture.rootPassword = ldapBackendTestAdminSecret
		if backend == "ldap" {
			seedLDAPBackendRWMProxy(t, fixture.store, "ldap://"+address, true)
			fixture.suffix, fixture.userDN = ldapBackendRWMLocalSuffix, ldapBackendRWMLocalAliceDN
			fixture.configDN, fixture.attribute = ldapBackendRWMOverlayDN, "olcRwmRewrite"
		} else {
			seedMetaOperationProxy(t, fixture.store, address)
			fixture.suffix, fixture.userDN = metaOperationLocalSuffix, metaOperationLocalUser
			fixture.configDN, fixture.attribute = "olcMetaSub={0}uri,"+metaOperationDatabaseDN, "olcDbRewrite"
		}
		fixture.rootDN = "cn=admin," + fixture.suffix
	}
	directives := rwmRewriteOverlayDirectives(fixture.suffix, remoteSuffix)
	if backend == "meta" {
		directives = rwmRewriteMetaDirectives(fixture.suffix, remoteSuffix)
	}
	if named {
		response := "searchEntryDN"
		if backend == "meta" {
			response = "searchResult"
		}
		directives = []string{
			"rewriteEngine on",
			"rewriteContext request",
			fmt.Sprintf(`rewriteRule "^(.+,)?%s$" "$1%s" :`, fixture.suffix, remoteSuffix),
			"rewriteContext default",
			`rewriteRule ".*" "" "#"`,
			"rewriteContext " + response,
			fmt.Sprintf(`rewriteRule "^(.+,)?%s$" "$1%s" :`, remoteSuffix, fixture.suffix),
			"rewriteContext searchAttrDN alias " + response,
			"rewriteContext matchedDN alias " + response,
			"rewriteContext referralDN",
			"rewriteContext referralAttrDN",
			"rewriteContext newRDN",
			"rewriteContext searchFilter",
			`rewriteRule "^[(]uid=alias[)]$" "(uid=alice)" :`,
		}
		for _, context := range []string{"bindDN", "searchDN", "addDN", "addAttrDN", "modifyDN", "modifyAttrDN", "compareDN", "compareAttrDN", "deleteDN", "renameDN", "modrDN", "newSuperiorDN", "extendedDN", "searchFilterAttrDN"} {
			directives = append(directives, "rewriteContext "+context+" alias request")
		}
		for index := range directives {
			directives[index] = fmt.Sprintf("{%d}%s", index, directives[index])
		}
	}
	replaceRWMRewriteConfiguration(t, fixture.store, fixture.configDN, fixture.attribute, directives...)
	var stop func()
	fixture.server, fixture.address, stop = startRWMConfigurationServer(t, fixture.store)
	t.Cleanup(stop)
	return fixture
}

func TestRWMRewriteNamedContextsCRUD(t *testing.T) {
	for _, backend := range []string{"relay", "ldap", "meta"} {
		t.Run(backend, func(t *testing.T) {
			fixture := startRWMRewriteFixture(t, backend, true)
			client := bindConstraintClient(t, fixture.address, fixture.userDN, fixture.password)
			defer client.Close()
			result, err := client.Search(ldap.NewSearchRequest(fixture.userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(uid=alias)", []string{"uid"}, nil))
			if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != fixture.userDN {
				t.Fatalf("named searchDN/searchFilter/response = %#v, %v", result, err)
			}
			if backend == "relay" {
				if err := client.Bind(fixture.rootDN, fixture.rootPassword); err != nil {
					t.Fatal(err)
				}
			}
			addedDN := "uid=rwmdsl,ou=people," + fixture.suffix
			add := ldap.NewAddRequest(addedDN, nil)
			add.Attribute("objectClass", []string{"inetOrgPerson"})
			add.Attribute("uid", []string{"rwmdsl"})
			add.Attribute("cn", []string{"Rewrite User"})
			add.Attribute("sn", []string{"User"})
			add.Attribute("seeAlso", []string{fixture.userDN})
			if err := client.Add(add); err != nil {
				t.Fatalf("named addDN/addAttrDN: %v", err)
			}
			modify := ldap.NewModifyRequest(addedDN, nil)
			modify.Replace("seeAlso", []string{fixture.userDN})
			modify.Replace("cn", []string{"Changed User"})
			if err := client.Modify(modify); err != nil {
				t.Fatalf("named modifyDN/modifyAttrDN: %v", err)
			}
			matched, err := client.Compare(addedDN, "seeAlso", fixture.userDN)
			if err != nil || !matched {
				t.Fatalf("named compareDN/compareAttrDN = %v, %v", matched, err)
			}
			if err := client.ModifyDN(ldap.NewModifyDNRequest(addedDN, "uid=renamed", true, "ou=people,"+fixture.suffix)); err != nil {
				t.Fatalf("named rename/newSuperiorDN/newRDN: %v", err)
			}
			renamedDN := "uid=renamed,ou=people," + fixture.suffix
			if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
				t.Fatalf("named deleteDN: %v", err)
			}
		})
	}
}

func TestRWMRewriteOnlineReplacementRollback(t *testing.T) {
	for _, backend := range []string{"relay", "ldap", "meta"} {
		t.Run(backend, func(t *testing.T) {
			fixture := startRWMRewriteFixture(t, backend, false)
			config := bindConstraintClient(t, fixture.address, "cn=config", "config-secret")
			defer config.Close()
			client := bindConstraintClient(t, fixture.address, fixture.userDN, fixture.password)
			defer client.Close()
			values := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
			values = append(values, fmt.Sprintf("{%d}rewriteContext searchFilter", len(values)), fmt.Sprintf(`{%d}rewriteRule "^[(]uid=alias[)]$" "(uid=alice)" :`, len(values)+1))
			modify := ldap.NewModifyRequest(fixture.configDN, nil)
			modify.Replace(fixture.attribute, values)
			if err := config.Modify(modify); err != nil {
				t.Fatalf("activate replacement DSL: %v", err)
			}
			active := fixture.server.runtime.Load()
			stored := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
			for _, invalid := range []string{
				`rewriteRule "(?i:a)" "b" :`,
				`rewriteRule ".*" "$0{unsupported}" :`,
				`rewriteRule ".*" "${>missing($0)}" :`,
				`rewriteRule ".*" "${**session}" :`,
				`rewriteRule ".*" "$0" Z`,
				`rewriteRule ".*" "$0" "G{999999999999999999}"`,
				`rewriteMap ldap lookup ldap:///dc=test`,
				`rewriteMaxPasses 1001`,
			} {
				bad := append(slices.Clone(stored), fmt.Sprintf("{%d}%s", len(stored), invalid))
				modify := ldap.NewModifyRequest(fixture.configDN, nil)
				modify.Replace(fixture.attribute, bad)
				if err := config.Modify(modify); err == nil {
					t.Fatalf("accepted %s", invalid)
				}
				if fixture.server.runtime.Load() != active {
					t.Fatalf("failed replacement activated a runtime: %s", invalid)
				}
				got := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
				if !slices.Equal(got, stored) {
					t.Fatalf("failed replacement changed persisted DSL: %s", invalid)
				}
				result, err := client.Search(ldap.NewSearchRequest(fixture.userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(uid=alias)", []string{"uid"}, nil))
				if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != fixture.userDN {
					t.Fatalf("active DSL after rollback = %#v, %v", result, err)
				}
			}
		})
	}
}

func TestRWMRewriteConfiguredLDAPResults(t *testing.T) {
	for _, backend := range []string{"relay", "ldap", "meta"} {
		t.Run(backend, func(t *testing.T) {
			fixture := startRWMRewriteFixture(t, backend, false)
			config := bindConstraintClient(t, fixture.address, "cn=config", "config-secret")
			defer config.Close()
			client := bindConstraintClient(t, fixture.address, fixture.userDN, fixture.password)
			defer client.Close()
			original := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
			for _, test := range []struct {
				flags string
				code  uint16
			}{{"#", ldap.LDAPResultUnwillingToPerform}, {":U{51}", ldap.LDAPResultBusy}} {
				values := append(slices.Clone(original), fmt.Sprintf("{%d}rewriteContext searchDN", len(original)), fmt.Sprintf(`{%d}rewriteRule ".*" "" "%s"`, len(original)+1, test.flags))
				modify := ldap.NewModifyRequest(fixture.configDN, nil)
				modify.Replace(fixture.attribute, values)
				if err := config.Modify(modify); err != nil {
					t.Fatal(err)
				}
				_, err := client.Search(ldap.NewSearchRequest(fixture.userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(uid=alice)", []string{"uid"}, nil))
				assertLDAPResultCode(t, err, test.code)
			}
			responseContext := "searchEntryDN"
			if backend == "meta" {
				responseContext = "searchResult"
			}
			values := append(slices.Clone(original), fmt.Sprintf("{%d}rewriteContext dropped alias %s", len(original), responseContext), fmt.Sprintf(`{%d}rewriteRule ".*" "" "#"`, len(original)+1))
			modify := ldap.NewModifyRequest(fixture.configDN, nil)
			modify.Replace(fixture.attribute, values)
			if err := config.Modify(modify); err != nil {
				t.Fatal(err)
			}
			result, err := client.Search(ldap.NewSearchRequest(fixture.userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(uid=alice)", []string{"uid"}, nil))
			if err != nil || len(result.Entries) != 0 {
				t.Fatalf("rejected response entry = %#v, %v", result, err)
			}
		})
	}
}
