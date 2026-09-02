package server

import (
	"context"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestMetaACLRequirementExtraction(t *testing.T) {
	requirements, err := loadMetaACLRequirements([][]byte{
		[]byte(`{0}to filter="(&(sn=Proxy)(uid:caseIgnoreMatch:=alice))" by dnattr=owner read`),
		[]byte(`{1}to * by dynacl/aci=customACI read`),
		[]byte(`{2}to * by group/groupOfNames/member.exact="cn=readers,dc=meta,dc=test" read`),
		[]byte(`{3}to * by set="this/manager & user" read`),
	})
	if err != nil {
		t.Fatalf("loadMetaACLRequirements(): %v", err)
	}
	want := []string{"sn", "uid", "owner", "customACI", "objectClass"}
	if !requirements.enabled || !requirements.requiresComplete ||
		!requirements.usesGroup || !reflect.DeepEqual(requirements.attributes, want) {
		t.Fatalf("requirements = %#v, want attributes %q with complete/group", requirements, want)
	}
}

func TestPrepareMetaACLSearchRequestAddsTargetFilterDependency(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedMetaOperationProxy(t, store, "127.0.0.1:1")
	setMetaACLDependencyRules(t, store, []string{
		`{0}to filter="(sn=Proxy)" attrs=jpegPhoto by * none`,
		`{1}to * by * read`,
	})
	server, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	t.Cleanup(server.metaTransports.close)
	runtime := server.runtime.Load()
	dn, err := runtime.schema.NormalizeDN(metaOperationLocalUser)
	if err != nil {
		t.Fatalf("NormalizeDN(): %v", err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil {
		t.Fatal("meta database was not loaded")
	}
	request, enabled, err := server.prepareMetaACLSearchRequest(
		context.Background(),
		&connectionState{runtime: runtime},
		*database,
		ldapwire.SearchRequest{
			BaseDN:     metaOperationLocalUser,
			Scope:      directory.ScopeBase,
			TypesOnly:  true,
			Attributes: []string{"jpegPhoto"},
		},
	)
	if err != nil {
		t.Fatalf("prepareMetaACLSearchRequest(): %v", err)
	}
	if !enabled {
		t.Fatal("meta ACL was not discovered")
	}
	if request.TypesOnly {
		t.Fatal("upstream ACL request retained typesOnly")
	}
	if want := []string{"jpegPhoto", "sn", "objectClass"}; !reflect.DeepEqual(request.Attributes, want) {
		t.Fatalf("upstream attributes = %q, want %q", request.Attributes, want)
	}
}

func TestMetaBackendACLTargetFilterUsesUnrequestedAttribute(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedMetaOperationProxy(t, proxyStore, providerAddress)
	setMetaACLDependencyRules(t, proxyStore, []string{
		`{0}to filter="(sn=Proxy)" attrs=jpegPhoto by * none`,
		`{1}to * by * read`,
	})
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := dialLDAPBackendClient(t, proxyAddress)
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		metaOperationLocalUser,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"jpegPhoto"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(back-meta target-filter ACL): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search entries = %d, want 1", len(result.Entries))
	}
	if len(result.Entries[0].GetRawAttributeValues("jpegPhoto")) != 0 {
		t.Fatal("target-filter ACL leaked jpegPhoto when sn was not requested")
	}
}

func TestMetaAndAsyncMetaACLPolicySources(t *testing.T) {
	rules := []string{
		`to filter="(sn=Proxy)" attrs=jpegPhoto by * none`,
		`to * by * read`,
	}
	for _, backend := range []string{"meta", "asyncmeta"} {
		for _, source := range []string{"database", "global", "config"} {
			t.Run(backend+"/"+source, func(t *testing.T) {
				providerStore := storage.NewMemory()
				t.Cleanup(func() { _ = providerStore.Close() })
				seedLDAPBackendProvider(t, providerStore)
				providerAddress, stopProvider := startServer(t, providerStore, Config{
					RootDN:       ldapBackendTestAdminDN,
					RootPassword: []byte(ldapBackendTestAdminSecret),
				})
				defer stopProvider()

				proxyStore := storage.NewMemory()
				t.Cleanup(func() { _ = proxyStore.Close() })
				databaseDN := seedMetaACLProxy(
					t,
					proxyStore,
					providerAddress,
					backend,
				)
				var policy *acl.Policy
				switch source {
				case "database":
					setMetaACLRulesAtDN(t, proxyStore, databaseDN, rules)
				case "global":
					setMetaACLRulesAtDN(t, proxyStore, "cn=config", rules)
				case "config":
					policy = newMetaACLPolicy(t, rules)
				}
				proxyAddress, stopProxy := startServer(t, proxyStore, Config{
					AccessPolicy: policy,
				})
				defer stopProxy()

				client := dialLDAPBackendClient(t, proxyAddress)
				defer client.Close()
				result, err := client.Search(ldap.NewSearchRequest(
					metaOperationLocalUser,
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					1,
					0,
					false,
					"(objectClass=*)",
					[]string{"jpegPhoto"},
					nil,
				))
				if err != nil || len(result.Entries) != 1 {
					t.Fatalf("Search(%s %s ACL) = %#v, %v", backend, source, result, err)
				}
				if len(result.Entries[0].GetRawAttributeValues("jpegPhoto")) != 0 {
					t.Fatalf("%s %s ACL leaked jpegPhoto", backend, source)
				}
			})
		}
	}
}

func TestMetaBackendACLIdentityDependencies(t *testing.T) {
	localGroupDN := "cn=readers," + metaOperationLocalPeople
	remoteGroupDN := "cn=readers," + ldapBackendTestPeopleDN
	for _, test := range []struct {
		name       string
		matcher    string
		attributes []directory.Attribute
		group      *directory.Entry
	}{
		{
			name:    "dnattr",
			matcher: "dnattr=owner",
			attributes: []directory.Attribute{{
				Description: "owner",
				Values:      stringValues(ldapBackendTestUserDN),
			}},
		},
		{
			name:    "group",
			matcher: `group.exact="` + localGroupDN + `"`,
			group: &directory.Entry{
				DN: remoteGroupDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("groupOfNames")},
					{Description: "cn", Values: stringValues("readers")},
					{Description: "member", Values: stringValues(ldapBackendTestUserDN)},
				},
			},
		},
		{
			name:    "set",
			matcher: `set="this/owner & user"`,
			attributes: []directory.Attribute{{
				Description: "owner",
				Values:      stringValues(ldapBackendTestUserDN),
			}},
		},
		{
			name:    "set LDAP URL scan",
			matcher: `set="this/description/entryDN & user"`,
			attributes: []directory.Attribute{{
				Description: "description",
				Values: stringValues(
					"ldap:///" + metaOperationLocalPeople + "??sub?(uid=alice)",
				),
			}},
		},
		{
			name:    "ACI dnattr",
			matcher: "dynacl/aci",
			attributes: []directory.Attribute{
				{Description: "owner", Values: stringValues(ldapBackendTestUserDN)},
				{
					Description: "OpenLDAPaci",
					Values: stringValues(
						"0#entry#grant;r;jpegPhoto#dnattr#owner",
					),
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerStore := storage.NewMemory()
			t.Cleanup(func() { _ = providerStore.Close() })
			seedLDAPBackendProvider(t, providerStore)
			if err := providerStore.Update(context.Background(), func(writer storage.Writer) error {
				userDN, err := directory.ParseDN(ldapBackendTestUserDN)
				if err != nil {
					return err
				}
				user, err := writer.Get(userDN)
				if err != nil {
					return err
				}
				for _, attribute := range test.attributes {
					user.ReplaceValues(attribute.Description, attribute.Values)
				}
				if err := writer.Put(user, true); err != nil {
					return err
				}
				if test.group != nil {
					return writer.Put(*test.group, false)
				}
				return nil
			}); err != nil {
				t.Fatalf("seed ACL dependency entries: %v", err)
			}
			providerAddress, stopProvider := startServer(t, providerStore, Config{
				RootDN:       ldapBackendTestAdminDN,
				RootPassword: []byte(ldapBackendTestAdminSecret),
			})
			defer stopProvider()

			proxyStore := storage.NewMemory()
			t.Cleanup(func() { _ = proxyStore.Close() })
			databaseDN := seedMetaACLProxy(t, proxyStore, providerAddress, "meta")
			setMetaACLRulesAtDN(t, proxyStore, databaseDN, []string{
				"to attrs=jpegPhoto by " + test.matcher + " read by * none",
				"to * by * read",
			})
			proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
			defer stopProxy()

			client := dialLDAPBackendClient(t, proxyAddress)
			defer client.Close()
			if err := client.Bind(metaOperationLocalUser, ldapBackendTestUserPassword); err != nil {
				t.Fatalf("Bind(back-meta ACL subject): %v", err)
			}
			result, err := client.Search(ldap.NewSearchRequest(
				metaOperationLocalUser,
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				1,
				0,
				false,
				"(objectClass=*)",
				[]string{"jpegPhoto"},
				nil,
			))
			if err != nil || len(result.Entries) != 1 ||
				len(result.Entries[0].GetRawAttributeValues("jpegPhoto")) != 1 {
				t.Fatalf("Search(%s ACL dependency) = %#v, %v", test.name, result, err)
			}
		})
	}
}

func TestMetaACLRemoteRequestProjectionPagingAndSort(t *testing.T) {
	t.Run("no ACL fast path", func(t *testing.T) {
		providerURI, provider, stopProvider := startOpenLDAPMetaClientPRProvider(t, false, 0)
		defer stopProvider()
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedLDAPGoMetaClientPRConfiguration(t, store, providerURI, "disable")
		address, stopProxy := startServer(t, store, Config{})
		defer stopProxy()

		client := dialLDAPBackendClient(t, address)
		defer client.Close()
		_, err := client.Search(ldap.NewSearchRequest(
			openLDAPMetaBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			true,
			"(objectClass=*)",
			[]string{"uid;lang-en", "jpegPhoto;binary", "+", "1.1"},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(no-ACL fast path): %v", err)
		}
		raw := provider.rawSnapshot()
		if len(raw) != 1 {
			t.Fatalf("upstream Searches = %d, want 1", len(raw))
		}
		want := []string{"uid;lang-en", "jpegPhoto;binary", "+", "1.1"}
		if !raw[0].request.TypesOnly || !reflect.DeepEqual(raw[0].request.Attributes, want) {
			t.Fatalf("no-ACL upstream request = %#v, want unchanged attributes/typesOnly", raw[0].request)
		}
	})

	t.Run("ACL dependencies stay private across client-pr pages", func(t *testing.T) {
		providerURI, provider, stopProvider := startOpenLDAPMetaClientPRProvider(t, false, 0)
		defer stopProvider()
		for index := range provider.entries {
			provider.entries[index].Attributes = append(
				provider.entries[index].Attributes,
				directory.Attribute{
					Description: "uid;lang-en",
					Values:      stringValues("localized-" + string(rune('0'+index))),
				},
				directory.Attribute{
					Description: "jpegPhoto;binary",
					Values:      [][]byte{{byte(index), 0xff}},
				},
				directory.Attribute{
					Description: "entryUUID",
					Values:      stringValues("00000000-0000-0000-0000-00000000000" + string(rune('0'+index))),
				},
			)
		}
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedLDAPGoMetaClientPRConfiguration(t, store, providerURI, "2")
		setMetaACLRulesAtDN(t, store, "olcDatabase={1}meta,cn=config", []string{
			`to filter="(sn=never)" attrs=description by * none`,
			`to * by * read`,
		})
		address, stopProxy := startServer(t, store, Config{})
		defer stopProxy()

		client := dialLDAPBackendClient(t, address)
		defer client.Close()
		if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
			t.Fatalf("Bind(back-meta root): %v", err)
		}
		page := ldap.NewControlPaging(99)
		sortControl := ldap.NewControlString(
			sortRequestControlOID,
			false,
			string(ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
				AttributeType: "uid",
			}})),
		)
		result, err := client.Search(ldap.NewSearchRequest(
			openLDAPMetaBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			true,
			"(objectClass=*)",
			[]string{"uid;lang-en", "jpegPhoto;binary", "+", "1.1"},
			[]ldap.Control{page, sortControl},
		))
		if err != nil {
			t.Fatalf("Search(ACL client-pr/sort): %v", err)
		}
		if len(result.Entries) != openLDAPMetaClientPREntryCount {
			t.Fatalf("Search entries = %d, want %d", len(result.Entries), openLDAPMetaClientPREntryCount)
		}
		for _, entry := range result.Entries {
			seen := make(map[string]bool)
			for _, attribute := range entry.Attributes {
				name := strings.ToLower(attribute.Name)
				switch name {
				case "uid;lang-en", "jpegphoto;binary", "entryuuid":
					seen[name] = true
				default:
					t.Fatalf("supplemental ACL attribute %q leaked in %s", attribute.Name, entry.DN)
				}
				if len(attribute.ByteValues) != 0 || len(attribute.Values) != 0 {
					t.Fatalf("typesOnly attribute %q retained values", attribute.Name)
				}
			}
			for _, name := range []string{"uid;lang-en", "jpegphoto;binary", "entryuuid"} {
				if !seen[name] {
					t.Fatalf("requested attribute %q is missing from %s", name, entry.DN)
				}
			}
		}

		raw := provider.rawSnapshot()
		if len(raw) != 3 {
			t.Fatalf("upstream client-pr Searches = %d, want 3", len(raw))
		}
		wantAttributes := []string{
			"uid;lang-en",
			"jpegPhoto;binary",
			"+",
			"1.1",
			"sn",
			"objectClass",
		}
		for index, request := range raw {
			if request.request.TypesOnly ||
				!reflect.DeepEqual(request.request.Attributes, wantAttributes) {
				t.Fatalf("upstream request %d = %#v", index, request.request)
			}
			if countControlOID(request.controls, sortRequestControlOID) != 1 ||
				countControlOID(request.controls, pagedResultsControlOID) != 1 {
				t.Fatalf("upstream request %d controls = %#v", index, request.controls)
			}
			paging := findLDAPControl(request.controls, pagedResultsControlOID)
			size, _, err := ldapwire.DecodePagedResultsValue(paging.Value)
			if err != nil || size != 2 {
				t.Fatalf("upstream request %d paging = %#v, %v", index, paging, err)
			}
		}
	})
}

func TestMetaACLAuxiliaryLookupFailureIsUnavailable(t *testing.T) {
	providerURI, provider, stopProvider := startOpenLDAPMetaClientPRProvider(t, false, 0)
	defer stopProvider()
	localGroupDN := "cn=readers," + openLDAPMetaBaseDN
	provider.failSearchBase("cn=readers," + openLDAPMetaClientPRRemoteBase)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoMetaClientPRConfiguration(t, store, providerURI, "disable")
	setMetaACLRulesAtDN(t, store, "olcDatabase={1}meta,cn=config", []string{
		`to attrs=uid by group.exact="` + localGroupDN + `" read by * none`,
		`to * by * read`,
	})
	address, stopProxy := startServer(t, store, Config{})
	defer stopProxy()

	client := dialLDAPBackendClient(t, address)
	defer client.Close()
	if err := client.Bind("uid=client-pr-0,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("Bind(back-meta ACL subject): %v", err)
	}
	_, err := client.Search(ldap.NewSearchRequest(
		"uid=client-pr-0,"+openLDAPMetaBaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
}

func countControlOID(controls []ldapwire.Control, oid string) int {
	count := 0
	for _, control := range controls {
		if control.OID == oid {
			count++
		}
	}
	return count
}

func findLDAPControl(controls []ldapwire.Control, oid string) ldapwire.Control {
	for _, control := range controls {
		if control.OID == oid {
			return control
		}
	}
	return ldapwire.Control{}
}

func setMetaACLDependencyRules(
	t *testing.T,
	store storage.Store,
	rules []string,
) {
	t.Helper()
	setMetaACLRulesAtDN(t, store, metaOperationDatabaseDN, rules)
}

func setMetaACLRulesAtDN(
	t *testing.T,
	store storage.Store,
	rawDN string,
	rules []string,
) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("parse back-meta database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(rules...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure back-meta ACL: %v", err)
	}
}

func newMetaACLPolicy(t *testing.T, values []string) *acl.Policy {
	t.Helper()
	rules := make([]acl.Rule, len(values))
	for index, value := range values {
		rule, err := acl.ParseRule(value)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", value, err)
		}
		rules[index] = rule
	}
	policy, err := acl.NewPolicy(rules, nil)
	if err != nil {
		t.Fatalf("NewPolicy(): %v", err)
	}
	return policy
}

func seedMetaACLProxy(
	t *testing.T,
	store storage.Store,
	providerAddress string,
	backend string,
) string {
	t.Helper()
	backend = strings.ToLower(backend)
	databaseDN := "olcDatabase={1}" + backend + ",cn=config"
	targetAttribute := "olcMetaSub"
	targetObjectClass := "olcMetaTargetConfig"
	databaseObjectClass := "olcMetaConfig"
	if backend == "asyncmeta" {
		targetAttribute = "olcAsyncMetaSub"
		targetObjectClass = "olcAsyncMetaTargetConfig"
		databaseObjectClass = "olcAsyncMetaConfig"
	}
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", databaseObjectClass)},
				{Description: "olcDatabase", Values: stringValues("{1}" + backend)},
				{Description: "olcSuffix", Values: stringValues(metaOperationLocalSuffix)},
				{Description: "olcRootDN", Values: stringValues(metaOperationLocalRootDN)},
				{Description: "olcRootPW", Values: stringValues(metaOperationLocalRootPass)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			},
		},
		{
			DN: targetAttribute + "={0}uri," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues(targetObjectClass)},
				{Description: targetAttribute, Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(
					"ldap://" + providerAddress + "/" + metaOperationLocalSuffix,
				)},
				{Description: "olcDbRewrite", Values: stringValues(
					`suffixmassage "` + metaOperationLocalSuffix + `" "` + ldapBackendTestSuffix + `"`,
				)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{metaOperationLocalSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed %s ACL proxy: %v", backend, err)
	}
	return databaseDN
}
