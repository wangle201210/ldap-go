package server

import (
	"context"
	"slices"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestAllowedNativeCorpus(t *testing.T) {
	for _, placement := range []string{"database", "frontend"} {
		t.Run(placement, func(t *testing.T) {
			address := allowedReferenceGoServer(t, placement)
			allowedReferenceCheck(t, address, placement, false)
		})
	}
}

func TestAllowedIncompleteSchemaDoesNotInventEffectiveRights(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ParseAndRegisterObjectClass("( 1.3.6.1.4.1.99999.999.1 NAME 'incompleteAux' SUP missingParent AUXILIARY )"); err != nil {
		t.Fatal(err)
	}
	plan, err := buildAllowedSchemaPlan(registry, []runtimeDatabase{{name: "mdb", allowedOverlay: true}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.classes["incompleteaux"] != nil {
		t.Fatal("incomplete class obtained effective attributes")
	}
	for _, class := range plan.auxiliaries {
		if class.name == "incompleteAux" {
			t.Fatal("incomplete required set advertised as writable")
		}
	}
}

func TestAllowedDelegatedConfigurationDoesNotSilentlyDoNothing(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	remote := runtimeDatabase{name: "ldap", ldapBackend: &ldapBackendRuntimeConfiguration{}}
	if plan, err := buildAllowedSchemaPlan(registry, []runtimeDatabase{remote}); err != nil || plan != nil {
		t.Fatalf("unconfigured overlay affected delegated backend: %v", err)
	}
	remote.allowedOverlay = true
	if _, err := buildAllowedSchemaPlan(registry, []runtimeDatabase{remote}); err == nil {
		t.Fatal("accepted a delegated allowed overlay without operational projection")
	}
	remote.allowedOverlay = false
	if _, err := buildAllowedSchemaPlan(registry, []runtimeDatabase{{name: "frontend", allowedOverlay: true}, remote}); err == nil {
		t.Fatal("global overlay silently omitted delegated results")
	}
}

func BenchmarkAllowedUnrequestedProjection(b *testing.B) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	plan, err := buildAllowedSchemaPlan(registry, []runtimeDatabase{{name: "mdb", allowedOverlay: true}})
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		plan  *allowedSchemaPlan
		attrs []string
	}{
		{"disabled", nil, nil}, {"enabled-default-selection", plan, nil},
	} {
		b.Run(test.name, func(b *testing.B) {
			server := &Server{}
			runtime := &runtimeState{schema: registry, allowed: test.plan}
			entry := directory.Entry{DN: aliceDN}
			b.ReportAllocs()
			for b.Loop() {
				server.applyAllowedAttributes(runtime, nil, "", entry, entry, test.attrs, false)
			}
		})
	}
}

func allowedTestStore(t *testing.T, enabled, global bool) storage.Store {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, _ := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		database, err := writer.Get(dn)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by self write by anonymous auth by * none",
			"{1}to * by self write by * read"))
		if err := writer.Put(database, true); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{DN: "uid=bob,ou=people,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("bob")}, {Description: "cn", Values: stringValues("Bob")},
			{Description: "sn", Values: stringValues("Example")}, {Description: "userPassword", Values: stringValues("bob-secret")},
		}}, false); err != nil {
			return err
		}
		if !enabled {
			return nil
		}
		parent := "olcDatabase={1}mdb,cn=config"
		if global {
			parent = "olcDatabase={-1}frontend,cn=config"
			if err := writer.Put(directory.Entry{DN: parent, Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			}}, false); err != nil {
				return err
			}
		}
		return writer.Put(directory.Entry{DN: "olcOverlay={0}allowed," + parent, Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues("{0}allowed")},
		}}, false)
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func allowedTestSearch(t *testing.T, client *ldap.Conn, dn string, requested []string, typesOnly bool) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, typesOnly, "(objectClass=*)", requested, nil))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("allowed search: %+v %v", result, err)
	}
	return result.Entries[0]
}

func TestAllowedOperationalProjectionAndIdentity(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			store := allowedTestStore(t, enabled, false)
			address, stop := startServer(t, store, Config{})
			defer stop()
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetTimeout(3 * time.Second)
			if err := client.Bind(aliceDN, "secret"); err != nil {
				t.Fatal(err)
			}
			for _, attrs := range [][]string{nil, {"*"}, {"1.1"}} {
				entry := allowedTestSearch(t, client, aliceDN, attrs, false)
				for _, name := range allowedAttributeNames {
					if len(entry.GetAttributeValues(name)) != 0 {
						t.Fatalf("default selection included %s", name)
					}
				}
			}
			for _, attrs := range [][]string{{"+"}, {"allowedAttributes", "allowedAttributesEffective", "allowedChildClasses", "allowedChildClassesEffective"}, {"1.2.840.113556.1.4.913"}} {
				entry := allowedTestSearch(t, client, aliceDN, attrs, false)
				values := entry.GetAttributeValues("allowedAttributes")
				if enabled {
					for _, name := range []string{"objectClass", "cn", "sn", "uid", "userPassword", "mail"} {
						if !slices.Contains(values, name) {
							t.Fatalf("inherited attributes missing %s: %v", name, values)
						}
					}
					if len(attrs) != 1 || attrs[0] == "+" {
						if !slices.Contains(entry.GetAttributeValues("allowedAttributesEffective"), "mail") {
							t.Fatal("self writable attribute omitted")
						}
						children := entry.GetAttributeValues("allowedChildClasses")
						if !slices.Contains(children, "extensibleObject") || slices.Contains(children, "inetOrgPerson") {
							t.Fatalf("child classes are not auxiliary classes: %v", children)
						}
					}
				} else if len(values) != 0 {
					t.Fatal("disabled overlay generated allowed attributes")
				}
			}
			if err := client.Bind("uid=bob,ou=people,dc=example,dc=com", "bob-secret"); err != nil {
				t.Fatal(err)
			}
			entry := allowedTestSearch(t, client, aliceDN, []string{"+"}, false)
			if len(entry.GetAttributeValues("allowedAttributesEffective")) != 0 || len(entry.GetAttributeValues("allowedChildClassesEffective")) != 0 {
				t.Fatal("another user's write privileges leaked")
			}
			if enabled {
				entry = allowedTestSearch(t, client, aliceDN, []string{"allowedAttributes"}, true)
				if len(entry.Attributes) != 1 || len(entry.Attributes[0].Values) != 0 {
					t.Fatalf("typesOnly: %+v", entry.Attributes)
				}
			}
			root := allowedTestSearch(t, client, "", []string{"allowedChildClasses"}, false)
			if len(root.Attributes) != 0 {
				t.Fatal("database overlay applied to Root DSE")
			}
			if readStoredEntry(t, store, aliceDN).HasAttribute("allowedAttributes") {
				t.Fatal("virtual attributes persisted")
			}
		})
	}
}

func TestAllowedCannotFilterCompareOrWriteVirtualValues(t *testing.T) {
	store := allowedTestStore(t, true, false)
	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatal(err)
	}
	for _, filter := range []string{"(allowedAttributes=*)", "(allowedAttributes=cn)", "(allowedChildClasses=extensibleObject)"} {
		result, err := client.Search(ldap.NewSearchRequest(aliceDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"+"}, nil))
		if err != nil || len(result.Entries) != 0 {
			t.Fatalf("virtual filter matched: %+v %v", result, err)
		}
	}
	matched, err := client.Compare(aliceDN, "allowedAttributes", "cn")
	if matched || (err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute)) {
		t.Fatalf("virtual Compare: %v %v", matched, err)
	}
	modify := ldap.NewModifyRequest(aliceDN, nil)
	modify.Replace("allowedAttributes", []string{"cn"})
	if err := client.Modify(modify); !ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) {
		t.Fatalf("virtual write: %v", err)
	}
}

func TestAllowedGlobalAndPagedProjection(t *testing.T) {
	store := allowedTestStore(t, true, true)
	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	root := allowedTestSearch(t, client, "", []string{"allowedChildClasses"}, false)
	if len(root.GetAttributeValues("allowedChildClasses")) == 0 {
		t.Fatal("frontend overlay did not project Root DSE")
	}
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatal(err)
	}
	result, err := client.SearchWithPaging(ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeSingleLevel, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=inetOrgPerson)", []string{"uid", "allowedAttributes", "allowedAttributesEffective"}, nil), 1)
	if err != nil || len(result.Entries) != 2 {
		t.Fatalf("paged allowed: %+v %v", result, err)
	}
	for _, entry := range result.Entries {
		if !slices.Contains(entry.GetAttributeValues("allowedAttributes"), "uid") {
			t.Fatal("paged projection omitted schema data")
		}
		if entry.DN != aliceDN && len(entry.GetAttributeValues("allowedAttributesEffective")) != 0 {
			t.Fatal("page crossed entry ACL boundary")
		}
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return reader.ForEach(func(entry directory.Entry) error {
			for _, name := range allowedAttributeNames {
				if entry.HasAttribute(name) {
					t.Errorf("%s stored %s", entry.DN, name)
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAllowedOnlineActivationACLReloadAndRollback(t *testing.T) {
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
		t.Fatal(err)
	}
	reader, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	search := func() *ldap.Entry {
		return allowedTestSearch(t, reader, aliceDN, []string{"allowedAttributes", "allowedAttributesEffective"}, false)
	}
	if len(search().Attributes) != 0 {
		t.Fatal("allowed attributes active before overlay")
	}
	const overlayDN = "olcOverlay={0}allowed,olcDatabase={1}mdb,cn=config"
	add := ldap.NewAddRequest(overlayDN, nil)
	add.Attribute("objectClass", []string{"olcOverlayConfig"})
	add.Attribute("olcOverlay", []string{"{0}allowed"})
	if err := config.Add(add); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(search().GetAttributeValues("allowedAttributes"), "cn") {
		t.Fatal("online activation did not publish projection")
	}
	if len(search().GetAttributeValues("allowedAttributesEffective")) != 0 {
		t.Fatal("read-only identity has writable attributes")
	}
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	modify.Replace("olcAccess", []string{"{0}to * by * write"})
	if err := config.Modify(modify); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(search().GetAttributeValues("allowedAttributesEffective"), "cn") {
		t.Fatal("ACL reload retained previous rights")
	}
	conflict := ldap.NewAddRequest("cn={9}allowed-conflict,cn=schema,cn=config", nil)
	conflict.Attribute("objectClass", []string{"olcSchemaConfig"})
	conflict.Attribute("cn", []string{"{9}allowed-conflict"})
	conflict.Attribute("olcAttributeTypes", []string{"( 1.2.840.113556.1.4.913 NAME 'allowedAttributes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"})
	if err := config.Add(conflict); err == nil {
		t.Fatal("incompatible schema redefined generated attribute")
	}
	if !slices.Contains(search().GetAttributeValues("allowedAttributesEffective"), "cn") {
		t.Fatal("rejected schema changed runtime projection")
	}
	if err := config.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatal(err)
	}
	if len(search().Attributes) != 0 {
		t.Fatal("deleted overlay still generates values")
	}
}
