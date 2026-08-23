package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestAttributeOptionRangeSearchAndModify(t *testing.T) {
	registry := registryWithAttributeOptions(t, "x x- range=")
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	aliceDN, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(aliceDN)
		if err != nil {
			return err
		}
		entry.Attributes = append(entry.Attributes,
			directory.Attribute{
				Description: "description;x",
				Values:      stringValues("exact"),
			},
			directory.Attribute{
				Description: "description;x-item",
				Values:      stringValues("prefixed"),
			},
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed optioned attributes: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Schema:       registry,
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		aliceDN.String(),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description;x-"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(description;x-): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search entry count = %d, want 1", len(result.Entries))
	}
	var descriptions []string
	for _, attribute := range result.Entries[0].Attributes {
		descriptions = append(descriptions, attribute.Name)
	}
	slices.Sort(descriptions)
	if !slices.Equal(descriptions, []string{"description;x", "description;x-item"}) {
		t.Fatalf("Search attributes = %v", descriptions)
	}

	for _, description := range []string{"description;x-", "description;range=0-1"} {
		modify := ldap.NewModifyRequest(aliceDN.String(), nil)
		modify.Replace(description, []string{"replacement"})
		err := client.Modify(modify)
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) ||
			ldapErr.ResultCode != ldap.LDAPResultUndefinedAttributeType {
			t.Errorf("Modify(%q) error = %v, want undefinedAttributeType", description, err)
		}
	}
}

func TestOpenLDAPReferenceAttributeOptionRangeSearchAndModify(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"attributeoptions x x- range=",
		"",
		"",
	)
	defer stop()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	const aliceDN = "uid=alice,ou=people,dc=example,dc=com"
	seed := ldap.NewModifyRequest(aliceDN, nil)
	seed.Add("description;x", []string{"exact"})
	seed.Add("description;x-item", []string{"prefixed"})
	if err := client.Modify(seed); err != nil {
		t.Fatalf("seed optioned attributes: %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		aliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description;x-"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(description;x-): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search entry count = %d, want 1", len(result.Entries))
	}
	var descriptions []string
	for _, attribute := range result.Entries[0].Attributes {
		descriptions = append(descriptions, attribute.Name)
	}
	slices.Sort(descriptions)
	if !slices.Equal(descriptions, []string{"description;x", "description;x-item"}) {
		t.Fatalf("Search attributes = %v", descriptions)
	}

	for _, description := range []string{"description;x-", "description;range=0-1"} {
		modify := ldap.NewModifyRequest(aliceDN, nil)
		modify.Replace(description, []string{"replacement"})
		err := client.Modify(modify)
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) ||
			ldapErr.ResultCode != ldap.LDAPResultUndefinedAttributeType {
			t.Errorf("Modify(%q) error = %v, want undefinedAttributeType", description, err)
		}
	}
}

func TestOpenLDAPReferenceAttributeOptionConfiguration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	tests := []struct {
		options string
		valid   bool
	}{
		{options: "x x- range=", valid: true},
		{options: "binary"},
		{options: "x- x-value"},
		{options: "x-value x-"},
		{options: "x x"},
		{options: "range=="},
	}
	for _, test := range tests {
		t.Run(test.options, func(t *testing.T) {
			root := t.TempDir()
			databaseDir := filepath.Join(root, "db")
			if err := os.Mkdir(databaseDir, 0o700); err != nil {
				t.Fatalf("create database directory: %v", err)
			}
			configPath := filepath.Join(root, "slapd.conf")
			config := fmt.Sprintf(
				"include %s\nattributeoptions %s\n"+
					"database mdb\nsuffix \"dc=example,dc=com\"\ndirectory %s\n",
				filepath.Join(tools.schemaDir, "core.schema"),
				test.options,
				databaseDir,
			)
			if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
				t.Fatalf("write slapd.conf: %v", err)
			}
			output, referenceErr := exec.Command(
				tools.slapd,
				"-Ttest",
				"-u",
				"-f", configPath,
			).CombinedOutput()
			if (referenceErr == nil) != test.valid {
				t.Fatalf(
					"OpenLDAP accepted=%t, want %t: %v\n%s",
					referenceErr == nil,
					test.valid,
					referenceErr,
					output,
				)
			}

			_, implementationErr := loadRegistryWithAttributeOptions(t, test.options)
			if (implementationErr == nil) != (referenceErr == nil) {
				t.Fatalf(
					"ldap-go error = %v, OpenLDAP error = %v\n%s",
					implementationErr,
					referenceErr,
					output,
				)
			}
		})
	}
}

const languageOptionTestDN = "uid=language-options,ou=people,dc=example,dc=com"

var languageOptionTestEntry = directory.Entry{
	DN: languageOptionTestDN,
	Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues(
			"top", "person", "organizationalPerson", "inetOrgPerson",
		)},
		{Description: "uid", Values: stringValues("language-options")},
		{Description: "cn", Values: stringValues("Bare CN")},
		{Description: "cn;lang-en", Values: stringValues("English CN")},
		{Description: "cn;lang-en-us", Values: stringValues("American CN")},
		{Description: "cn;lang-fr", Values: stringValues("French CN")},
		{Description: "sn", Values: stringValues("Bare SN")},
		{Description: "sn;lang-en", Values: stringValues("English SN")},
		{Description: "description", Values: stringValues("Bare description")},
		{Description: "description;lang-fr", Values: stringValues("French description")},
	},
}

func TestLanguageAttributeOptionProjection(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(languageOptionTestEntry, false)
	}); err != nil {
		t.Fatalf("seed language option entry: %v", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Schema:       registry,
	})
	defer stop()

	got := observeLanguageAttributeOptionProjection(t, "ldap://"+address, "admin-secret")
	assertLanguageAttributeOptionProjection(t, got)
}

func TestOpenLDAPReferenceLanguageAttributeOptionProjection(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"",
		`

dn: uid=language-options,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: language-options
cn: Bare CN
cn;lang-en: English CN
cn;lang-en-us: American CN
cn;lang-fr: French CN
sn: Bare SN
sn;lang-en: English SN
description: Bare description
description;lang-fr: French description
`,
	)
	defer stop()

	reference := observeLanguageAttributeOptionProjection(t, uri, "secret")
	assertLanguageAttributeOptionProjection(t, reference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(languageOptionTestEntry, false)
	}); err != nil {
		t.Fatalf("seed local language option entry: %v", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	address, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Schema:       registry,
	})
	defer stopLocal()
	local := observeLanguageAttributeOptionProjection(t, "ldap://"+address, "admin-secret")
	if !reflect.DeepEqual(local, reference) {
		t.Fatalf("language option projection\nlocal:     %#v\nOpenLDAP: %#v", local, reference)
	}
}

type languageAttributeProjection map[string]map[string][]string

func observeLanguageAttributeOptionProjection(
	t *testing.T,
	uri,
	password string,
) languageAttributeProjection {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", password); err != nil {
		t.Fatalf("Bind(%s): %v", uri, err)
	}
	tests := []struct {
		name      string
		requested []string
		typesOnly bool
	}{
		{name: "bare", requested: []string{"cn"}},
		{name: "exact", requested: []string{"cn;lang-en"}},
		{name: "range", requested: []string{"cn;lang-"}},
		{name: "supertype", requested: []string{"name;lang-en"}},
		{name: "wildcard", requested: []string{"*"}},
		{name: "types-only", requested: []string{"cn;lang-"}, typesOnly: true},
	}
	result := make(languageAttributeProjection, len(tests))
	for _, test := range tests {
		search, searchErr := client.Search(ldap.NewSearchRequest(
			languageOptionTestDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			test.typesOnly,
			"(objectClass=*)",
			test.requested,
			nil,
		))
		if searchErr != nil || len(search.Entries) != 1 {
			t.Fatalf("Search(%s, %v): entries=%d err=%v", test.name, test.requested, len(search.Entries), searchErr)
		}
		attributes := make(map[string][]string)
		for _, attribute := range search.Entries[0].Attributes {
			base := strings.ToLower(strings.SplitN(attribute.Name, ";", 2)[0])
			if base != "cn" && base != "sn" && base != "description" {
				continue
			}
			values := append([]string(nil), attribute.Values...)
			slices.Sort(values)
			attributes[strings.ToLower(attribute.Name)] = values
		}
		result[test.name] = attributes
	}
	return result
}

func assertLanguageAttributeOptionProjection(t *testing.T, got languageAttributeProjection) {
	t.Helper()
	want := languageAttributeProjection{
		"bare": {
			"cn":            {"Bare CN"},
			"cn;lang-en":    {"English CN"},
			"cn;lang-en-us": {"American CN"},
			"cn;lang-fr":    {"French CN"},
		},
		"exact": {
			"cn;lang-en": {"English CN"},
		},
		"range": {
			"cn;lang-en":    {"English CN"},
			"cn;lang-en-us": {"American CN"},
			"cn;lang-fr":    {"French CN"},
		},
		"supertype": {
			"cn;lang-en": {"English CN"},
			"sn;lang-en": {"English SN"},
		},
		"wildcard": {
			"cn":                  {"Bare CN"},
			"cn;lang-en":          {"English CN"},
			"cn;lang-en-us":       {"American CN"},
			"cn;lang-fr":          {"French CN"},
			"sn":                  {"Bare SN"},
			"sn;lang-en":          {"English SN"},
			"description":         {"Bare description"},
			"description;lang-fr": {"French description"},
		},
		"types-only": {
			"cn;lang-en":    nil,
			"cn;lang-en-us": nil,
			"cn;lang-fr":    nil,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("language attribute projection = %#v, want %#v", got, want)
	}
}

func registryWithAttributeOptions(t *testing.T, options string) *schema.Registry {
	t.Helper()
	registry, err := loadRegistryWithAttributeOptions(t, options)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	return registry
}

func loadRegistryWithAttributeOptions(
	t *testing.T,
	options string,
) (*schema.Registry, error) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(storage.OpenLDAPConfigPartition, directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcAttributeOptions",
				Values:      stringValues(options),
			}},
		}, false)
	}); err != nil {
		t.Fatalf("seed olcAttributeOptions: %v", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if _, err := schema.LoadOpenLDAPConfig(context.Background(), store, registry); err != nil {
		return nil, err
	}
	return registry, nil
}
