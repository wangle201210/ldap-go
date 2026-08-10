package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
