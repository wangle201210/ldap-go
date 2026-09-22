package server

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSQLSearchRequirementsFeature(t *testing.T) {
	if runtimeFeaturesForDatabases([]runtimeDatabase{{name: "{1}mdb"}}).sqlBackend {
		t.Fatal("local database enabled SQL requirements")
	}
	if !runtimeFeaturesForDatabases([]runtimeDatabase{{name: "{1}mdb"}, {
		name: "{2}sql", sqlBackend: &sqlBackendRuntimeConfiguration{},
	}}).sqlBackend {
		t.Fatal("SQL database did not enable requirements")
	}
}

func TestSubschemaDepthShortcutMatchesGeneralComparison(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeState{schema: registry}
	target, err := registry.NormalizeDN("cn=Subschema")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "cn=Subschema", "CN=subschema", "2.5.4.3=Subschema", "cn=other", "cn=Subschema,dc=example", "uid=alice,ou=people,dc=example"} {
		dn, err := registry.NormalizeDN(value)
		if err != nil {
			t.Fatal(err)
		}
		if got := isRuntimeSubschemaDN(runtime, dn); got != target.Equal(dn) {
			t.Fatalf("subschema match changed for %q", value)
		}
	}
}

func TestIndexedPagedSnapshotLargeValueFallback(t *testing.T) {
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seedDirectory(t, store)
	seedPagedPeople(t, store, 150)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbIndex", stringValues("objectClass eq"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{
		RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret"),
		MaxSearchCandidateBytes: 128 << 10,
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()
	original, err := client.Search(newPagedPeopleSearch(0, nil))
	if err != nil || len(original.Entries) != 151 {
		t.Fatalf("initial entries: %v, %v", original, err)
	}
	largeDN := original.Entries[1].DN
	largeValue := strings.Repeat("x", 256<<10)
	modify := ldap.NewModifyRequest(largeDN, nil)
	modify.Replace("description", []string{largeValue})
	if err := client.Modify(modify); err != nil {
		t.Fatal(err)
	}
	control := ldap.NewControlPaging(1)
	request := newPagedPeopleSearch(0, control)
	request.Attributes = []string{"uid", "description"}
	var dns []string
	for page := 0; ; page++ {
		if page > 151 {
			t.Fatal("paging failed to terminate")
		}
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, entry := range result.Entries {
			dns = append(dns, entry.DN)
			if entry.DN == largeDN && entry.GetAttributeValue("description") != largeValue {
				t.Fatal("fallback lost the large value")
			}
		}
		cookie := pagedResponseControl(t, result).Cookie
		if len(cookie) == 0 {
			break
		}
		control.SetCookie(bytes.Clone(cookie))
	}
	if !slices.Equal(dns, searchResultDNs(original)) {
		t.Fatal("snapshot fallback changed entry order or contents")
	}
}
