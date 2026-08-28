package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestNopsOverlaySuppressesIdempotentReplace(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedNopsOverlay(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stop)
	root := dialAndBindReferencePassword(
		t,
		"ldap://"+address,
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer root.Close()

	before := readStoredEntry(t, store, aliceDN)
	modify := ldap.NewModifyRequest(aliceDN, nil)
	modify.Replace("sn", []string{"Example"})
	if err := root.Modify(modify); err != nil {
		t.Fatalf("idempotent Modify: %v", err)
	}
	after := readStoredEntry(t, store, aliceDN)
	if !before.Equal(after) {
		t.Fatalf("idempotent Modify changed entry:\nbefore=%#v\nafter=%#v", before, after)
	}

	mixed := ldap.NewModifyRequest(aliceDN, nil)
	mixed.Replace("sn", []string{"Example"})
	mixed.Replace("description", []string{"changed"})
	if err := root.Modify(mixed); err != nil {
		t.Fatalf("mixed Modify: %v", err)
	}
	after = readStoredEntry(t, store, aliceDN)
	if got := after.Values("description"); len(got) != 1 || string(got[0]) != "changed" {
		t.Fatalf("description = %q", got)
	}
	if string(after.Values("sn")[0]) != "Example" {
		t.Fatalf("sn = %q", after.Values("sn"))
	}
}

func TestNopsValueMatchingPreservesOpenLDAPDuplicateQuirk(t *testing.T) {
	if !nopsValuesEqual(
		[][]byte{[]byte("a"), []byte("a")},
		[][]byte{[]byte("a"), []byte("b")},
	) {
		t.Fatal("duplicate replacement did not reproduce OpenLDAP matching quirk")
	}
	if nopsValuesEqual([][]byte{[]byte("a")}, [][]byte{[]byte("a"), []byte("b")}) {
		t.Fatal("different value counts were accepted")
	}
}

func seedNopsOverlay(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}nops,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      stringValues("{0}nops"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
}
