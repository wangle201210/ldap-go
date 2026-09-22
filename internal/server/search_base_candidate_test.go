package server

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestBasePresenceCandidateMatchesGeneralSearch(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			var store storage.Store = storage.NewMemory()
			if backend == "bolt" {
				var err error
				store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "base.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = store.Close() })
			seedAliasDirectory(t, store)
			address, stop := startServer(t, store, Config{RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret")})
			defer stop()
			for _, root := range []bool{true, false} {
				client, err := ldap.DialURL("ldap://" + address)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if root {
					if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
						t.Fatal(err)
					}
				}
				for _, base := range []string{"dc=example,dc=com", "uid=alice,ou=people,dc=example,dc=com", "cn=direct,ou=aliases,dc=example,dc=com", "cn=missing,dc=example,dc=com"} {
					for _, deref := range []int{ldap.NeverDerefAliases, ldap.DerefInSearching, ldap.DerefFindingBaseObj, ldap.DerefAlways} {
						for _, typesOnly := range []bool{false, true} {
							t.Run(fmt.Sprintf("root=%t/%s/deref=%d/types=%t", root, base, deref, typesOnly), func(t *testing.T) {
								search := func(filter string) (*ldap.SearchResult, error) {
									return client.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, deref, 2, 0, typesOnly, filter, []string{"*", "+"}, nil))
								}
								got, gotErr := search("(objectClass=*)")
								want, wantErr := search("(&(objectClass=*))")
								if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
									t.Fatalf("base search differs: %v/%v, want %v/%v", got, gotErr, want, wantErr)
								}
								if root && base == "dc=example,dc=com" && (gotErr != nil || len(got.Entries) != 1) {
									t.Fatal("expected exactly one root base entry")
								}
							})
						}
					}
				}
			}
		})
	}
}
