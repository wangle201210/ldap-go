package server

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSubstringScanMatchesGeneralFilter(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			var store storage.Store = storage.NewMemory()
			if backend == "bolt" {
				var err error
				store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "substring.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			seedPagedPeople(t, store, 30)
			address, stop := startServer(t, store, Config{RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
			defer stop()
			for _, root := range []bool{true, false} {
				client, err := ldap.DialURL("ldap://" + address)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if root {
					err = client.Bind(syncTestRootDN, syncTestRootPassword)
				} else {
					err = client.Bind(aliceDN, "secret")
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, filter := range []string{"(uid=page-0*)", "(uid=page-*)", "(uid=missing*)", "(uid=*ice)", "(cn=*ag*0*)", "(cn;lang-en=Pag*)", "(unknownAttribute=*)"} {
					for _, typesOnly := range []bool{false, true} {
						for _, limit := range []int{0, 1, 10, 100} {
							for _, attrs := range [][]string{{"uid", "cn"}, {"*"}, nil, {"*", "+"}, {"1.1"}} {
								search := func(f string) (*ldap.SearchResult, error) {
									return client.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 0, typesOnly, f, attrs, nil))
								}
								got, gotErr := search(filter)
								want, wantErr := search("(&" + filter + ")")
								if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
									t.Fatalf("root=%t filter=%s types=%t limit=%d attrs=%v: got %v/%v, want %v/%v", root, filter, typesOnly, limit, attrs, got, gotErr, want, wantErr)
								}
								if filter == "(uid=page-0*)" && limit == 100 && (gotErr != nil || len(got.Entries) != 10) {
									t.Fatal("prefix result count changed")
								}
							}
						}
					}
				}
			}
		})
	}
}
