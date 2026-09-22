package server

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSubstringMetadataPreservesSpecialEntries(t *testing.T) {
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "metadata.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedAliasDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{DN: "cn=reference,ou=people,dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("referral", "extensibleObject")},
			{Description: "cn", Values: stringValues("reference")},
			{Description: "ref", Values: stringValues("ldap://example.invalid/dc=remote,dc=test")},
		}}, false)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatal(err)
	}
	addSubentry(t, client, "cn=policy,ou=people,dc=example,dc=com", "policy")
	for _, base := range []string{"dc=example,dc=com", "ou=people,dc=example,dc=com", "ou=aliases,dc=example,dc=com"} {
		for _, deref := range []int{ldap.NeverDerefAliases, ldap.DerefInSearching, ldap.DerefFindingBaseObj, ldap.DerefAlways} {
			for _, filter := range []string{"(uid=ali*)", "(uid=missing*)", "(cn=pol*)", "(cn=ref*)"} {
				for i, controls := range [][]ldap.Control{nil, {subentriesControl(true)}, {subentriesControl(false)}, {ldap.NewControlManageDsaIT(true)}, {ldap.NewControlManageDsaIT(true), subentriesControl(true)}} {
					t.Run(fmt.Sprintf("%s/%d/%s/%d", base, deref, filter, i), func(t *testing.T) {
						search := func(f string) (*ldap.SearchResult, error) {
							return client.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, deref, 0, 0, false, f, []string{"uid", "cn", "ref"}, controls))
						}
						got, gotErr := search(filter)
						want, wantErr := search("(&" + filter + ")")
						if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
							t.Fatalf("metadata search differs: %v/%v, want %v/%v", got, gotErr, want, wantErr)
						}
						if base == "ou=people,dc=example,dc=com" && deref == ldap.NeverDerefAliases && filter == "(uid=missing*)" && i == 0 && (gotErr != nil || len(got.Referrals) != 1) {
							t.Fatal("nonmatching referral was lost")
						}
					})
				}
			}
		}
	}
}
