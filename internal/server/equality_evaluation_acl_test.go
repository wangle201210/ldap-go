package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPEqualityEvaluationPreservesNonRootACL(t *testing.T) {
	t.Parallel()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := tx.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by anonymous auth by * none",
			"{1}to attrs=sn by * none",
			"{2}to * by users read by * none",
		))
		return tx.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		filter string
		want   int
	}{
		{"(uid=alice)", 1},
		{"(objectClass=person)", 1},
		{"(sn=Example)", 0},
		{"(!(sn=Example))", 0},
		{"(!(sn=absent))", 0},
		{"(userPassword=secret)", 0},
		{"(!(userPassword=wrong))", 0},
		{"(&(uid=alice)(!(sn=absent)))", 0},
		{"(|(sn=Example)(uid=alice))", 1},
		{"(|(sn=Example)(uid=absent))", 0},
		{"(!(|(sn=absent)(uid=absent)))", 0},
		{"(!(&(sn=Example)(uid=absent)))", 1},
		{"(!(unknownEqualityAttribute=value))", 0},
		{"(!(createTimestamp=bad-time))", 0},
	} {
		t.Run(test.filter, func(t *testing.T) {
			result, err := client.Search(ldap.NewSearchRequest(
				"uid=alice,ou=people,dc=example,dc=com", ldap.ScopeBaseObject,
				ldap.NeverDerefAliases, 0, 0, false, test.filter,
				[]string{"uid", "sn", "userPassword"}, nil,
			))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Entries) != test.want {
				t.Fatalf("Search returned %d entries, want %d", len(result.Entries), test.want)
			}
			for _, entry := range result.Entries {
				if len(entry.GetAttributeValues("sn")) != 0 || len(entry.GetAttributeValues("userPassword")) != 0 {
					t.Fatal("Search exposed denied attribute values")
				}
			}
		})
	}
}
