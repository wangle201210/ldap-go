package server

import (
	"context"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPDispatchACLContextAcrossProxyAndBind(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedProxyAuthorizationDirectory(t, store, "", nil, nil)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(mustProxyAuthorizationDN(aliceDN))
		if err != nil {
			return err
		}
		entry.ReplaceValues("mail", stringValues("alice@example.com"))
		entry.ReplaceValues("description", stringValues("TLS only"))
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		database, err := writer.Get(mustProxyAuthorizationDN("olcDatabase={1}mdb,cn=config"))
		if err != nil {
			return err
		}
		database.ReplaceValues("olcAccess", stringValues(
			`{0}to attrs=userPassword by anonymous auth by * none`,
			`{1}to attrs=cn by self read by * none`,
			`{2}to attrs=sn by realdn.exact="`+proxyAuthorizationRootDN+`" read by * none`,
			`{3}to attrs=mail by peername.ip="127.0.0.0%255.0.0.0" read by * none`,
			`{4}to attrs=description by tls_ssf=1 read by * none`,
			`{5}to * by * read`,
		))
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("seed context ACLs: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN: proxyAuthorizationRootDN, RootPassword: []byte(proxyAuthorizationRootPassword),
		MaxOperationsPerConnection: 1,
	})
	defer stop()
	client := dialAndBindLDAPClient(t, address, aliceDN, "secret")
	defer client.Close()
	client.SetTimeout(3 * time.Second)
	search := func(controls []ldap.Control, cn, sn, description bool) {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(aliceDN, ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 0, 0, false, "(uid=alice)", []string{"uid", "cn", "sn", "mail", "description"}, controls))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("Search() = %#v, %v", result, err)
		}
		for name, want := range map[string]bool{"uid": true, "cn": cn, "sn": sn, "mail": true, "description": description} {
			if got := len(result.Entries[0].GetAttributeValues(name)) > 0; got != want {
				t.Fatalf("attribute %s visible=%t, want %t; entry=%#v", name, got, want, result.Entries[0])
			}
		}
	}
	search(nil, true, false, false)
	search(nil, true, false, false)
	if err := client.Bind(proxyAuthorizationRootDN, proxyAuthorizationRootPassword); err != nil {
		t.Fatalf("root rebind: %v", err)
	}
	search([]ldap.Control{proxyAuthorizationControl("dn:"+aliceDN, true)}, true, true, false)
	search([]ldap.Control{proxyAuthorizationControl("dn:"+proxyAuthorizationBobDN, true)}, false, true, false)
	search(nil, true, true, true)
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:"+proxyAuthorizationRootDN {
		t.Fatalf("restored identity = %#v, %v", identity, err)
	}
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("user rebind: %v", err)
	}
	search(nil, true, false, false)
}
