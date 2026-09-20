package server

import (
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPGoSyncreplOpenLDAPProviderSubtreeRename(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	providerURI, stopProvider := startOpenLDAPReferenceServer(t, tools, []string{"syncprov"})
	defer stopProvider()
	provider, err := ldap.DialURL(providerURI)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if err := provider.Bind(syncTestRootDN, "secret"); err != nil {
		t.Fatal(err)
	}

	const oldParent = "ou=people,dc=example,dc=com"
	const newParent = "ou=renamed,dc=example,dc=com"
	team := ldap.NewAddRequest("ou=team,"+oldParent, nil)
	team.Attribute("objectClass", []string{"organizationalUnit"})
	team.Attribute("ou", []string{"team"})
	if err := provider.Add(team); err != nil {
		t.Fatal(err)
	}
	nested := ldap.NewAddRequest("cn=nested,ou=team,"+oldParent, nil)
	nested.Attribute("objectClass", []string{"person"})
	nested.Attribute("cn", []string{"nested"})
	nested.Attribute("sn", []string{"Example"})
	if err := provider.Add(nested); err != nil {
		t.Fatal(err)
	}

	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "consumer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedSyncConsumerDatabase(t, store, strings.TrimPrefix(providerURI, "ldap://"), "secret")
	address, stopConsumer := startServer(t, store, Config{
		RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, address)
	defer consumer.Close()
	type identity struct{ uuid, csn string }
	children := make(map[string]identity)
	for _, relative := range []string{"uid=alice", "uid=bob", "uid=carol", "ou=team", "cn=nested,ou=team"} {
		dn := relative + "," + oldParent
		value := identity{
			uuid: ldapEntryAttribute(t, provider, dn, "entryUUID"),
			csn:  ldapEntryAttribute(t, provider, dn, "entryCSN"),
		}
		waitForSyncConsumerAttribute(t, consumer, dn, "entryUUID", value.uuid)
		children[relative] = value
	}
	if err := provider.ModifyDN(ldap.NewModifyDNRequest(oldParent, "ou=renamed", true, "")); err != nil {
		t.Fatalf("rename native provider subtree: %v", err)
	}
	waitForSyncConsumerAttribute(t, consumer, newParent, "ou", "renamed")
	for relative, value := range children {
		newChild := relative + "," + newParent
		if got := ldapEntryAttribute(t, provider, newChild, "entryUUID"); got != value.uuid {
			t.Fatalf("provider changed descendant UUID: %s != %s", got, value.uuid)
		}
		if got := ldapEntryAttribute(t, provider, newChild, "entryCSN"); got != value.csn {
			t.Fatalf("provider changed descendant CSN: %s != %s", got, value.csn)
		}
		waitForSyncConsumerAttribute(t, consumer, newChild, "entryUUID", value.uuid)
		waitForSyncConsumerAttribute(t, consumer, newChild, "entryCSN", value.csn)
		waitForSyncConsumerMissing(t, consumer, relative+","+oldParent)
	}
	waitForSyncConsumerMissing(t, consumer, oldParent)
}
