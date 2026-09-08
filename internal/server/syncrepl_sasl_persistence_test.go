package server

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncreplDIGESTMD5SecurityReconnectPersistence(t *testing.T) {
	for _, ssf := range []uint32{1, 128} {
		t.Run(fmt.Sprint(ssf), func(t *testing.T) {
			providerStore := storage.NewMemory()
			defer providerStore.Close()
			seedSyncProviderDirectory(t, providerStore)
			seedSASLDigestMD5Configuration(t, providerStore)
			setSyncConsumerSecurityTestGlobal(t, providerStore, "olcSaslHost", "localhost")
			setSyncConsumerSecurityTestGlobal(t, providerStore, "olcSaslSecProps", "noplain,noanonymous,maxbufsize=128")
			providerAddress, stop := startServer(t, providerStore, Config{RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
			defer stop()
			runSyncreplSecurityReconnectPersistence(t, providerAddress,
				fmt.Sprintf(`bindmethod=sasl saslmech=DIGEST-MD5 authcid=alice realm=example.com credentials=secret secprops="minssf=%d,maxssf=%d,maxbufsize=128"`, ssf, ssf))
		})
	}
}

func runSyncreplSecurityReconnectPersistence(t *testing.T, providerAddress, bind string) {
	t.Helper()
	gate := startSyncreplHAGate(t, providerAddress)
	defer gate.stop()
	_, port, err := net.SplitHostPort(gate.address())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "consumer.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	seedSyncConsumerDatabase(t, store, "localhost:"+port, "unused")
	dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSyncrepl", stringValues(`{0}rid=001 provider=ldap://localhost:`+port+` `+bind+
			` searchbase="dc=example,dc=com" scope=sub attrs="*,+" schemachecking=off type=refreshAndPersist retry="1 +"`))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	configuration := Config{RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)}
	consumerAddress, stop := startServer(t, store, configuration)
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer func() { consumer.Close() }()
	const alice = "uid=alice,ou=people,dc=example,dc=com"
	waitForSyncConsumerAttribute(t, consumer, alice, "cn", "Alice Example")
	cookieConfig := syncConsumerConfig{rid: 1, partition: storage.OpenLDAPDatabasePartition("{1}mdb", nil)}
	initial := waitForSyncreplHACookie(t, store, cookieConfig)
	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	attempts := gate.attemptCount()
	gate.pause()
	modifySyncreplHACN(t, provider, "alice", "Alice Protected Reconnect")
	gate.resume()
	waitForSyncConsumerAttribute(t, consumer, alice, "cn", "Alice Protected Reconnect")
	if gate.attemptCount() <= attempts {
		t.Fatal("consumer did not reconnect")
	}
	waitForSyncreplHACookieAdvance(t, store, cookieConfig, initial)
	persisted := waitForSyncreplHACookie(t, store, cookieConfig)
	consumer.Close()
	stop()
	stop = nil
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	gate.pause()
	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSyncConsumerCookie(t, store, cookieConfig, persisted)
	modifySyncreplHACN(t, provider, "alice", "Alice Protected Restart")
	consumerAddress, stop = startServer(t, store, configuration)
	consumer = dialLDAPRoot(t, consumerAddress)
	assertSyncConsumerLDAPAttribute(t, consumer, alice, "cn", "Alice Protected Reconnect")
	gate.resume()
	waitForSyncConsumerAttribute(t, consumer, alice, "cn", "Alice Protected Restart")
	waitForSyncreplHACookieAdvance(t, store, cookieConfig, persisted)
}
