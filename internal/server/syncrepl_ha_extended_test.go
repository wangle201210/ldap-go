package server

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncreplTwoNodeSingleWriterHAExtendedFailureMatrix(t *testing.T) {
	t.Run("multiple provider URIs fail over in both directions", func(t *testing.T) {
		providerStore := storage.NewMemory()
		defer providerStore.Close()
		seedSyncProviderDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopProvider()

		first := startSyncreplHAGate(t, providerAddress)
		defer first.stop()
		second := startSyncreplHAGate(t, providerAddress)
		defer second.stop()
		first.pause()

		consumerStore := storage.NewMemory()
		defer consumerStore.Close()
		seedSyncreplHAConsumerDatabase(t, consumerStore, []string{
			"ldap://" + first.address(),
			"ldap://" + second.address(),
		}, "")
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopConsumer()

		consumer := dialLDAPRoot(t, consumerAddress)
		defer consumer.Close()
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Example")
		waitForSyncreplHAGateAttempts(t, first, 1)
		waitForSyncreplHAGateAttempts(t, second, 1)

		provider := dialLDAPRoot(t, providerAddress)
		defer provider.Close()
		first.resume()
		second.pause()
		modifySyncreplHACN(t, provider, "alice", "Alice Primary Restored")
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Primary Restored")
		waitForSyncreplHAGateAttempts(t, first, 2)

		first.pause()
		second.resume()
		modifySyncreplHACN(t, provider, "alice", "Alice Secondary Restored")
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Secondary Restored")
		waitForSyncreplHAGateAttempts(t, second, 2)
	})

	t.Run("long offline interval spans retries and converges", func(t *testing.T) {
		providerStore := storage.NewMemory()
		defer providerStore.Close()
		seedSyncProviderDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopProvider()
		gate := startSyncreplHAGate(t, providerAddress)
		defer gate.stop()

		consumerStore := storage.NewMemory()
		defer consumerStore.Close()
		seedSyncreplHAConsumerDatabase(t, consumerStore,
			[]string{"ldap://" + gate.address()}, "")
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopConsumer()
		consumer := dialLDAPRoot(t, consumerAddress)
		defer consumer.Close()
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Example")

		provider := dialLDAPRoot(t, providerAddress)
		defer provider.Close()
		baselineAttempts := gate.attemptCount()
		gate.pause()
		for revision := 1; revision <= 5; revision++ {
			modifySyncreplHACN(t, provider, "alice", fmt.Sprintf("Alice Offline %d", revision))
		}
		if err := provider.Add(newPersonAddRequest("offline-added")); err != nil {
			t.Fatalf("provider Add(offline-added): %v", err)
		}
		waitForSyncreplHAGateAttempts(t, gate, baselineAttempts+3)
		assertSyncConsumerLDAPAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Example")

		gate.resume()
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Offline 5")
		waitForSyncConsumerAttribute(t, consumer,
			"uid=offline-added,ou=people,dc=example,dc=com", "uid", "offline-added")
	})

	t.Run("consumer survives repeated process restarts", func(t *testing.T) {
		providerStore := storage.NewMemory()
		defer providerStore.Close()
		seedSyncProviderDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopProvider()
		provider := dialLDAPRoot(t, providerAddress)
		defer provider.Close()

		consumerStore := storage.NewMemory()
		defer consumerStore.Close()
		seedSyncConsumerDatabase(t, consumerStore, providerAddress, syncTestRootPassword)
		consumerConfig := syncConsumerConfig{
			rid:       1,
			partition: storage.OpenLDAPDatabasePartition("{1}mdb", nil),
		}
		var previousCookie []byte
		for restart := 0; restart < 4; restart++ {
			want := "Alice Example"
			if restart > 0 {
				want = fmt.Sprintf("Alice Restart %d", restart)
			}
			consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
				RootDN:       syncTestRootDN,
				RootPassword: []byte(syncTestRootPassword),
			})
			consumer := dialLDAPRoot(t, consumerAddress)
			waitForSyncConsumerAttribute(t, consumer,
				"uid=alice,ou=people,dc=example,dc=com", "cn", want)
			cookie := waitForSyncreplHACookie(t, consumerStore, consumerConfig)
			if restart > 0 && !syncreplHACookieStrictlyAdvances(previousCookie, cookie) {
				consumer.Close()
				stopConsumer()
				t.Fatalf("restart %d cookie %q did not advance beyond %q",
					restart, cookie, previousCookie)
			}
			previousCookie = cookie
			consumer.Close()
			stopConsumer()
			if restart < 3 {
				modifySyncreplHACN(t, provider, "alice",
					fmt.Sprintf("Alice Restart %d", restart+1))
			}
		}
		assertSyncreplHAEntryCount(t, provider, "(uid=alice)", 1)
	})

	t.Run("LDAPS certificate trust failure recovers after rotation", func(t *testing.T) {
		trustedAuthority := newGlobalTLSTestAuthority(t)
		untrustedAuthority := newGlobalTLSTestAuthority(t)
		trustedCertificate := trustedAuthority.issue(t, "localhost", true).tlsCertificate
		untrustedCertificate := untrustedAuthority.issue(t, "localhost", true).tlsCertificate
		var activeCertificate atomic.Pointer[tls.Certificate]
		activeCertificate.Store(&trustedCertificate)

		providerStore := storage.NewMemory()
		defer providerStore.Close()
		seedSyncProviderDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
			ImplicitTLS:  true,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return activeCertificate.Load(), nil
				},
			},
		})
		defer stopProvider()
		gate := startSyncreplHAGate(t, providerAddress)
		defer gate.stop()

		caFile := filepath.Join(t.TempDir(), "trusted-ca.pem")
		if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: trustedAuthority.certificateDER,
		}), 0o600); err != nil {
			t.Fatalf("write trusted CA: %v", err)
		}
		_, port, err := net.SplitHostPort(gate.address())
		if err != nil {
			t.Fatalf("split gate address: %v", err)
		}
		consumerStore := storage.NewMemory()
		defer consumerStore.Close()
		seedSyncreplHAConsumerDatabase(t, consumerStore,
			[]string{"ldaps://localhost:" + port},
			`tls_cacert="`+caFile+`" tls_reqcert=demand`)
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
		defer stopConsumer()
		consumer := dialLDAPRoot(t, consumerAddress)
		defer consumer.Close()
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Example")

		provider, err := ldap.DialURL("ldaps://"+providerAddress,
			ldap.DialWithTLSConfig(&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			}))
		if err != nil {
			t.Fatalf("dial LDAPS provider: %v", err)
		}
		defer provider.Close()
		if err := provider.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
			t.Fatalf("bind LDAPS provider: %v", err)
		}

		baselineAttempts := gate.attemptCount()
		activeCertificate.Store(&untrustedCertificate)
		gate.pause()
		gate.resume()
		modifySyncreplHACN(t, provider, "alice", "Alice During Bad Certificate")
		// A second retry proves that at least one full TLS attempt failed; merely
		// observing the proxy accept a TCP connection would race the handshake.
		waitForSyncreplHAGateAttempts(t, gate, baselineAttempts+2)
		assertSyncConsumerLDAPAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice Example")

		activeCertificate.Store(&trustedCertificate)
		waitForSyncConsumerAttribute(t, consumer,
			"uid=alice,ou=people,dc=example,dc=com", "cn", "Alice During Bad Certificate")
	})
}

func seedSyncreplHAConsumerDatabase(
	t *testing.T,
	store storage.Store,
	providers []string,
	extra string,
) {
	t.Helper()
	providerValue := strings.Join(providers, " ")
	config := `{0}rid=001 provider="` + providerValue + `"` +
		` bindmethod=simple binddn="` + syncTestRootDN + `"` +
		` credentials="` + syncTestRootPassword + `"` +
		` searchbase="dc=example,dc=com" filter="(objectClass=*)"` +
		` scope=sub attrs="*,+" schemachecking=off` +
		` type=refreshAndPersist retry="1 +"`
	if extra != "" {
		config += " " + extra
	}
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcSyncrepl", Values: stringValues(config)},
			{Description: "olcUpdateRef", Values: stringValues(providers[0])},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed HA sync consumer database: %v", err)
	}
}

func waitForSyncreplHAGateAttempts(
	t *testing.T,
	gate *syncreplHAGate,
	want int,
) {
	t.Helper()
	deadline := time.Now().Add(syncConsumerWaitTimeout())
	for time.Now().Before(deadline) {
		if gate.attemptCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("HA gate attempts = %d, want at least %d", gate.attemptCount(), want)
}
