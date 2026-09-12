package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncreplSCRAMPlusReconnectPersistence(t *testing.T) {
	for _, mechanism := range syncConsumerSCRAMPlusMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedSyncProviderDirectory(t, store)
			seedSASLSCRAMConfiguration(t, store, mechanism)
			setUnsupportedRuntimeConfigurationAttribute(t, store, "cn=config", saslCBindingAttribute, "tls-endpoint")
			authority := newGlobalTLSTestAuthority(t)
			certificate := authority.issue(t, "localhost", true)
			config := syncConsumerSCRAMTestConfig(t, authority)
			address, stop := startServer(t, store, Config{RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword),
				TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate.tlsCertificate}, MinVersion: tls.VersionTLS12}})
			defer stop()
			runSyncreplSecurityReconnectPersistence(t, address, fmt.Sprintf(
				`bindmethod=sasl saslmech=%s authcid=alice credentials=secret starttls=critical tls_reqcert=demand tls_cacert=%q timeout=3 network-timeout=3`,
				mechanism, config.tls.caCertificate))
		})
	}
}

func TestSyncreplSCRAMPlusRejectsStartTLSDowngrade(t *testing.T) {
	for _, mechanism := range syncConsumerSCRAMPlusMechanisms {
		for _, startTLS := range []syncConsumerStartTLS{syncConsumerStartTLSOff, syncConsumerStartTLSYes} {
			t.Run(fmt.Sprintf("%s/starttls=%d", mechanism, startTLS), func(t *testing.T) {
				address, done := startSyncConsumerSCRAMPeer(t, func(connection net.Conn) error {
					if startTLS != syncConsumerStartTLSOff {
						message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
						if err != nil {
							return err
						}
						request, ok := message.Request.(ldapwire.ExtendedRequest)
						if !ok || request.Name != syncConsumerStartTLSOID {
							return fmt.Errorf("expected StartTLS, got %#v", message.Request)
						}
						decoded := ldapwire.EncodeExtendedResponse(message.ID,
							ldapwire.Result{Code: ldapwire.ResultUnavailable}, "", nil, nil)
						if err := writeSyncConsumerPacket(connection, decoded); err != nil {
							return err
						}
					}
					return expectSyncConsumerSCRAMClosed(connection)
				})
				consumer, store, config := newSyncConsumerUnitServer(t)
				config.bindMethod, config.saslMechanism = "sasl", mechanism
				config.authenticationID, config.credentials = "alice", []byte("secret")
				config.startTLS = startTLS
				config.networkTimeout, config.operationTimeout = time.Second, time.Second
				cookie := []byte("rid=001,csn=20260730010101.000001Z#000000#001#000000")
				if err := consumer.storeSyncConsumerCookie(t.Context(), config, cookie); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				err := consumer.runSyncConsumerCycle(ctx, config, "ldap://"+address)
				cancel()
				if err == nil || (startTLS != syncConsumerStartTLSOff && !strings.Contains(err.Error(), "start TLS")) {
					t.Errorf("expected TLS failure, got %v", err)
				}
				assertSyncConsumerCookie(t, store, config, cookie)
				waitSyncConsumerSCRAMPeer(t, done)
			})
		}
	}
}
