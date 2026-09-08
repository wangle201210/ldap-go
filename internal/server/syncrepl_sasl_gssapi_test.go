package server

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerGSSAPISecurityTransport(t *testing.T) {
	for _, ssf := range []uint32{1, 256} {
		t.Run(fmt.Sprint(ssf), func(t *testing.T) {
			for cycle := range 2 {
				client, peer := net.Pipe()
				defer peer.Close()
				state := saslkrb5.SecurityState{SendSequence: uint64(11 + cycle*100), ReceiveSequence: uint64(29 + cycle*100), AcceptorSubkey: true}
				layer := byte(saslkrb5.SecurityIntegrity)
				if ssf > 1 {
					layer = saslkrb5.SecurityConfidentiality
				}
				done := make(chan error, 1)
				go runLDAPBackendGSSAPITestServer(peer, ldapBackendGSSAPITestKey(), state, done, layer)
				transport := &syncConsumerTransport{connection: client, context: t.Context(), operationTimeout: 3 * time.Second}
				defer transport.close()
				configuration := syncConsumerConfig{
					bindMethod: "sasl", saslMechanism: "GSSAPI", authenticationID: "proxy", realm: "EXAMPLE.TEST",
					authorizationID: "dn:uid=alice,dc=example,dc=com", credentials: []byte("secret"), credentialsSet: true,
					securityProperties: syncConsumerSASLSecurityProperties{minSSF: ssf, maxSSF: ssf, maxBufferSize: 128},
				}
				if err := bindSyncConsumerGSSAPISecurityWithFactory(t.Context(), transport, configuration, "ldap://ldap.example.test",
					func(settings syncConsumerGSSAPISettings) (ldapBackendGSSAPIInitiator, error) {
						if settings.servicePrincipal != "ldap/ldap.example.test" {
							return nil, fmt.Errorf("target = %q", settings.servicePrincipal)
						}
						return &ldapBackendGSSAPITestInitiator{key: ldapBackendGSSAPITestKey(), state: state}, nil
					}); err != nil {
					t.Fatal(err)
				}
				if transport.ssf != ssf || string(configuration.credentials) != "secret" {
					t.Fatal("SSF or credentials changed incorrectly")
				}
				secured := transport.currentConnection()
				if _, err := secured.Write([]byte("secured request")); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, len("secured response"))
				if _, err := io.ReadFull(secured, response); err != nil || string(response) != "secured response" {
					t.Fatalf("response = %q, %v", response, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				transport.close()
			}
		})
	}
}

func TestSyncConsumerGSSAPISecurityRejectsInvalidProperties(t *testing.T) {
	for _, properties := range []syncConsumerSASLSecurityProperties{
		{minSSF: 2, maxSSF: 1},
		{maxSSF: 256, maxBufferSize: 1 << 24},
		{passCredentials: true},
		{forwardSecrecy: true},
	} {
		client, peer := net.Pipe()
		transport := &syncConsumerTransport{connection: client, context: t.Context()}
		err := bindSyncConsumerGSSAPISecurityWithFactory(t.Context(), transport,
			syncConsumerConfig{securityProperties: properties}, "ldap://localhost",
			func(syncConsumerGSSAPISettings) (ldapBackendGSSAPIInitiator, error) {
				t.Error("initialized credentials for an invalid policy")
				return nil, fmt.Errorf("unexpected initialization")
			})
		client.Close()
		peer.Close()
		if err == nil {
			t.Fatalf("accepted invalid properties: %+v", properties)
		}
	}
}

func TestSyncreplGSSAPISecurityReconnectPersistence(t *testing.T) {
	tools := requireOpenLDAPGSSAPITestTools(t)
	kdc := startOpenLDAPGSSAPITestKDC(t, tools)
	t.Setenv("KRB5_CONFIG", kdc.configuration)
	t.Setenv("KRB5CCNAME", "FILE:"+kdc.credential)
	t.Setenv("KRB5_CLIENT_KTNAME", "")
	t.Setenv("KRB5_KTNAME", "")
	for _, ssf := range []uint32{1, 256} {
		t.Run(fmt.Sprint(ssf), func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			seedSyncProviderDirectory(t, store)
			seedSASLConfiguration(t, store, "noplain,noanonymous,maxbufsize=128",
				`^uid=alice,cn=[^,]+,cn=gssapi,cn=auth$ uid=alice,ou=people,dc=example,dc=com`)
			setSyncConsumerSecurityTestGlobal(t, store, "olcSaslHost", "localhost")
			address, stop := startServer(t, store, Config{
				RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword), GSSAPIKeytabPath: "FILE:" + kdc.serviceKeytab,
			})
			defer stop()
			runSyncreplSecurityReconnectPersistence(t, address,
				fmt.Sprintf(`bindmethod=sasl saslmech=GSSAPI secprops="minssf=%d,maxssf=%d,maxbufsize=128"`, ssf, ssf))
		})
	}
}
