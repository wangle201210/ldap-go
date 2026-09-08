package server

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestOpenLDAPSyncreplDIGESTMD5SecurityLayers(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	// Cyrus uses OpenSSL's legacy provider for the RFC 2831 RC4/DES ciphers.
	// This configuration belongs only to the disposable reference process.
	opensslConfig := filepath.Join(t.TempDir(), "openssl.cnf")
	writeOpenLDAPGSSAPITestFile(t, opensslConfig, `openssl_conf = openssl_init
[openssl_init]
providers = providers
[providers]
default = default_provider
legacy = legacy_provider
[default_provider]
activate = 1
[legacy_provider]
activate = 1
`)
	t.Setenv("OPENSSL_CONF", opensslConfig)
	const replicatorDN = "uid=replicator,ou=people,dc=example,dc=com"
	for _, ssf := range []uint32{1, 40, 55, 56, 112, 128} {
		t.Run(fmt.Sprint(ssf), func(t *testing.T) {
			providerURI, stop := startOpenLDAPReferenceServerWithConfig(t, tools, []string{"syncprov"},
				`sasl-realm example.com
sasl-secprops noplain,noanonymous,maxbufsize=128
authz-regexp "^uid=replicator,.*cn=auth$" "`+replicatorDN+`"`,
				`access to * by dn.exact="`+replicatorDN+`" read by anonymous auth by * none`,
				`
dn: `+replicatorDN+`
objectClass: inetOrgPerson
uid: replicator
cn: Replicator
sn: Replicator
userPassword: replication-secret
`)
			defer stop()
			configuration := syncConsumerConfig{
				bindMethod: "sasl", saslMechanism: "DIGEST-MD5", authenticationID: "replicator", realm: "example.com",
				credentials: []byte("replication-secret"), operationTimeout: 3 * time.Second,
				securityProperties: syncConsumerSASLSecurityProperties{minSSF: ssf, maxSSF: ssf, maxBufferSize: 128},
			}
			transport, err := dialSyncConsumer(t.Context(), configuration, providerURI)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.close()
			if err := bindSyncConsumerSASL(transport, configuration, providerURI); err != nil {
				t.Fatal(err)
			}
			if transport.ssf != ssf {
				t.Fatalf("SSF = %d, want %d", transport.ssf, ssf)
			}
			if err := transport.clearDeadline(); err != nil {
				t.Fatal(err)
			}
			connection := ldap.NewConn(&syncConsumerResponseConn{Conn: transport.currentConnection()}, false)
			connection.Start()
			connection.SetTimeout(3 * time.Second)
			defer connection.Close()
			// Small negotiated buffers force real Cyrus frames to cross BER boundaries.
			result, err := connection.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"*", "+"}, nil))
			if err != nil || len(result.Entries) < 3 {
				t.Fatalf("protected search: %v", err)
			}
			identity, err := connection.WhoAmI(nil)
			if err != nil || !strings.EqualFold(identity.AuthzID, "dn:"+replicatorDN) {
				t.Fatalf("identity = %#v, %v", identity, err)
			}
		})
	}
}
