package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestOpenLDAP2613SyncreplSCRAMPlus(t *testing.T) {
	tools := requireSASLCBindingOpenLDAP(t)
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	config := syncConsumerSCRAMTestConfig(t, authority)
	config.authenticationID = "replicator"
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "server.pem"), filepath.Join(root, "server.key")
	if err := os.WriteFile(certPath, certificate.certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, certificate.privateKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	const replicatorDN = "uid=replicator,ou=people,dc=example,dc=com"
	for _, policy := range []string{"tls-endpoint", "none", "tls-unique"} {
		t.Run(policy, func(t *testing.T) {
			uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, []string{"syncprov"},
				fmt.Sprintf(`TLSCertificateFile %s
TLSCertificateKeyFile %s
sasl-host localhost
sasl-secprops none
sasl-cbinding %s
authz-regexp "^uid=replicator,.*cn=auth$" "%s"`, certPath, keyPath, policy, replicatorDN),
				`access to * by dn.exact="`+replicatorDN+`" read by anonymous auth by * none`,
				`
dn: `+replicatorDN+`
objectClass: inetOrgPerson
uid: replicator
cn: Replicator
sn: Replicator
userPassword: secret
`)
			defer stop()
			uri = strings.Replace(uri, "127.0.0.1", "localhost", 1)
			for _, mechanism := range syncConsumerSCRAMPlusMechanisms {
				t.Run(mechanism, func(t *testing.T) {
					configuration := config
					configuration.saslMechanism = mechanism
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					transport, err := dialSyncConsumer(ctx, configuration, uri)
					if err != nil {
						t.Fatal(err)
					}
					defer transport.close()
					provider, err := parseSyncConsumerProviderURL(uri)
					if err != nil {
						t.Fatal(err)
					}
					if err := performSyncConsumerStartTLS(transport, configuration, provider); err != nil {
						t.Fatal(err)
					}
					err = bindSyncConsumerSASL(transport, configuration, uri)
					if policy != "tls-endpoint" {
						if err == nil {
							t.Fatalf("PLUS accepted incompatible server binding policy %s", policy)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if err := transport.clearDeadline(); err != nil {
						t.Fatal(err)
					}
					client := ldap.NewConn(transport.currentConnection(), true)
					client.Start()
					client.SetTimeout(2 * time.Second)
					defer client.Close()
					identity, err := client.WhoAmI(nil)
					if err != nil || identity.AuthzID != "dn:"+replicatorDN {
						t.Fatalf("WhoAmI = %#v, %v", identity, err)
					}
					result, err := client.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree,
						ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
					if err != nil || len(result.Entries) < 3 {
						t.Fatalf("authenticated search = %#v, %v", result, err)
					}
				})
			}
		})
	}
}
