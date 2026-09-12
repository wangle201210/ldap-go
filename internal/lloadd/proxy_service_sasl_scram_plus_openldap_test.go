package lloadd

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
)

// Source comparison only: read objects at the exact pin, independently of the
// checkout's current HEAD. This does not claim a native binary differential run.
func TestServiceSASLSCRAMPlusOpenLDAP2613SourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("set OPENLDAP_SOURCE to a git repository containing the OpenLDAP 2.6.13 pin")
	}
	read := func(path string) string {
		t.Helper()
		data, err := exec.Command("git", "-C", source, "show", openLDAPLloaddCommit+":"+path).Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	upstream := read("servers/lloadd/upstream.c")
	for _, anchor := range []string{
		"ldap_pvt_tls_get_unique( ssl, &cbv, 0 )", `cb->name = "ldap";`, "cb->critical = 0;",
		"cb->len = cbv.bv_len;", "memcpy( cb_data, cbv.bv_val, cbv.bv_len );",
		"sasl_setprop( ctx, SASL_CHANNEL_BINDING, cb );",
	} {
		if !strings.Contains(upstream, anchor) {
			t.Fatalf("native lloadd binding contract lacks %q", anchor)
		}
	}
	config := read("servers/lloadd/config.c")
	if !strings.Contains(config, "static slap_cf_aux_table bindkey[]") || strings.Contains(config, "tls_cbinding") {
		t.Fatal("native lloadd binding-type configuration boundary changed")
	}
	cyrus := read("libraries/libldap/cyrus.c")
	for _, anchor := range []string{`endpoint_prefix[] = "tls-server-end-point:"`, `cb->name = "ldap";`, "cb->len = plen + cbv.bv_len;", "memcpy( cb_data, prefix, plen );"} {
		if !strings.Contains(cyrus, anchor) {
			t.Fatalf("native libldap endpoint contract lacks %q", anchor)
		}
	}
	t.Logf("OpenLDAP 2.6.13 %s: lloadd automatic raw tls-unique, no tls_cbinding; libldap endpoint uses ldap + prefixed digest", openLDAPLloaddCommit)
}

// Exercise the native lloadd binding bytes with the existing SCRAM provider.
// Unlike GSSAPI's noncritical input, a selected PLUS exchange authenticates c=.
func TestServiceSASLSCRAMPlusRejectsNativeUniqueBinding(t *testing.T) {
	t.Parallel()
	pki := newExternalTestPKI(t)
	pki.serverTLS.MinVersion, pki.serverTLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	for _, mechanism := range serviceSCRAMPlusTestMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			generator, _ := serviceSCRAMGenerator(mechanism)
			client, err := generator.NewClient("service", serviceSASLTestPassword, "")
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: "native-unique-salt", Iters: 4096})
			if err != nil {
				t.Fatal(err)
			}
			server, err := generator.NewServer(func(string) (scram.StoredCredentials, error) { return credentials, nil })
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan bool, 1)
			uri := startServiceSCRAMPlusTestPeer(t, pki.serverTLS, false, func(conn *tls.Conn) {
				defer func() { done <- true }()
				unique := conn.ConnectionState().TLSUnique
				if len(unique) == 0 {
					t.Error("missing real TLS 1.2 unique data")
					return
				}
				conversation := server.NewConversationWithChannelBindingRequired(scram.ChannelBinding{Type: "ldap", Data: unique})
				for step := 0; step < 2; step++ {
					message, err := ldapwire.ReadMessage(conn, ldapwire.DefaultMaxMessageSize)
					if err != nil {
						t.Error(err)
						return
					}
					bind, ok := message.Request.(ldapwire.BindRequest)
					if !ok || bind.Authentication.SASLMechanism != mechanism {
						t.Error("PLUS mechanism changed")
						return
					}
					response, err := conversation.Step(string(bind.Authentication.SASLCredentials))
					code := ldapwire.ResultSASLBindInProgress
					if step == 0 && err != nil {
						t.Error(err)
						return
					}
					if step == 1 {
						if err == nil || conversation.Valid() {
							t.Error("endpoint matched raw tls-unique")
							return
						}
						code = ldapwire.ResultInvalidCredentials
					}
					if err := ldapwire.Write(conn, ldapwire.EncodeSASLBindResponse(message.ID, ldapwire.Result{Code: code}, []byte(response), true, nil)); err != nil {
						t.Error(err)
						return
					}
				}
				var data [1]byte
				if n, err := conn.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Error("PLUS retried or downgraded after binding mismatch")
				}
			})
			proxy, err := NewProxy(serviceSCRAMPlusTestConfig(t, pki, uri, mechanism, false))
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			if upstream, err := proxy.tiers[0].backends[0].connect(t.Context(), "native-unique", false); err == nil || upstream != nil {
				t.Fatal("incompatible binding was admitted")
			}
			<-done
		})
	}
}
