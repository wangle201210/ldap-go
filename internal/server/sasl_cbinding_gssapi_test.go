package server

import (
	"crypto/tls"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

func TestOpenLDAP2613SASLCBindingGSSAPI(t *testing.T) {
	referenceTools := requireSASLCBindingOpenLDAP(t)
	tools := requireOpenLDAPGSSAPITestTools(t)
	kdc := startOpenLDAPGSSAPITestKDC(t, tools)
	t.Setenv("KRB5_CONFIG", kdc.configuration)
	t.Setenv("KRB5_KTNAME", kdc.serviceKeytab)
	for _, policy := range []string{"none", "tls-unique", "tls-endpoint"} {
		t.Run(policy, func(t *testing.T) {
			address, configuration := startSASLCBindingConfiguredServer(t, policy, Config{GSSAPIKeytabPath: kdc.serviceKeytab})
			configuration.MaxVersion = tls.VersionTLS12
			global := "sasl-host localhost\nsasl-secprops none\nsasl-cbinding " + policy + "\n" + openLDAPReferenceStartTLSConfiguration(t)
			reference, stop := startOpenLDAPReferenceServerWithConfig(t, referenceTools, nil, global, "", "")
			defer stop()
			for _, target := range []struct {
				name, address string
				tls           *tls.Config
			}{
				{"Go", address, configuration},
				// The disposable reference helper owns its certificate; this test
				// exercises GSSAPI, with transport trust tested separately.
				{"OpenLDAP", strings.TrimPrefix(reference, "ldap://"), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}},
			} {
				for _, secure := range []bool{false, true} {
					name := target.name + "/clear"
					var tlsConfig *tls.Config
					if secure {
						name = target.name + "/TLS"
						tlsConfig = target.tls
					}
					t.Run(name, func(t *testing.T) {
						transport := dialSASLCBinding(t, target.address, tlsConfig, false)
						if !containsString(saslCBindingRawMechanisms(t, transport), "GSSAPI") {
							t.Fatal("GSSAPI not advertised")
						}
						completeSASLCBindingGSSAPI(t, transport, kdc, nil, ldap.LDAPResultSuccess)
					})
				}
			}
		})
	}
	// The explicit Go GSSAPI option is separate from olcSaslCBinding and
	// continues to require a matching endpoint even when the latter is none.
	address, configuration := startSASLCBindingConfiguredServer(t, "none", Config{
		GSSAPIKeytabPath: kdc.serviceKeytab, GSSAPIChannelBinding: saslkrb5.ChannelBindingTLSServerEndpoint,
	})
	for _, mode := range []string{"matching", "missing", "wrong", "clear"} {
		t.Run("explicit endpoint/"+mode, func(t *testing.T) {
			config := configuration
			if mode == "clear" {
				config = nil
			}
			transport := dialSASLCBinding(t, address, config, false)
			var binding []byte
			if mode == "matching" || mode == "wrong" {
				state := transport.connection.(*tls.Conn).ConnectionState()
				var err error
				binding, err = saslkrb5.TLSServerEndpoint(state.PeerCertificates[0])
				if err != nil {
					t.Fatal(err)
				}
				if mode == "wrong" {
					binding[len(binding)-1] ^= 1
				}
			}
			want := uint16(ldap.LDAPResultInvalidCredentials)
			if mode == "matching" {
				want = ldap.LDAPResultSuccess
			}
			completeSASLCBindingGSSAPI(t, transport, kdc, binding, want)
		})
	}
}

func completeSASLCBindingGSSAPI(t *testing.T, transport *syncConsumerTransport, kdc openLDAPGSSAPITestKDC, binding []byte, want uint16) {
	t.Helper()
	initiator, err := saslkrb5.NewInitiatorFromCCache(kdc.credential, kdc.configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	initial, err := initiator.InitialToken("ldap/localhost", binding)
	if err != nil {
		t.Fatal(err)
	}
	first, err := sendSyncConsumerSASLBind(transport, "GSSAPI", initial, true)
	clear(initial)
	if err != nil {
		t.Fatal(err)
	}
	if want != ldap.LDAPResultSuccess {
		if uint16(first.code) != want {
			t.Fatalf("GSSAPI result %+v, want %d", first, want)
		}
		return
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("GSSAPI AP-REQ: %+v", first)
	}
	if err := initiator.AcceptAPRep(first.saslCredentials); err != nil {
		t.Fatal(err)
	}
	offer, err := sendSyncConsumerSASLBind(transport, "GSSAPI", nil, false)
	if err != nil || offer.code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("GSSAPI offer: %+v, %v", offer, err)
	}
	key, err := initiator.ContextKey()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.KeyValue)
	state, err := initiator.SecurityState()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := saslkrb5.Unwrap(offer.saslCredentials, key, true, state.AcceptorSubkey, state.ReceiveSequence)
	if err != nil {
		t.Fatal(err)
	}
	layers, _, err := saslkrb5.DecodeOffer(decoded)
	if err != nil || layers&saslkrb5.SecurityNone == 0 {
		t.Fatalf("GSSAPI layers: %x, %v", decoded, err)
	}
	selection, err := saslkrb5.Wrap([]byte{saslkrb5.SecurityNone, 0, 0, 0}, key, false, state.AcceptorSubkey, state.SendSequence)
	if err != nil {
		t.Fatal(err)
	}
	final, err := sendSyncConsumerSASLBind(transport, "GSSAPI", selection, true)
	if err != nil || final.code != ldap.LDAPResultSuccess {
		t.Fatalf("GSSAPI final: %+v, %v", final, err)
	}
	client := ldap.NewConn(transport.connection, transport.secure)
	client.Start()
	defer client.Close()
	identity, err := client.WhoAmI(nil)
	// Cyrus may strip its local realm; the Go acceptor retains the principal's realm.
	if err != nil || identity == nil ||
		(!strings.EqualFold(identity.AuthzID, "dn:uid=alice,cn="+kdc.realm+",cn=gssapi,cn=auth") &&
			identity.AuthzID != "dn:uid=alice,cn=gssapi,cn=auth") {
		t.Fatalf("GSSAPI identity: %+v, %v", identity, err)
	}
}
