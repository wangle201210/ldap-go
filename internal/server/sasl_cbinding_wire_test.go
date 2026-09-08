package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

func startSASLCBindingServer(t *testing.T, policy string, implicit bool) (string, *tls.Config) {
	t.Helper()
	return startSASLCBindingConfiguredServer(t, policy, Config{ImplicitTLS: implicit})
}

func startSASLCBindingConfiguredServer(t *testing.T, policy string, config Config) (string, *tls.Config) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	setUnsupportedRuntimeConfigurationAttribute(t, store, "cn=config", "olcSaslSecProps", "none")
	setUnsupportedRuntimeConfigurationAttribute(t, store, "cn=config", "olcSaslHost", "localhost")
	setUnsupportedRuntimeConfigurationAttribute(t, store, "cn=config", "olcAuthzRegexp",
		`^uid=([^,]+),cn=scram-[^,]+,cn=auth$ uid=$1,ou=people,dc=example,dc=com`)
	if policy != "" {
		setUnsupportedRuntimeConfigurationAttribute(t, store, "cn=config", saslCBindingAttribute, policy)
	}
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	configuration := &tls.Config{Certificates: []tls.Certificate{certificate.tlsCertificate}, MinVersion: tls.VersionTLS12}
	configuration.SetSessionTicketKeys([][32]byte{{1, 2, 3, 4}})
	config.TLSConfig = configuration
	address, stop := startServer(t, store, config)
	t.Cleanup(stop)
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	return address, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

func dialSASLCBinding(t *testing.T, address string, configuration *tls.Config, implicit bool) *syncConsumerTransport {
	t.Helper()
	raw, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport := newSASLSCRAMPlusTransport(raw)
	t.Cleanup(func() { _ = transport.close() })
	if configuration != nil {
		secureSASLCBinding(t, transport, configuration, implicit)
	}
	return transport
}

func secureSASLCBinding(t *testing.T, transport *syncConsumerTransport, configuration *tls.Config, implicit bool) {
	t.Helper()
	if !implicit {
		transport.messageID++
		encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{ID: transport.messageID,
			Request: ldapwire.ExtendedRequest{Name: syncConsumerStartTLSOID}})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := ber.DecodePacketErr(encoded)
		if err != nil {
			t.Fatal(err)
		}
		result, err := transport.exchangeLDAPResult(transport.messageID, packet, ldap.ApplicationExtendedResponse)
		if err != nil || result.code != ldap.LDAPResultSuccess {
			t.Fatalf("StartTLS: %+v, %v", result, err)
		}
	}
	secured := tls.Client(transport.connection, configuration.Clone())
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	transport.replaceConnection(secured)
	transport.secure = true
}

func saslCBindingClientData(t *testing.T, transport *syncConsumerTransport, policy string, native bool) scram.ChannelBinding {
	t.Helper()
	state := transport.connection.(*tls.Conn).ConnectionState()
	var binding scram.ChannelBinding
	if policy == "tls-unique" {
		binding = scram.NewTLSUniqueBinding(bytes.Clone(state.TLSUnique))
	} else {
		var err error
		binding, err = scram.NewTLSServerEndpointBinding(&state)
		if err != nil {
			t.Fatal(err)
		}
	}
	if native {
		binding.Data = append([]byte(string(binding.Type)+":"), binding.Data...)
		binding.Type = "ldap"
	}
	return binding
}

func saslCBindingRawMechanisms(t *testing.T, transport *syncConsumerTransport) []string {
	t.Helper()
	transport.messageID++
	if err := transport.connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer transport.connection.SetDeadline(time.Time{})
	writeOpenLDAPReferenceRequest(t, transport.connection, transport.messageID,
		rawSyncSearchRequestFor(t, "", ldap.ScopeBaseObject, ldap.NeverDerefAliases, "(objectClass=*)"), nil)
	var result []string
	for {
		packet, err := ber.ReadPacket(transport.connection)
		if err != nil {
			t.Fatal(err)
		}
		op := packet.Children[1]
		if op.Tag == ldap.ApplicationSearchResultDone {
			if rawLDAPResultCode(t, op) != ldap.LDAPResultSuccess {
				t.Fatal("Root DSE failed")
			}
			return result
		}
		if op.Tag != ldap.ApplicationSearchResultEntry {
			t.Fatalf("unexpected response %v", op.Tag)
		}
		for _, attribute := range op.Children[1].Children {
			if strings.EqualFold(attribute.Children[0].Data.String(), "supportedSASLMechanisms") {
				for _, value := range attribute.Children[1].Children {
					result = append(result, value.Data.String())
				}
			}
		}
	}
}

func assertSASLCBindingAdvertised(t *testing.T, transport *syncConsumerTransport, want bool) {
	t.Helper()
	mechanisms := saslCBindingRawMechanisms(t, transport)
	if got := containsString(mechanisms, "SCRAM-SHA-256-PLUS"); got != want {
		t.Fatalf("PLUS advertisement = %v, want %v: %v", got, want, mechanisms)
	}
	if !containsString(mechanisms, "SCRAM-SHA-256") {
		t.Fatalf("ordinary SCRAM disappeared: %v", mechanisms)
	}
}

func completeSASLCBindingSCRAM(t *testing.T, transport *syncConsumerTransport, mechanism string, binding scram.ChannelBinding, want uint16) {
	t.Helper()
	client, err := scram.SHA256.NewClient("alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	conversation := client.NewConversationWithChannelBinding(binding)
	first, err := conversation.Step("")
	if err != nil {
		t.Fatal(err)
	}
	result, err := sendSyncConsumerSASLBind(transport, mechanism, []byte(first), true)
	if err != nil {
		t.Fatal(err)
	}
	if result.code == ldap.LDAPResultSaslBindInProgress {
		final, err := conversation.Step(string(result.saslCredentials))
		if err != nil {
			t.Fatal(err)
		}
		result, err = sendSyncConsumerSASLBind(transport, mechanism, []byte(final), true)
		if err != nil {
			t.Fatal(err)
		}
	}
	if uint16(result.code) != want {
		t.Fatalf("%s bind: %+v, want %d", mechanism, result, want)
	}
	if want == ldap.LDAPResultSuccess {
		if _, err := conversation.Step(string(result.saslCredentials)); err != nil || !conversation.Valid() {
			t.Fatalf("server proof: %v", err)
		}
	}
}

func TestSASLCBindingTransportPolicy(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		for _, policy := range []string{"", "none", "tls-unique", "tls-endpoint"} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				name := policy + "/" + tls.VersionName(version)
				if implicit {
					name += "/ldaps"
				}
				t.Run(name, func(t *testing.T) {
					address, configuration := startSASLCBindingServer(t, policy, implicit)
					configuration.MinVersion, configuration.MaxVersion = version, version
					transport := dialSASLCBinding(t, address, configuration, implicit)
					available := policy == "tls-endpoint" || policy == "tls-unique" && version == tls.VersionTLS12
					assertSASLCBindingAdvertised(t, transport, available)
					if available {
						for _, native := range []bool{false, true} {
							transport := dialSASLCBinding(t, address, configuration, implicit)
							binding := saslCBindingClientData(t, transport, policy, native)
							binding.Data[len(binding.Data)-1] ^= 1
							completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", binding, ldap.LDAPResultInvalidCredentials)
							binding.Data[len(binding.Data)-1] ^= 1
							completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", binding, ldap.LDAPResultSuccess)
						}
						for _, mechanism := range []string{"SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"} {
							result, err := sendSyncConsumerSASLBind(transport, mechanism, []byte("y,,n=alice,r=downgradeNonce"), true)
							if err != nil || result.code != ldap.LDAPResultInvalidCredentials {
								t.Fatalf("downgrade: %+v, %v", result, err)
							}
						}
						completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", scram.ChannelBinding{}, ldap.LDAPResultInvalidCredentials)
						wrongType := saslCBindingClientData(t, transport, "tls-endpoint", false)
						if policy == "tls-endpoint" {
							wrongType.Type = scram.ChannelBindingTLSUnique
						}
						completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", wrongType, ldap.LDAPResultInvalidCredentials)
					} else {
						completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", saslCBindingClientData(t, transport, "tls-endpoint", true), ldap.LDAPResultAuthMethodNotSupported)
						completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256", saslCBindingClientData(t, transport, "tls-endpoint", true), ldap.LDAPResultInvalidCredentials)
					}
					completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256", scram.ChannelBinding{}, ldap.LDAPResultSuccess)
				})
			}
		}
	}
}

func TestSASLCBindingOnlineConnectionLifetime(t *testing.T) {
	address, configuration := startSASLCBindingServer(t, "none", false)
	configuration.MaxVersion = tls.VersionTLS12
	old := dialSASLCBinding(t, address, configuration, false)
	pending := dialSASLCBinding(t, address, nil, false)
	admin := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer admin.Close()
	update := func(value string) {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace(saslCBindingAttribute, []string{value})
		if err := admin.Modify(request); err != nil {
			t.Fatal(err)
		}
	}
	assertSASLCBindingAdvertised(t, old, false)
	update("tls-endpoint")
	assertSASLCBindingAdvertised(t, old, false)
	assertSASLCBindingAdvertised(t, pending, false)
	secureSASLCBinding(t, pending, configuration, false)
	assertSASLCBindingAdvertised(t, pending, true)
	newConnection := dialSASLCBinding(t, address, configuration, false)
	assertSASLCBindingAdvertised(t, newConnection, true)
	binding := saslCBindingClientData(t, newConnection, "tls-endpoint", true)
	client, err := scram.SHA256.NewClient("alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	conversation := client.NewConversationWithChannelBinding(binding)
	first, _ := conversation.Step("")
	challenge, err := sendSyncConsumerSASLBind(newConnection, "SCRAM-SHA-256-PLUS", []byte(first), true)
	if err != nil || challenge.code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("first: %+v, %v", challenge, err)
	}
	update("none")
	final, err := conversation.Step(string(challenge.saslCredentials))
	if err != nil {
		t.Fatal(err)
	}
	result, err := sendSyncConsumerSASLBind(newConnection, "SCRAM-SHA-256-PLUS", []byte(final), true)
	if err != nil || result.code != ldap.LDAPResultSuccess {
		t.Fatalf("in-flight bind: %+v, %v", result, err)
	}
	assertSASLCBindingAdvertised(t, newConnection, true)
	completeSASLCBindingSCRAM(t, newConnection, "SCRAM-SHA-256-PLUS", binding, ldap.LDAPResultAuthMethodNotSupported)
	assertSASLCBindingAdvertised(t, newConnection, false)
	completeSASLCBindingSCRAM(t, pending, "SCRAM-SHA-256-PLUS", saslCBindingClientData(t, pending, "tls-endpoint", true), ldap.LDAPResultSuccess)
	assertSASLCBindingAdvertised(t, dialSASLCBinding(t, address, configuration, false), false)
}

func TestSASLCBindingResumedTLS12(t *testing.T) {
	for _, policy := range []string{"tls-unique", "tls-endpoint"} {
		t.Run(policy, func(t *testing.T) {
			address, configuration := startSASLCBindingServer(t, policy, false)
			configuration.MaxVersion = tls.VersionTLS12
			configuration.ClientSessionCache = tls.NewLRUClientSessionCache(2)
			first := dialSASLCBinding(t, address, configuration, false)
			assertSASLCBindingAdvertised(t, first, true)
			_ = first.close()
			second := dialSASLCBinding(t, address, configuration, false)
			if !second.connection.(*tls.Conn).ConnectionState().DidResume {
				t.Fatal("TLS session did not resume")
			}
			assertSASLCBindingAdvertised(t, second, policy == "tls-endpoint")
			completeSASLCBindingSCRAM(t, second, "SCRAM-SHA-256", scram.ChannelBinding{}, ldap.LDAPResultSuccess)
		})
	}
}
