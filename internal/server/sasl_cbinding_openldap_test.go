package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

func TestOpenLDAP2613SASLCBindingSource(t *testing.T) {
	root := os.Getenv("OPENLDAP_SOURCE")
	if root == "" {
		t.Skip("set OPENLDAP_SOURCE to OpenLDAP d172686d3d270bc961b78f3ff00d7019c8dfb094")
	}
	for _, test := range []struct {
		path, digest string
		anchors      []string
	}{
		{"servers/slapd/bconfig.c", "901a7da3d3b0440ae09799da56682f9083c3b3e4a06117fcd79e02f217e1811b", []string{`ARG_STRING, &sasl_cbinding,`, `OLcfgGlAt:100 NAME 'olcSaslCBinding'`}},
		{"servers/slapd/sasl.c", "076df39a3fc24667862e0931dea5f579cb439859bf4e94cdc6666f7c6d6f06bb", []string{`if ( sasl_cbinding == NULL )`, `if ( i < 0 )`, `conn->c_sasl_cbind = cb;`}},
		{"servers/slapd/connection.c", "3a4ffeb9a5ba486a08b1a964b50b50e2a2a4af86c90a2179632a63d1c0c782ce", []string{`slap_sasl_cbinding( c, ssl );`}},
		{"libraries/libldap/cyrus.c", "a6f168dbd6b5c38e1163251a853d56eddb7a88a19c94651e8ffc0a7aaa893bd0", []string{`strcasecmp(arg, "tls-unique")`, `strcasecmp(arg, "tls-endpoint")`, `cb->name = "ldap";`, `cb->critical = 0;`}},
		{"libraries/libldap/tls_o.c", "1e2e3b0ca403bb8a9a53989ae91f4b9293ebf923aa5f940f9bea75c8a4f37e8d", []string{`SSL_session_reused(s) ^ !is_server`, `SSL_get_peer_finished(s,`, `SSL_get_certificate( s )`}},
	} {
		t.Run(test.path, func(t *testing.T) {
			assertSASLCBindingSource(t, filepath.Join(root, test.path), test.digest, test.anchors)
		})
	}
}

func TestCyrus2128SASLCBindingSource(t *testing.T) {
	root := os.Getenv("CYRUS_SASL_SOURCE")
	if root == "" {
		t.Skip("set CYRUS_SASL_SOURCE to Cyrus SASL 2.1.28")
	}
	assertSASLCBindingSource(t, filepath.Join(root, "plugins/gssapi.c"), "732d311438c588ece922b866aa74d5833734cddedc5a8a1954ef737fa0e6cac0",
		[]string{"gss_accept_sec_context", "GSS_C_NO_CHANNEL_BINDINGS"})
	assertSASLCBindingSource(t, filepath.Join(root, "plugins/scram.c"), "b3b7216a14ea6997f96b39fb959739b4bb32f5937d63826b422a463a6ff891f7",
		[]string{"strcmp(sparams->cbinding->name, text->cbindingname)", "sparams->cbinding->data"})
}

func assertSASLCBindingSource(t *testing.T, path, digest string, anchors []string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != digest {
		t.Fatalf("%s SHA256 = %s, want %s", path, got, digest)
	}
	for _, anchor := range anchors {
		if !bytes.Contains(contents, []byte(anchor)) {
			t.Fatalf("%s lacks %q", path, anchor)
		}
	}
}

func requireSASLCBindingOpenLDAP(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "slapd 2.6.13 (") {
		t.Fatalf("requires OpenLDAP 2.6.13: %s, %v", output, err)
	}
	return tools
}

func TestOpenLDAP2613SASLCBindingConfiguration(t *testing.T) {
	tools := requireSASLCBindingOpenLDAP(t)
	reference := startOpenLDAPDynamicConfigReferralServer(t, tools)
	store := storage.NewMemory()
	defer store.Close()
	seedOnlineConfiguration(t, store)
	_, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	type observation struct {
		codes  []uint16
		values [][]string
	}
	var observations []observation
	for _, uri := range []string{reference, "ldap://" + address} {
		client, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.Bind("cn=config", "config-secret"); err != nil {
			t.Fatal(err)
		}
		observed := observation{values: [][]string{readSASLCBindingConfig(t, client)}}
		for _, test := range []struct {
			operation int
			values    []string
		}{
			{ldap.AddAttribute, []string{"TLS-UNIQUE"}},
			{ldap.AddAttribute, []string{"tls-unique"}},
			{ldap.AddAttribute, []string{"none"}},
			{ldap.ReplaceAttribute, []string{"NoNe"}},
			{ldap.ReplaceAttribute, []string{"tls-ENDPOINT"}},
			{ldap.ReplaceAttribute, []string{"none", "tls-unique"}},
			{ldap.DeleteAttribute, []string{"none"}},
			{ldap.DeleteAttribute, []string{"TLS-ENDPOINT"}},
			{ldap.DeleteAttribute, nil},
			{ldap.ReplaceAttribute, []string{"tls-unique"}},
			{ldap.ReplaceAttribute, nil},
		} {
			request := ldap.NewModifyRequest("cn=config", nil)
			request.Changes = []ldap.Change{{Operation: uint(test.operation), Modification: ldap.PartialAttribute{Type: saslCBindingAttribute, Vals: test.values}}}
			observed.codes = append(observed.codes, ldapOperationResultCode(client.Modify(request)))
			observed.values = append(observed.values, readSASLCBindingConfig(t, client))
		}
		observations = append(observations, observed)
		for _, value := range []string{"unknown", "tls-server-end-point", "tls-exporter", " none", "none "} {
			request := ldap.NewModifyRequest("cn=config", nil)
			request.Replace(saslCBindingAttribute, []string{value})
			want := uint16(ldap.LDAPResultSuccess)
			if uri != reference {
				want = ldap.LDAPResultConstraintViolation
			}
			if got := ldapOperationResultCode(client.Modify(request)); got != want {
				t.Fatalf("%s unsupported %q: %d, want %d", uri, value, got, want)
			}
		}
	}
	if !reflect.DeepEqual(observations[0], observations[1]) {
		t.Fatalf("OpenLDAP: %+v\nldap-go: %+v", observations[0], observations[1])
	}
}

func TestOpenLDAP2613SASLCBindingTLS(t *testing.T) {
	tools := requireSASLCBindingOpenLDAP(t)
	uri := startOpenLDAPDynamicConfigReferralServer(t, tools)
	admin, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "localhost", true)
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "server.pem"), filepath.Join(root, "server.key")
	if err := os.WriteFile(certPath, certificate.certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, certificate.privateKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	request := ldap.NewModifyRequest("cn=config", nil)
	request.Replace("olcTLSCertificateFile", []string{certPath})
	request.Replace("olcTLSCertificateKeyFile", []string{keyPath})
	request.Replace("olcSaslSecProps", []string{"none"})
	request.Replace("olcAuthzRegexp", []string{`^uid=alice,.* uid=alice,dc=example,dc=com`})
	if err := admin.Modify(request); err != nil {
		t.Fatal(err)
	}
	dataAdmin, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer dataAdmin.Close()
	if err := dataAdmin.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	add := ldap.NewAddRequest("uid=alice,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"alice"})
	add.Attribute("cn", []string{"Alice"})
	add.Attribute("sn", []string{"Alice"})
	add.Attribute("userPassword", []string{"secret"})
	if err := dataAdmin.Add(add); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	configuration := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	address := strings.TrimPrefix(uri, "ldap://")
	old := dialSASLCBinding(t, address, configuration, false)
	assertSASLCBindingAdvertised(t, old, false)
	for _, policy := range []string{"tls-endpoint", "tls-unique", "none"} {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace(saslCBindingAttribute, []string{policy})
		if err := admin.Modify(request); err != nil {
			t.Fatal(err)
		}
		transport := dialSASLCBinding(t, address, configuration, false)
		assertSASLCBindingAdvertised(t, transport, policy != "none")
		assertSASLCBindingAdvertised(t, old, false)
		if policy != "none" {
			binding := saslCBindingClientData(t, transport, policy, true)
			binding.Data[len(binding.Data)-1] ^= 1
			completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", binding, ldap.LDAPResultOther)
			binding.Data[len(binding.Data)-1] ^= 1
			reset := ldap.NewModifyRequest("cn=config", nil)
			reset.Replace(saslCBindingAttribute, []string{"none"})
			if err := admin.Modify(reset); err != nil {
				t.Fatal(err)
			}
			assertSASLCBindingAdvertised(t, transport, true)
			completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", binding, ldap.LDAPResultSuccess)
			assertSASLCBindingAdvertised(t, transport, true)
			completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256-PLUS", binding, ldap.LDAPResultOther)
			assertSASLCBindingAdvertised(t, transport, false)
		} else {
			completeSASLCBindingSCRAM(t, transport, "SCRAM-SHA-256", scram.ChannelBinding{}, ldap.LDAPResultSuccess)
		}
	}
}
