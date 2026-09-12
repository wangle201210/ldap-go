package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/lloadd"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	vcReferenceCommit        = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	vcReferenceOID           = "1.3.6.1.4.1.4203.666.6.5"
	vcReferenceAuthzRequest  = "2.16.840.1.113730.3.4.16"
	vcReferenceAuthzResponse = "2.16.840.1.113730.3.4.15"
	vcReferenceUser          = "cn=user,dc=example"
	vcReferenceAdmin         = "cn=admin,dc=example"
)

// Opt in with LDAP_GO_OPENLDAP_VC_DOCKER_TESTS=1 and OPENLDAP_SOURCE pointing
// to a Git checkout containing vcReferenceCommit. The C server is an external
// oracle only; run Go with CGO_ENABLED=0. No production VC decoder is reused.
func TestOpenLDAPVerifyCredentialsReference(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_VC_DOCKER_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_VC_DOCKER_TESTS=1 to build the pinned native VC oracle")
	}
	container := vcReferenceContainer(t)
	for _, config := range []vcReferenceOptions{
		{name: "without-authzid"}, {name: "with-authzid", authzid: true},
		{name: "simple-bind-ssf", authzid: true, requireTLS: true},
	} {
		t.Run(config.name, func(t *testing.T) {
			seed := vcReferenceSeed(time.Now())
			address, tlsConfig := vcReferenceServer(t, container, config.authzid, config.requireTLS, seed)
			var native, actual map[string]vcReferenceResult
			t.Run("native", func(t *testing.T) { native = vcReferenceCheckServer(t, address, tlsConfig, config) })
			t.Run("go", func(t *testing.T) {
				goAddress, goTLS := vcReferenceGoServer(t, config, seed)
				actual = vcReferenceCheckServer(t, goAddress, goTLS, config)
			})
			if native == nil || actual == nil {
				return
			} // Permit -run to select one endpoint.
			for _, test := range vcReferenceCases(config.authzid) {
				want, nativeOK := native[test.name]
				have, goOK := actual[test.name]
				if !nativeOK || !goOK {
					t.Errorf("missing result for %s: native=%v Go=%v", test.name, nativeOK, goOK)
					continue
				}
				// Both warnings were checked against the same seeded expiry time;
				// their remaining lifetime can differ as these requests are sequential.
				_, nativePolicy := want.controls[ldap.ControlTypeBeheraPasswordPolicy]
				_, goPolicy := have.controls[ldap.ControlTypeBeheraPasswordPolicy]
				if test.policy && test.policyError < 0 && !config.requireTLS && nativePolicy && goPolicy {
					want.controls[ldap.ControlTypeBeheraPasswordPolicy] = "expiry warning"
					have.controls[ldap.ControlTypeBeheraPasswordPolicy] = "expiry warning"
				}
				if !reflect.DeepEqual(have, want) {
					t.Errorf("%s Go=%+v native=%+v", test.name, have, want)
				}
			}
		})
	}
}

type vcReferenceOptions struct {
	name                string
	authzid, requireTLS bool
}

// A separately seeded Go server can run the same wire requests and assertions.
func vcReferenceCheckServer(t *testing.T, address string, tlsConfig *tls.Config, config vcReferenceOptions) map[string]vcReferenceResult {
	t.Helper()
	results := make(map[string]vcReferenceResult)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(3 * time.Second)
	root, err := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"supportedExtension"}, nil))
	if err != nil || len(root.Entries) != 1 {
		t.Fatalf("RootDSE: %v", err)
	}
	if slices.Contains(root.Entries[0].GetAttributeValues("supportedExtension"), vcReferenceOID) {
		t.Fatal("SLAP_EXOP_HIDE extension was advertised")
	}
	for _, test := range vcReferenceCases(config.authzid) {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if config.requireTLS {
				response := vcReferenceExchange(t, connection, 1, ldapwire.ExtendedRequest{Name: "1.3.6.1.4.1.1466.20037"})
				if vcReferenceCode(t, response) != 0 {
					t.Fatal("StartTLS failed")
				}
				secured := tls.Client(connection, tlsConfig)
				if err := secured.Handshake(); err != nil {
					t.Fatal(err)
				}
				connection = secured
			}
			bind := vcReferenceExchange(t, connection, 2, ldapwire.BindRequest{Version: 3, Name: vcReferenceAdmin, Authentication: ldapwire.Authentication{Simple: []byte("admin-password")}})
			if code := vcReferenceCode(t, bind); code != 0 {
				t.Fatalf("outer Bind=%d", code)
			}
			vcReferenceWhoAmI(t, connection, 3, "dn:"+vcReferenceAdmin)
			value := test.value
			if value == nil {
				value = vcReferenceRequest(test.dn, test.password, test.controls...)
			}
			response := vcReferenceExchange(t, connection, 4, ldapwire.ExtendedRequest{Name: vcReferenceOID, Value: value, HasValue: true})
			got := vcReferenceDecode(t, response)
			results[test.name] = got
			t.Logf("outer=%d inner=%d present=%v diagnostic=%q innerDiagnostic=%q authzid=%q ppolicy=%x", got.outer, got.inner, got.hasInner, got.diagnostic, got.innerDiagnostic, got.controls[vcReferenceAuthzResponse], got.controls[ldap.ControlTypeBeheraPasswordPolicy])
			outer, inner := test.outer, test.inner
			if config.requireTLS && test.bound {
				outer, inner = 13, 13
			}
			if got.outer != outer || got.hasInner != (inner >= 0) || (inner >= 0 && got.inner != inner) {
				t.Errorf("want outer=%d inner=%d", outer, inner)
			}
			if test.authzid && config.authzid && got.inner == 0 {
				want := "dn:" + test.dn
				if test.dn == "" {
					want = ""
				}
				if value, ok := got.controls[vcReferenceAuthzResponse]; !ok || value != want {
					t.Errorf("authzid=%q present=%v, want %q", value, ok, want)
				}
			}
			wantControls := 0
			if test.authzid && config.authzid && got.inner == 0 {
				wantControls++
			}
			if test.policy && !config.requireTLS {
				wantControls++
				value, ok := got.controls[ldap.ControlTypeBeheraPasswordPolicy]
				if !ok {
					t.Error("missing inner ppolicy control")
				} else {
					vcReferencePolicy(t, []byte(value), test.policyError)
				}
			}
			if len(got.controls) != wantControls {
				t.Errorf("response controls=%d, want %d", len(got.controls), wantControls)
			}
			if got.diagnostic != "" {
				t.Errorf("unexpected outer diagnostic %q", got.diagnostic)
			}
			if test.name == "empty-password" && got.innerDiagnostic != "unauthenticated bind (DN with no password) disallowed" {
				t.Error("missing inner empty-password diagnostic")
			}
			if config.requireTLS && test.bound && got.innerDiagnostic != "confidentiality required" {
				t.Error("missing inner SSF diagnostic")
			}
			vcReferenceWhoAmI(t, connection, 5, "dn:"+vcReferenceAdmin)
		})
	}
	return results
}

type vcReferenceCase struct {
	name, dn, password string
	controls           [][]byte
	value              []byte
	outer, inner       int64
	bound, authzid     bool
	policy             bool
	policyError        int64
}

func vcReferenceCases(authzid bool) []vcReferenceCase {
	cases := []vcReferenceCase{
		{name: "correct", dn: vcReferenceUser, password: "user-password", bound: true},
		{name: "wrong", dn: vcReferenceUser, password: "wrong-password", outer: 49, inner: 49, bound: true},
		{name: "missing-entry", dn: "cn=missing,dc=example", password: "user-password", outer: 49, inner: 49, bound: true},
		{name: "outside-suffix", dn: "cn=user,dc=elsewhere", password: "user-password", outer: 49, inner: 49},
		{name: "anonymous"},
		{name: "anonymous-password", password: "user-password", outer: 49, inner: 49},
		{name: "empty-password", dn: vcReferenceUser, outer: 53, inner: 53},
		{name: "invalid-DN", dn: "bad DN", password: "user-password", outer: 2, inner: -1},
		{name: "missing-authentication", value: vcReferenceTLV(0x30, vcReferenceTLV(4, nil)), outer: 2, inner: -1},
		{name: "missing-DN", value: vcReferenceTLV(0x30, vcReferenceTLV(0x80, nil)), outer: 2, inner: -1},
		{name: "simple-cookie", value: vcReferenceTLV(0x30, vcReferenceTLV(0x80, make([]byte, 8)), vcReferenceTLV(4, []byte(vcReferenceUser)), vcReferenceTLV(0x80, []byte("user-password"))), outer: 2, inner: -1},
		{name: "SASL-without-Cyrus", value: vcReferenceTLV(0x30, vcReferenceTLV(4, nil), vcReferenceTLV(0xa3, vcReferenceTLV(4, []byte("PLAIN")), vcReferenceTLV(4, []byte("\x00user\x00user-password")))), outer: 7, inner: 7},
		{name: "unknown-optional", dn: vcReferenceUser, password: "user-password", bound: true, controls: [][]byte{vcReferenceControl("1.2.3.999", false, nil)}},
		{name: "unknown-critical", dn: vcReferenceUser, password: "user-password", controls: [][]byte{vcReferenceControl("1.2.3.999", true, nil)}, outer: 2, inner: -1},
		{name: "manageDSAit-critical", dn: vcReferenceUser, password: "user-password", controls: [][]byte{vcReferenceControl(ldap.ControlTypeManageDsaIT, true, nil)}, outer: 2, inner: -1},
		{name: "manageDSAit-optional", dn: vcReferenceUser, password: "user-password", bound: true, controls: [][]byte{vcReferenceControl(ldap.ControlTypeManageDsaIT, false, nil)}},
		{name: "ppolicy", dn: vcReferenceUser, password: "user-password", bound: true, policy: true, policyError: -1, controls: [][]byte{vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, nil)}},
		{name: "ppolicy-critical", dn: vcReferenceUser, password: "user-password", bound: true, policy: true, policyError: -1, controls: [][]byte{vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, true, nil)}},
		{name: "ppolicy-empty-value", dn: vcReferenceUser, password: "user-password", controls: [][]byte{vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, []byte{})}, outer: 2, inner: -1},
		{name: "ppolicy-duplicate", dn: vcReferenceUser, password: "user-password", bound: true, policy: true, policyError: -1, controls: [][]byte{vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, nil), vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, nil)}},
		{name: "ppolicy-expired", dn: "cn=expired,dc=example", password: "user-password", bound: true, policy: true, policyError: 0, outer: 49, inner: 49, controls: [][]byte{vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, nil)}},
		{name: "ppolicy-reset", dn: "cn=reset,dc=example", password: "user-password", bound: true, policy: true, policyError: 2, controls: [][]byte{vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, nil)}},
		{name: "authzid", dn: vcReferenceUser, password: "user-password", bound: true, authzid: true, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, false, nil)}},
		{name: "authzid-critical", dn: vcReferenceUser, password: "user-password", bound: true, authzid: true, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, true, nil)}},
		{name: "anonymous-authzid", authzid: true, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, false, nil)}},
		{name: "authzid-wrong-password", dn: vcReferenceUser, password: "wrong-password", bound: true, authzid: true, outer: 49, inner: 49, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, false, nil)}},
		{name: "authzid-ppolicy", dn: vcReferenceUser, password: "user-password", bound: true, authzid: true, policy: true, policyError: -1, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, false, nil), vcReferenceControl(ldap.ControlTypeBeheraPasswordPolicy, false, nil)}},
		{name: "authzid-empty-value", dn: vcReferenceUser, password: "user-password", bound: true, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, false, []byte{})}},
		{name: "authzid-duplicate", dn: vcReferenceUser, password: "user-password", bound: true, controls: [][]byte{vcReferenceControl(vcReferenceAuthzRequest, false, nil), vcReferenceControl(vcReferenceAuthzRequest, false, nil)}},
	}
	for i := range cases {
		if (!authzid && cases[i].name == "authzid-critical") || (authzid && (cases[i].name == "authzid-empty-value" || cases[i].name == "authzid-duplicate")) {
			cases[i].outer, cases[i].inner, cases[i].bound = 2, -1, false
		}
	}
	return cases
}

func vcReferencePolicy(t *testing.T, value []byte, wantError int64) {
	t.Helper()
	packet, err := ber.DecodePacketErr(value)
	if err != nil || len(packet.Children) != 1 {
		t.Fatalf("ppolicy response=%x: %v", value, err)
	}
	field := packet.Children[0]
	if wantError < 0 {
		if field.Tag != 0 || len(field.Children) != 1 || field.Children[0].Tag != 0 {
			t.Fatalf("missing expiry warning: %x", value)
		}
		seconds, err := ber.ParseInt64(field.Children[0].Data.Bytes())
		if err != nil || seconds < 3500 || seconds > 3600 {
			t.Fatalf("expiry warning=%d: %v", seconds, err)
		}
	} else {
		code, err := ber.ParseInt64(field.Data.Bytes())
		if field.Tag != 1 || err != nil || code != wantError {
			t.Fatalf("ppolicy error=%x, want %d", value, wantError)
		}
	}
}

func vcReferenceRequest(dn, password string, controls ...[]byte) []byte {
	fields := [][]byte{vcReferenceTLV(4, []byte(dn)), vcReferenceTLV(0x80, []byte(password))}
	if controls != nil {
		fields = append(fields, vcReferenceTLV(0xa2, controls...))
	}
	return vcReferenceTLV(0x30, fields...)
}

func vcReferenceControl(oid string, critical bool, value []byte) []byte {
	fields := [][]byte{vcReferenceTLV(4, []byte(oid))}
	if critical {
		fields = append(fields, []byte{1, 1, 0xff})
	}
	if value != nil {
		fields = append(fields, vcReferenceTLV(4, value))
	}
	return vcReferenceTLV(0x30, fields...)
}

func vcReferenceTLV(tag byte, parts ...[]byte) []byte {
	value := bytes.Join(parts, nil)
	header := []byte{tag}
	switch {
	case len(value) < 128:
		header = append(header, byte(len(value)))
	case len(value) < 256:
		header = append(header, 0x81, byte(len(value)))
	default:
		if len(value) > 65535 {
			panic("VC reference value exceeds fixture bound")
		}
		header = append(header, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(header, value...)
}

func vcReferenceExchange(t *testing.T, conn net.Conn, id int64, request ldapwire.Request) *ber.Packet {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wire, err := ldapwire.EncodeRequestMessage(ldapwire.Message{ID: id, Request: request})
	if err != nil {
		t.Fatal(err)
	}
	if err := ldapwire.Write(conn, wire); err != nil {
		t.Fatal(err)
	}
	frame, err := lloadd.ReadFrame(conn, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := ber.DecodePacketErr(frame.Raw)
	if err != nil || len(packet.Children) != 2 || packet.Children[0].Value != id {
		t.Fatalf("invalid native envelope: %v", err)
	}
	return packet.Children[1]
}

func vcReferenceCode(t *testing.T, packet *ber.Packet) int64 {
	t.Helper()
	if len(packet.Children) < 3 {
		t.Fatal("short LDAPResult")
	}
	code, ok := packet.Children[0].Value.(int64)
	if !ok {
		t.Fatal("invalid resultCode")
	}
	return code
}

func vcReferenceWhoAmI(t *testing.T, conn net.Conn, id int64, want string) {
	t.Helper()
	response := vcReferenceExchange(t, conn, id, ldapwire.ExtendedRequest{Name: "1.3.6.1.4.1.4203.1.11.3"})
	if vcReferenceCode(t, response) != 0 {
		t.Fatal("WhoAmI failed")
	}
	for _, field := range response.Children[3:] {
		if field.Tag == 11 && field.ClassType == ber.ClassContext && field.Data.String() == want {
			return
		}
	}
	t.Fatal("outer connection identity changed")
}

type vcReferenceResult struct {
	outer, inner                int64
	hasInner                    bool
	diagnostic, innerDiagnostic string
	controls                    map[string]string
}

func vcReferenceDecode(t *testing.T, packet *ber.Packet) vcReferenceResult {
	t.Helper()
	result := vcReferenceResult{outer: vcReferenceCode(t, packet), inner: -1, diagnostic: packet.Children[2].Data.String(), controls: map[string]string{}}
	if packet.Tag != ldapwire.ApplicationExtendedResponse {
		t.Fatal("expected ExtendedResponse")
	}
	if packet.Children[1].Data.Len() != 0 {
		t.Fatal("unexpected outer matchedDN")
	}
	for _, field := range packet.Children[3:] {
		if field.ClassType != ber.ClassContext || field.Tag != 11 {
			t.Fatal("unexpected outer response field")
		}
		if result.hasInner {
			t.Fatal("duplicate VC responseValue")
		}
		inner, err := ber.DecodePacketErr(field.Data.Bytes())
		if err != nil || len(inner.Children) < 2 || inner.Children[0].Tag != ber.TagInteger {
			t.Fatalf("invalid VC response: %v", err)
		}
		result.inner, result.hasInner = inner.Children[0].Value.(int64), true
		result.innerDiagnostic = inner.Children[1].Data.String()
		for _, controls := range inner.Children[2:] {
			if controls.ClassType != ber.ClassContext || controls.Tag != 2 {
				t.Fatal("unexpected VC response field")
			}
			for _, control := range controls.Children {
				if len(control.Children) < 1 {
					t.Fatal("empty response control")
				}
				oid := control.Children[0].Data.String()
				if _, exists := result.controls[oid]; exists {
					t.Fatal("duplicate VC response control")
				}
				value := ""
				if last := control.Children[len(control.Children)-1]; len(control.Children) > 1 && last.Tag == 4 {
					value = last.Data.String()
				}
				result.controls[oid] = value
			}
		}
	}
	return result
}

func vcReferenceDocker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Docker %s: %v: %s", args[0], err, output)
	}
	return strings.TrimSpace(string(output))
}

func vcReferenceContainer(t *testing.T) string {
	t.Helper()
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE must be a Git checkout containing the pinned release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	git := func(args ...string) []byte {
		t.Helper()
		output, err := exec.CommandContext(ctx, "git", append([]string{"-C", source}, args...)...).Output()
		if err != nil {
			t.Fatalf("reference Git %s: %v", args[0], err)
		}
		return output
	}
	if string(bytes.TrimSpace(git("rev-parse", vcReferenceCommit+"^{commit}"))) != vcReferenceCommit {
		t.Fatal("incorrect reference commit")
	}
	// Reuse is explicitly limited to a caller-owned disposable oracle at /oracle/src.
	// The default always builds the exact archive in a new container and removes it.
	container := os.Getenv("LDAP_GO_OPENLDAP_VC_DOCKER_CONTAINER")
	if container == "" {
		container = vcReferenceDocker(t, "run", "-d", "--rm", "--init", "-p", "127.0.0.1::1389", "golang:1.26", "sleep", "infinity")
		t.Cleanup(func() { vcReferenceDocker(t, "rm", "-f", container) })
		vcReferenceDocker(t, "exec", container, "mkdir", "-p", "/oracle/src")
		extract := exec.CommandContext(ctx, "docker", "exec", "-i", container, "tar", "-x", "-C", "/oracle/src")
		extract.Stdin = bytes.NewReader(git("archive", vcReferenceCommit))
		if output, err := extract.CombinedOutput(); err != nil {
			t.Fatalf("extract pinned source: %v: %s", err, output)
		}
		t.Log("building pinned OpenLDAP 2.6.13 vc/authzid with OpenSSL, without Cyrus SASL")
		vcReferenceDocker(t, "exec", container, "sh", "-c", `set -eu
trap 'tail -80 /oracle/build.log' EXIT
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/oracle/build.log 2>&1
apt-get install -y -qq libltdl-dev libssl-dev >>/oracle/build.log 2>&1
cd /oracle/src
./configure --enable-mdb --enable-ppolicy --enable-modules --without-cyrus-sasl --with-tls=openssl >>/oracle/build.log 2>&1
make -j2 depend >>/oracle/build.log 2>&1
make -j2 -C libraries >>/oracle/build.log 2>&1
make -j2 -C clients/tools >>/oracle/build.log 2>&1
make -j2 -C servers/slapd >>/oracle/build.log 2>&1
make -C contrib/slapd-modules/vc >>/oracle/build.log 2>&1
make -C contrib/slapd-modules/authzid >>/oracle/build.log 2>&1
trap - EXIT`)
	}
	for _, name := range []string{"contrib/slapd-modules/vc/vc.c", "contrib/slapd-modules/authzid/authzid.c", "servers/slapd/connection.c", "servers/slapd/bind.c", "servers/slapd/controls.c", "servers/slapd/overlays/ppolicy.c"} {
		want := fmt.Sprintf("%x", sha256.Sum256(git("show", vcReferenceCommit+":"+name)))
		actual := vcReferenceDocker(t, "exec", container, "sha256sum", "/oracle/src/"+name)
		if !strings.HasPrefix(actual, want+" ") {
			t.Fatalf("oracle source differs from pinned commit: %s", name)
		}
	}
	if version := vcReferenceDocker(t, "exec", container, "/oracle/src/servers/slapd/slapd", "-VV"); !strings.Contains(version, "slapd 2.6.13") {
		t.Fatal("incorrect oracle version")
	}
	return container
}

func vcReferenceServer(t *testing.T, container string, authzid, requireTLS bool, seed string) (string, *tls.Config) {
	t.Helper()
	directory := t.TempDir()
	certificate, clientTLS := vcReferenceTLS(t)
	var certPEM []byte
	for _, der := range certificate.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := `include /oracle/src/servers/slapd/schema/core.schema
include /oracle/src/servers/slapd/schema/cosine.schema
moduleload /oracle/src/contrib/slapd-modules/vc/vc.la
pidfile /oracle/case/slapd.pid
argsfile /oracle/case/slapd.args
TLSCertificateFile /oracle/case/cert.pem
TLSCertificateKeyFile /oracle/case/key.pem
`
	if authzid {
		config += "moduleload /oracle/src/contrib/slapd-modules/authzid/authzid.la\noverlay authzid\n"
	}
	config += `database mdb
suffix "dc=example"
rootdn "cn=admin,dc=example"
rootpw "admin-password"
directory /oracle/case/db
access to attrs=userPassword by anonymous auth by * none
access to * by * read
overlay ppolicy
ppolicy_default "cn=policy,dc=example"
`
	if requireTLS {
		config += "security simple_bind=128\n"
	}
	for name, data := range map[string][]byte{"slapd.conf": []byte(config), "seed.ldif": []byte(seed), "cert.pem": certPEM, "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vcReferenceDocker(t, "exec", container, "sh", "-c", "rm -rf /oracle/case && mkdir -p /oracle/case/db")
	vcReferenceDocker(t, "cp", directory+"/.", container+":/oracle/case")
	vcReferenceDocker(t, "exec", container, "/oracle/src/servers/slapd/slapd", "-Tadd", "-f", "/oracle/case/slapd.conf", "-l", "/oracle/case/seed.ldif")
	command := exec.Command("docker", "exec", container, "/oracle/src/servers/slapd/slapd", "-f", "/oracle/case/slapd.conf", "-h", "ldap://0.0.0.0:1389/", "-d", "0")
	var log bytes.Buffer
	command.Stdout, command.Stderr = &log, &log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		vcReferenceDocker(t, "exec", container, "sh", "-c", "test ! -f /oracle/case/slapd.pid || kill $(cat /oracle/case/slapd.pid)")
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native VC process did not stop")
		}
	})
	address := vcReferenceDocker(t, "port", container, "1389/tcp")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("native VC exited: %v: %s", err, log.String())
		default:
		}
		conn, err := ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}))
		if err == nil {
			conn.SetTimeout(100 * time.Millisecond)
			err = conn.UnauthenticatedBind("")
			conn.Close()
			if err == nil {
				return address, clientTLS
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("native VC slapd did not start")
	return "", nil
}

func vcReferenceTLS(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

func vcReferenceGoServer(t *testing.T, options vcReferenceOptions, seed string) (string, *tls.Config) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	configuration := `dn: cn=config
objectClass: olcGlobal
cn: config

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModuleLoad: vc.la
`
	if options.authzid {
		configuration += "olcModuleLoad: authzid.la\n"
	}
	configuration += `

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcSuffix: dc=example
olcRootDN: cn=admin,dc=example
olcRootPW: admin-password
olcAccess: {0}to attrs=userPassword by anonymous auth by * none
olcAccess: {1}to * by * read
`
	if options.requireTLS {
		configuration += "olcSecurity: simple_bind=128\n"
	}
	configuration += `
dn: olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: {0}ppolicy
olcPPolicyDefault: cn=policy,dc=example

`
	if options.authzid {
		configuration += `dn: olcOverlay={0}authzid,olcDatabase={-1}frontend,cn=config
objectClass: olcOverlayConfig
olcOverlay: {0}authzid

`
	}
	if _, err := migration.ImportLDIF(t.Context(), store, strings.NewReader(configuration+seed), migration.ImportOptions{SkipSchemaValidation: true}); err != nil {
		t.Fatal(err)
	}
	certificate, tlsConfig := vcReferenceTLS(t)
	address, stop := startServer(t, store, Config{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}})
	t.Cleanup(stop)
	return address, tlsConfig
}

func vcReferenceSeed(now time.Time) string {
	return fmt.Sprintf(`dn: dc=example
objectClass: domain
dc: example

dn: cn=policy,dc=example
objectClass: organizationalRole
objectClass: pwdPolicy
cn: policy
pwdAttribute: userPassword
pwdMaxAge: 3600
pwdExpireWarning: 7200
pwdMustChange: TRUE

dn: cn=user,dc=example
objectClass: person
cn: user
sn: User
userPassword: user-password
pwdChangedTime: %s

dn: cn=expired,dc=example
objectClass: person
cn: expired
sn: Expired
userPassword: user-password
pwdChangedTime: %s

dn: cn=reset,dc=example
objectClass: person
cn: reset
sn: Reset
userPassword: user-password
pwdReset: TRUE

`, now.UTC().Format("20060102150405Z"), now.Add(-2*time.Hour).UTC().Format("20060102150405Z"))
}
