package server

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	openLDAPAutoCAVersion = "2.6.13"
	openLDAPAutoCACommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	autoCAPhaseOneBaseDN  = "dc=example,dc=com"
	autoCAPhaseOneAliceDN = "uid=autoca-alice,ou=people," + autoCAPhaseOneBaseDN
	autoCAPhaseOneBobDN   = "uid=autoca-bob,ou=people," + autoCAPhaseOneBaseDN
	autoCAPhaseOneCarolDN = "uid=autoca-carol,ou=people," + autoCAPhaseOneBaseDN
	autoCAPhaseOneACLDN   = "uid=autoca-acl,ou=people," + autoCAPhaseOneBaseDN
)

var (
	autoCAOIDUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	autoCAOIDOU  = asn1.ObjectIdentifier{2, 5, 4, 11}
	autoCAOIDDC  = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

func TestOpenLDAPReferenceAutoCAPhaseOne(t *testing.T) {
	tools := requireOpenLDAPAutoCAReferenceTools(t)
	assertPinnedOpenLDAPAutoCAReference(t)

	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{strings.Join([]string{
			"autoca",
			"caKeybits 1024",
			"userKeybits 1024",
			"userDays 30",
		}, "\n")},
		"",
		strings.Join([]string{
			"access to attrs=userPrivateKey by self none by * none",
			"access to attrs=userPassword by self write by anonymous auth by * none",
			"access to * by * read",
		}, "\n"),
		autoCAPhaseOneFixtureLDIF(),
	)
	defer stop()

	root := bindOverlayReferenceClient(t, uri, "secret")
	defer root.Close()

	caDER := autoCAPhaseOneSingleRawAttribute(
		t,
		root,
		autoCAPhaseOneBaseDN,
		[]string{"cACertificate;binary"},
		"cACertificate;binary",
	)
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse generated AutoCA certificate: %v", err)
	}
	if !caCertificate.BasicConstraintsValid || !caCertificate.IsCA {
		t.Fatalf(
			"generated AutoCA certificate is not a valid CA: basicConstraints=%t isCA=%t",
			caCertificate.BasicConstraintsValid,
			caCertificate.IsCA,
		)
	}
	if err := caCertificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("verify generated AutoCA self-signed certificate: %v", err)
	}
	assertAutoCASubjectValues(t, caCertificate, map[string][]string{
		autoCAOIDDC.String(): {"com", "example"},
	})

	t.Run("strict request signs DER certificate and PKCS8 key", func(t *testing.T) {
		certificateDER, privateKeyDER := autoCAPhaseOneRequestPair(
			t,
			root,
			autoCAPhaseOneAliceDN,
		)
		certificate, privateKey := assertAutoCAPhaseOnePair(
			t,
			certificateDER,
			privateKeyDER,
			caCertificate,
			map[string][]string{
				autoCAOIDUID.String(): {"autoca-alice"},
				autoCAOIDOU.String():  {"people"},
				autoCAOIDDC.String():  {"com", "example"},
			},
			"alice@example.com",
		)
		if certificate == nil || privateKey == nil {
			t.Fatal("parsed AutoCA pair unexpectedly contains a nil value")
		}

		secondCertificate, secondPrivateKey := autoCAPhaseOneRequestPair(
			t,
			root,
			autoCAPhaseOneAliceDN,
		)
		if !bytes.Equal(secondCertificate, certificateDER) ||
			!bytes.Equal(secondPrivateKey, privateKeyDER) {
			t.Fatal("second strict Search regenerated rather than reused the stored pair")
		}
	})

	t.Run("wrong order does not sign", func(t *testing.T) {
		autoCAPhaseOneAssertNoSigning(
			t,
			root,
			autoCAPhaseOneBobDN,
			[]string{"userPrivateKey;binary", "userCertificate;binary"},
		)
	})

	t.Run("missing attribute does not sign", func(t *testing.T) {
		autoCAPhaseOneAssertNoSigning(
			t,
			root,
			autoCAPhaseOneCarolDN,
			// OpenLDAP 2.6.13 reads the uninitialized terminator after a
			// one-attribute request. Keep the missing-key case deterministic.
			[]string{"userCertificate;binary", "objectClass"},
		)
	})

	t.Run("self signing bypasses write ACL but result ACL hides key", func(t *testing.T) {
		self, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatalf("dial AutoCA ACL fixture: %v", err)
		}
		defer self.Close()
		if err := self.Bind(autoCAPhaseOneACLDN, "acl-secret"); err != nil {
			t.Fatalf("bind AutoCA ACL fixture as self: %v", err)
		}

		result, code := autoCAPhaseOneSearch(
			t,
			self,
			autoCAPhaseOneACLDN,
			[]string{"userCertificate;binary", "userPrivateKey;binary"},
		)
		if code != ldap.LDAPResultSuccess {
			t.Fatalf("self AutoCA Search result code = %d, want success", code)
		}
		entry := autoCAPhaseOneSingleEntry(t, result)
		if got := entry.GetRawAttributeValues("userCertificate;binary"); len(got) != 1 {
			t.Fatalf("self AutoCA Search certificate count = %d, want 1", len(got))
		}
		if got := entry.GetRawAttributeValues("userPrivateKey;binary"); len(got) != 0 {
			t.Fatalf("self AutoCA Search exposed %d ACL-hidden private keys", len(got))
		}

		certificateDER, privateKeyDER := autoCAPhaseOneStoredPair(
			t,
			root,
			autoCAPhaseOneACLDN,
		)
		assertAutoCAPhaseOnePair(
			t,
			certificateDER,
			privateKeyDER,
			caCertificate,
			map[string][]string{
				autoCAOIDUID.String(): {"autoca-acl"},
				autoCAOIDOU.String():  {"people"},
				autoCAOIDDC.String():  {"com", "example"},
			},
			"acl@example.com",
		)
	})
}

func requireOpenLDAPAutoCAReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP slapd overlays: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "slapd "+openLDAPAutoCAVersion) {
		t.Fatalf(
			"selected OpenLDAP binary is not version %s:\n%s",
			openLDAPAutoCAVersion,
			output,
		)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "autoca") {
			return tools
		}
	}
	t.Skipf("selected OpenLDAP slapd was not built with autoca; slapd -VVV output:\n%s", output)
	return openLDAPReferenceTools{}
}

func assertPinnedOpenLDAPAutoCAReference(t *testing.T) {
	t.Helper()
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OpenLDAP reference verified flag = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPAutoCAVersion {
		t.Fatalf("OpenLDAP reference version = %q, want %q", got, openLDAPAutoCAVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPAutoCACommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPAutoCACommit)
	}

	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("pinned OpenLDAP AutoCA fixture requires OPENLDAP_SOURCE")
	}
	revision, err := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP checkout: %v", err)
	}
	if got := strings.TrimSpace(string(revision)); got != openLDAPAutoCACommit {
		t.Fatalf("OpenLDAP source checkout = %q, want %q", got, openLDAPAutoCACommit)
	}

	sources := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: filepath.Join("servers", "slapd", "overlays", "autoca.c"),
			hash: "1334aaa1eea43090d26581706853b0fe410bff3dfe1eaa8f893614a85522e7d7",
			anchors: []string{
				"if ( !be_isroot( op ) &&",
				"a = attr_find( rs->sr_entry->e_attrs, ad_usrPkey );",
				"EVP_PKEY2PKCS8( evpk )",
				"mp->sml_flags = SLAP_MOD_INTERNAL;",
				"op->ors_attrs[0].an_desc == ad_usrCert &&",
				"op->ors_attrs[1].an_desc == ad_usrPkey &&",
				"op->ors_attrs[2].an_name.bv_val == NULL",
				"autoca.on_bi.bi_op_search = autoca_op_search;",
			},
		},
		{
			path: filepath.Join("tests", "scripts", "test066-autoca"),
			hash: "791555f294f5280f767352c1ee00fc73b35358397b090ef445d015893bbdb754",
			anchors: []string{
				"Automatic CA overlay not available, test skipped",
				"objectClass: olcAutoCAConfig",
				"'objectclass=*' 'userCertificate;binary' 'userPrivateKey;binary'",
			},
		},
		{
			path: filepath.Join("doc", "man", "man5", "slapo-autoca.5"),
			hash: "0652d698b7723a9efb68a5e9a62c3207d54ff4789794d5a77e4c65785ba7739a",
			anchors: []string{
				"returning only the userCertificate;binary and",
				"userPrivateKey;binary attributes.",
				"The private key values are encoded in PKCS#8 format.",
			},
		},
	}
	for _, source := range sources {
		path := filepath.Join(sourceRoot, source.path)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", source.path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != source.hash {
			t.Fatalf("pinned OpenLDAP source %s hash = %s, want %s", source.path, got, source.hash)
		}
		for _, anchor := range source.anchors {
			if !bytes.Contains(contents, []byte(anchor)) {
				t.Fatalf("pinned OpenLDAP source %s lacks %q", source.path, anchor)
			}
		}
	}
}

func autoCAPhaseOneFixtureLDIF() string {
	var fixture strings.Builder
	for _, entry := range []struct {
		dn       string
		uid      string
		cn       string
		mail     string
		password string
	}{
		{autoCAPhaseOneAliceDN, "autoca-alice", "AutoCA Alice", "alice@example.com", "alice-secret"},
		{autoCAPhaseOneBobDN, "autoca-bob", "AutoCA Bob", "bob@example.com", "bob-secret"},
		{autoCAPhaseOneCarolDN, "autoca-carol", "AutoCA Carol", "carol@example.com", "carol-secret"},
		{autoCAPhaseOneACLDN, "autoca-acl", "AutoCA ACL", "acl@example.com", "acl-secret"},
	} {
		fmt.Fprintf(
			&fixture,
			"\ndn: %s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: User\nmail: %s\nuserPassword: %s\n",
			entry.dn,
			entry.uid,
			entry.cn,
			entry.mail,
			entry.password,
		)
	}
	return fixture.String()
}

func autoCAPhaseOneRequestPair(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) ([]byte, []byte) {
	t.Helper()
	result, code := autoCAPhaseOneSearch(
		t,
		client,
		dn,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("strict AutoCA Search(%s) result code = %d, want success", dn, code)
	}
	entry := autoCAPhaseOneSingleEntry(t, result)
	certificates := entry.GetRawAttributeValues("userCertificate;binary")
	privateKeys := entry.GetRawAttributeValues("userPrivateKey;binary")
	if len(certificates) != 1 || len(privateKeys) != 1 {
		t.Fatalf(
			"strict AutoCA Search(%s) returned certificates=%d privateKeys=%d, want 1/1",
			dn,
			len(certificates),
			len(privateKeys),
		)
	}
	return bytes.Clone(certificates[0]), bytes.Clone(privateKeys[0])
}

func autoCAPhaseOneStoredPair(
	t *testing.T,
	client *ldap.Conn,
	dn string,
) ([]byte, []byte) {
	t.Helper()
	result, code := autoCAPhaseOneSearch(
		t,
		client,
		dn,
		[]string{"objectClass", "userCertificate;binary", "userPrivateKey;binary"},
	)
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("stored AutoCA pair Search(%s) result code = %d, want success", dn, code)
	}
	entry := autoCAPhaseOneSingleEntry(t, result)
	certificates := entry.GetRawAttributeValues("userCertificate;binary")
	privateKeys := entry.GetRawAttributeValues("userPrivateKey;binary")
	if len(certificates) != 1 || len(privateKeys) != 1 {
		t.Fatalf(
			"stored AutoCA pair Search(%s) returned certificates=%d privateKeys=%d, want 1/1",
			dn,
			len(certificates),
			len(privateKeys),
		)
	}
	return bytes.Clone(certificates[0]), bytes.Clone(privateKeys[0])
}

func autoCAPhaseOneAssertNoSigning(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
) {
	t.Helper()
	result, code := autoCAPhaseOneSearch(t, client, dn, attributes)
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("non-triggering AutoCA Search(%s) result code = %d, want success", dn, code)
	}
	entry := autoCAPhaseOneSingleEntry(t, result)
	if got := entry.GetRawAttributeValues("userCertificate;binary"); len(got) != 0 {
		t.Fatalf("non-triggering AutoCA Search(%s) returned %d certificates", dn, len(got))
	}
	if got := entry.GetRawAttributeValues("userPrivateKey;binary"); len(got) != 0 {
		t.Fatalf("non-triggering AutoCA Search(%s) returned %d private keys", dn, len(got))
	}

	stored, storedCode := autoCAPhaseOneSearch(
		t,
		client,
		dn,
		[]string{"objectClass", "userCertificate;binary", "userPrivateKey;binary"},
	)
	if storedCode != ldap.LDAPResultSuccess {
		t.Fatalf("verify non-triggering AutoCA Search(%s) result code = %d", dn, storedCode)
	}
	storedEntry := autoCAPhaseOneSingleEntry(t, stored)
	if got := storedEntry.GetRawAttributeValues("userCertificate;binary"); len(got) != 0 {
		t.Fatalf("non-triggering AutoCA Search(%s) persisted %d certificates", dn, len(got))
	}
	if got := storedEntry.GetRawAttributeValues("userPrivateKey;binary"); len(got) != 0 {
		t.Fatalf("non-triggering AutoCA Search(%s) persisted %d private keys", dn, len(got))
	}
}

func autoCAPhaseOneSearch(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
) (*ldap.SearchResult, uint16) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	))
	if err == nil {
		return result, ldap.LDAPResultSuccess
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatalf("AutoCA Search(%s) returned non-LDAP error: %v", dn, err)
	}
	return result, ldapError.ResultCode
}

func autoCAPhaseOneSingleEntry(
	t *testing.T,
	result *ldap.SearchResult,
) *ldap.Entry {
	t.Helper()
	if result == nil || len(result.Entries) != 1 {
		count := 0
		if result != nil {
			count = len(result.Entries)
		}
		t.Fatalf("AutoCA base Search entry count = %d, want 1", count)
	}
	return result.Entries[0]
}

func autoCAPhaseOneSingleRawAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
	attribute string,
) []byte {
	t.Helper()
	result, code := autoCAPhaseOneSearch(t, client, dn, attributes)
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("AutoCA Search(%s,%s) result code = %d, want success", dn, attribute, code)
	}
	values := autoCAPhaseOneSingleEntry(t, result).GetRawAttributeValues(attribute)
	if len(values) != 1 {
		t.Fatalf("AutoCA Search(%s,%s) value count = %d, want 1", dn, attribute, len(values))
	}
	return bytes.Clone(values[0])
}

func assertAutoCAPhaseOnePair(
	t *testing.T,
	certificateDER,
	privateKeyDER []byte,
	caCertificate *x509.Certificate,
	wantSubject map[string][]string,
	wantEmail string,
) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse generated AutoCA leaf certificate: %v", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		t.Fatalf("parse generated AutoCA PKCS#8 private key: %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("generated AutoCA PKCS#8 key type %T does not implement crypto.Signer", privateKey)
	}
	assertAutoCASubjectValues(t, certificate, wantSubject)
	if len(certificate.EmailAddresses) != 1 || certificate.EmailAddresses[0] != wantEmail {
		t.Fatalf("generated AutoCA SAN emails = %q, want [%q]", certificate.EmailAddresses, wantEmail)
	}
	if !bytes.Equal(certificate.RawIssuer, caCertificate.RawSubject) {
		t.Fatalf("generated AutoCA issuer does not match the stored CA subject")
	}
	if err := certificate.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("verify generated AutoCA leaf signature: %v", err)
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		t.Fatalf("marshal generated AutoCA certificate public key: %v", err)
	}
	privatePublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal generated AutoCA private-key public half: %v", err)
	}
	if !bytes.Equal(certificatePublic, privatePublic) {
		t.Fatal("generated AutoCA certificate and PKCS#8 private key do not match")
	}
	return certificate, signer
}

func assertAutoCASubjectValues(
	t *testing.T,
	certificate *x509.Certificate,
	want map[string][]string,
) {
	t.Helper()
	got := make(map[string][]string)
	for _, name := range certificate.Subject.Names {
		got[name.Type.String()] = append(got[name.Type.String()], fmt.Sprint(name.Value))
	}
	if len(got) != len(want) {
		t.Fatalf(
			"generated AutoCA subject attributes = %v, want %v (subject %q)",
			got,
			want,
			certificate.Subject.String(),
		)
	}
	for oid, wantValues := range want {
		gotValues := append([]string(nil), got[oid]...)
		if !sameAutoCAStringSet(gotValues, wantValues) {
			t.Fatalf(
				"generated AutoCA subject %s values = %q, want %q (subject %q)",
				oid,
				gotValues,
				wantValues,
				certificate.Subject.String(),
			)
		}
	}
}

func sameAutoCAStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	used := make([]bool, len(right))
	for _, value := range left {
		matched := false
		for index, candidate := range right {
			if !used[index] && value == candidate {
				used[index] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
