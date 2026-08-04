package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type autoCADifferentialPair struct {
	certificatePresent bool
	privateKeyPresent  bool
	certificateParsed  bool
	privateKeyParsed   bool
	signedByCA         bool
	publicKeyMatches   bool
	subject            []string
	emailSANs          []string
}

type autoCADifferentialNoSigning struct {
	code                 uint16
	responseEntry        bool
	responseCertificates int
	responsePrivateKeys  int
	storedEntry          bool
	storedCertificates   int
	storedPrivateKeys    int
}

type autoCADifferentialSelfACL struct {
	bindCode           uint16
	searchCode         uint16
	certificateVisible bool
	privateKeyHidden   bool
	storedCertificate  bool
	storedPrivateKey   bool
	storedPair         autoCADifferentialPair
}

type autoCADifferentialOutcome struct {
	caCode       uint16
	caPresent    bool
	caParsed     bool
	caIsCA       bool
	caSelfSigned bool
	caSubject    []string
	strictCode   uint16
	strictPair   autoCADifferentialPair
	secondCode   uint16
	secondReused bool
	wrongOrder   autoCADifferentialNoSigning
	missing      autoCADifferentialNoSigning
	selfACL      autoCADifferentialSelfACL
}

func TestOpenLDAPReferenceAutoCADifferential(t *testing.T) {
	tools := requireOpenLDAPAutoCAReferenceTools(t)
	assertPinnedOpenLDAPAutoCAReference(t)

	var reference autoCADifferentialOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		uri, stop := startAutoCADifferentialOpenLDAP(t, tools)
		defer stop()
		root := bindOverlayReferenceClient(t, uri, "secret")
		defer root.Close()

		reference = observeAutoCADifferential(t, uri, root)
		assertAutoCADifferentialReference(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		uri, root, stop := startAutoCADifferentialLDAPGo(t)
		defer stop()
		defer root.Close()

		got := observeAutoCADifferential(t, uri, root)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go AutoCA is not implemented or differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func startAutoCADifferentialOpenLDAP(
	t *testing.T,
	tools openLDAPReferenceTools,
) (string, func()) {
	t.Helper()
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{autoCADifferentialStaticOverlay()},
		"",
		autoCADifferentialACL(),
		autoCAPhaseOneFixtureLDIF(),
	)
}

func autoCADifferentialStaticOverlay() string {
	return "autoca\ncaKeybits 1024\nuserKeybits 1024\nuserDays 30"
}

func autoCADifferentialACL() string {
	return "access to attrs=userPrivateKey by self none by * none\n" +
		"access to attrs=userPassword by self write by anonymous auth by * none\n" +
		"access to * by * read"
}

func startAutoCADifferentialLDAPGo(
	t *testing.T,
) (string, *ldap.Conn, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	entries := []directory.Entry{
		{
			DN: "olcOverlay={0}autoca,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcAutoCAConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}autoca")},
				{Description: "olcAutoCAKeybits", Values: stringValues("1024")},
				{Description: "olcAutoCAuserKeybits", Values: stringValues("1024")},
				{Description: "olcAutoCAuserDays", Values: stringValues("30")},
			},
		},
	}
	for _, fixture := range []struct {
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
		entries = append(entries, directory.Entry{
			DN: fixture.dn,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues(fixture.uid)},
				{Description: "cn", Values: stringValues(fixture.cn)},
				{Description: "sn", Values: stringValues("User")},
				{Description: "mail", Values: stringValues(fixture.mail)},
				{Description: "userPassword", Values: stringValues(fixture.password)},
			},
		})
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dataDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		data, err := writer.Get(dataDN)
		if err != nil {
			return err
		}
		data.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPrivateKey by self none by * none",
			"{1}to attrs=userPassword by self write by anonymous auth by * none",
			"{2}to * by * read",
		))
		if err := writer.Put(data, true); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap-go AutoCA differential fixture: %v", err)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("initialize ldap-go AutoCA differential schema: %v", err)
	}
	if err := schema.RegisterOpenLDAPAutoCASchema(registry); err != nil {
		t.Fatalf("register ldap-go AutoCA differential schema: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
		Schema:       registry,
	})
	uri := "ldap://" + address
	root := bindOverlayReferenceClient(t, uri, "secret")
	return uri, root, stop
}

func observeAutoCADifferential(
	t *testing.T,
	uri string,
	root *ldap.Conn,
) autoCADifferentialOutcome {
	t.Helper()
	var outcome autoCADifferentialOutcome

	caSearch := readAutoCADifferentialSearch(
		t,
		root,
		autoCAPhaseOneBaseDN,
		[]string{"cACertificate;binary"},
	)
	outcome.caCode = caSearch.code
	outcome.caPresent = len(caSearch.certificates) == 1
	var ca *x509.Certificate
	if outcome.caPresent {
		var err error
		ca, err = x509.ParseCertificate(caSearch.certificates[0])
		outcome.caParsed = err == nil
		if ca != nil {
			outcome.caIsCA = ca.BasicConstraintsValid && ca.IsCA
			outcome.caSelfSigned = ca.CheckSignatureFrom(ca) == nil
			outcome.caSubject = autoCADifferentialSubject(ca)
		}
	}

	strict := readAutoCADifferentialSearch(
		t,
		root,
		autoCAPhaseOneAliceDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	outcome.strictCode = strict.code
	outcome.strictPair = autoCADifferentialPairSummary(strict, ca)
	second := readAutoCADifferentialSearch(
		t,
		root,
		autoCAPhaseOneAliceDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	outcome.secondCode = second.code
	outcome.secondReused = autoCADifferentialRawPairEqual(strict, second)

	outcome.wrongOrder = observeAutoCADifferentialNoSigning(
		t,
		root,
		autoCAPhaseOneBobDN,
		[]string{"userPrivateKey;binary", "userCertificate;binary"},
	)
	outcome.missing = observeAutoCADifferentialNoSigning(
		t,
		root,
		autoCAPhaseOneCarolDN,
		[]string{"userCertificate;binary", "objectClass"},
	)
	outcome.selfACL = observeAutoCADifferentialSelfACL(t, uri, root, ca)
	return outcome
}

type autoCADifferentialSearch struct {
	code         uint16
	entryCount   int
	certificates [][]byte
	privateKeys  [][]byte
}

func readAutoCADifferentialSearch(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
) autoCADifferentialSearch {
	t.Helper()
	result, code := autoCAPhaseOneSearch(t, client, dn, attributes)
	observation := autoCADifferentialSearch{code: code}
	if result == nil {
		return observation
	}
	observation.entryCount = len(result.Entries)
	if len(result.Entries) != 1 {
		return observation
	}
	entry := result.Entries[0]
	for _, value := range entry.GetRawAttributeValues("userCertificate;binary") {
		observation.certificates = append(observation.certificates, bytes.Clone(value))
	}
	if len(observation.certificates) == 0 {
		for _, value := range entry.GetRawAttributeValues("cACertificate;binary") {
			observation.certificates = append(observation.certificates, bytes.Clone(value))
		}
	}
	for _, value := range entry.GetRawAttributeValues("userPrivateKey;binary") {
		observation.privateKeys = append(observation.privateKeys, bytes.Clone(value))
	}
	return observation
}

func autoCADifferentialPairSummary(
	search autoCADifferentialSearch,
	ca *x509.Certificate,
) autoCADifferentialPair {
	summary := autoCADifferentialPair{
		certificatePresent: len(search.certificates) == 1,
		privateKeyPresent:  len(search.privateKeys) == 1,
	}
	if !summary.certificatePresent {
		return summary
	}
	certificate, err := x509.ParseCertificate(search.certificates[0])
	if err != nil {
		return summary
	}
	summary.certificateParsed = true
	summary.subject = autoCADifferentialSubject(certificate)
	summary.emailSANs = append([]string(nil), certificate.EmailAddresses...)
	sort.Strings(summary.emailSANs)
	if ca != nil {
		summary.signedByCA = certificate.CheckSignatureFrom(ca) == nil
	}
	if !summary.privateKeyPresent {
		return summary
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(search.privateKeys[0])
	if err != nil {
		return summary
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return summary
	}
	summary.privateKeyParsed = true
	certificatePublic, certificateErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	privatePublic, privateErr := x509.MarshalPKIXPublicKey(signer.Public())
	summary.publicKeyMatches = certificateErr == nil && privateErr == nil &&
		bytes.Equal(certificatePublic, privatePublic)
	return summary
}

func autoCADifferentialSubject(certificate *x509.Certificate) []string {
	if certificate == nil {
		return nil
	}
	values := make([]string, 0, len(certificate.Subject.Names))
	for _, name := range certificate.Subject.Names {
		values = append(values, fmt.Sprintf("%s=%v", name.Type.String(), name.Value))
	}
	sort.Strings(values)
	return values
}

func autoCADifferentialRawPairEqual(
	left,
	right autoCADifferentialSearch,
) bool {
	return len(left.certificates) == 1 && len(right.certificates) == 1 &&
		len(left.privateKeys) == 1 && len(right.privateKeys) == 1 &&
		bytes.Equal(left.certificates[0], right.certificates[0]) &&
		bytes.Equal(left.privateKeys[0], right.privateKeys[0])
}

func observeAutoCADifferentialNoSigning(
	t *testing.T,
	root *ldap.Conn,
	dn string,
	attributes []string,
) autoCADifferentialNoSigning {
	t.Helper()
	response := readAutoCADifferentialSearch(t, root, dn, attributes)
	stored := readAutoCADifferentialSearch(
		t,
		root,
		dn,
		[]string{"objectClass", "userCertificate;binary", "userPrivateKey;binary"},
	)
	return autoCADifferentialNoSigning{
		code:                 response.code,
		responseEntry:        response.entryCount == 1,
		responseCertificates: len(response.certificates),
		responsePrivateKeys:  len(response.privateKeys),
		storedEntry:          stored.entryCount == 1,
		storedCertificates:   len(stored.certificates),
		storedPrivateKeys:    len(stored.privateKeys),
	}
}

func observeAutoCADifferentialSelfACL(
	t *testing.T,
	uri string,
	root *ldap.Conn,
	ca *x509.Certificate,
) autoCADifferentialSelfACL {
	t.Helper()
	observation := autoCADifferentialSelfACL{privateKeyHidden: true}
	self, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial AutoCA differential self client: %v", err)
	}
	defer self.Close()
	observation.bindCode = autoCADifferentialLDAPCode(
		self.Bind(autoCAPhaseOneACLDN, "acl-secret"),
	)
	if observation.bindCode == ldap.LDAPResultSuccess {
		response := readAutoCADifferentialSearch(
			t,
			self,
			autoCAPhaseOneACLDN,
			[]string{"userCertificate;binary", "userPrivateKey;binary"},
		)
		observation.searchCode = response.code
		observation.certificateVisible = len(response.certificates) == 1
		observation.privateKeyHidden = len(response.privateKeys) == 0
	}
	stored := readAutoCADifferentialSearch(
		t,
		root,
		autoCAPhaseOneACLDN,
		[]string{"objectClass", "userCertificate;binary", "userPrivateKey;binary"},
	)
	observation.storedCertificate = len(stored.certificates) == 1
	observation.storedPrivateKey = len(stored.privateKeys) == 1
	observation.storedPair = autoCADifferentialPairSummary(stored, ca)
	return observation
}

func autoCADifferentialLDAPCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapError.ResultCode
	}
	return ldap.LDAPResultOther
}

func assertAutoCADifferentialReference(
	t *testing.T,
	got autoCADifferentialOutcome,
) {
	t.Helper()
	want := autoCADifferentialOutcome{
		caCode:       ldap.LDAPResultSuccess,
		caPresent:    true,
		caParsed:     true,
		caIsCA:       true,
		caSelfSigned: true,
		caSubject: []string{
			"0.9.2342.19200300.100.1.25=com",
			"0.9.2342.19200300.100.1.25=example",
		},
		strictCode: ldap.LDAPResultSuccess,
		strictPair: autoCADifferentialPair{
			certificatePresent: true,
			privateKeyPresent:  true,
			certificateParsed:  true,
			privateKeyParsed:   true,
			signedByCA:         true,
			publicKeyMatches:   true,
			subject: []string{
				"0.9.2342.19200300.100.1.1=autoca-alice",
				"0.9.2342.19200300.100.1.25=com",
				"0.9.2342.19200300.100.1.25=example",
				"2.5.4.11=people",
			},
			emailSANs: []string{"alice@example.com"},
		},
		secondCode:   ldap.LDAPResultSuccess,
		secondReused: true,
		wrongOrder: autoCADifferentialNoSigning{
			code:          ldap.LDAPResultSuccess,
			responseEntry: true,
			storedEntry:   true,
		},
		missing: autoCADifferentialNoSigning{
			code:          ldap.LDAPResultSuccess,
			responseEntry: true,
			storedEntry:   true,
		},
		selfACL: autoCADifferentialSelfACL{
			bindCode:           ldap.LDAPResultSuccess,
			searchCode:         ldap.LDAPResultSuccess,
			certificateVisible: true,
			privateKeyHidden:   true,
			storedCertificate:  true,
			storedPrivateKey:   true,
			storedPair: autoCADifferentialPair{
				certificatePresent: true,
				privateKeyPresent:  true,
				certificateParsed:  true,
				privateKeyParsed:   true,
				signedByCA:         true,
				publicKeyMatches:   true,
				subject: []string{
					"0.9.2342.19200300.100.1.1=autoca-acl",
					"0.9.2342.19200300.100.1.25=com",
					"0.9.2342.19200300.100.1.25=example",
					"2.5.4.11=people",
				},
				emailSANs: []string{"acl@example.com"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP AutoCA differential fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}
