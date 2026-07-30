package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientSASLExternalOverMutualTLS(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedExternalDirectory(t, store)
	serverTLS, clientTLS := testMutualTLSConfigs(t)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=external-admin,o=example",
		RootPassword: []byte("unused-bootstrap-secret"),
		TLSConfig:    serverTLS,
		ImplicitTLS:  true,
	})
	defer stop()
	client, err := ldap.DialURL(
		"ldaps://"+address,
		ldap.DialWithTLSConfig(clientTLS),
	)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedSASLMechanisms"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedSASLMechanisms"),
			"EXTERNAL",
		) {
		t.Fatalf("SASL Root DSE = %#v, %v", rootDSE, err)
	}
	beforeBind, err := client.WhoAmI(nil)
	if err != nil || beforeBind.AuthzID != "" {
		t.Fatalf("pre-Bind WhoAmI() = %#v, %v", beforeBind, err)
	}
	if err := client.ExternalBind(); err != nil {
		t.Fatalf("ExternalBind(): %v", err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil {
		t.Fatalf("WhoAmI(): %v", err)
	}
	rawIdentity := strings.TrimPrefix(identity.AuthzID, "dn:")
	gotDN, err := directory.ParseDN(rawIdentity)
	if err != nil {
		t.Fatalf("parse EXTERNAL identity %q: %v", identity.AuthzID, err)
	}
	wantDN, err := directory.ParseDN("cn=external-admin,o=example")
	if err != nil {
		t.Fatalf("parse expected identity: %v", err)
	}
	if !gotDN.Equal(wantDN) {
		t.Fatalf("EXTERNAL identity = %q", identity.AuthzID)
	}

	add := ldap.NewAddRequest("uid=mtls-user,o=example", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"mtls-user"})
	add.Attribute("cn", []string{"Mutual TLS User"})
	add.Attribute("sn", []string{"User"})
	if err := client.Add(add); err != nil {
		t.Fatalf("root Add() after ExternalBind: %v", err)
	}
}

func TestLDAPClientSASLExternalRequiresVerifiedIdentity(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedSASLMechanisms"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 {
		t.Fatalf("Root DSE = %#v, %v", rootDSE, err)
	}
	if values := rootDSE.Entries[0].GetAttributeValues("supportedSASLMechanisms"); len(values) != 0 {
		t.Fatalf("unsecured supportedSASLMechanisms = %q", values)
	}
	assertLDAPResultCode(t, client.ExternalBind(), ldap.LDAPResultInvalidCredentials)
}

func TestLDAPClientSASLExternalRejectsUnverifiedCertificate(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	serverTLS, clientTLS := testMutualTLSConfigs(t)
	serverTLS.ClientAuth = tls.RequestClientCert
	serverTLS.ClientCAs = nil

	address, stop := startServer(t, store, Config{
		TLSConfig:   serverTLS,
		ImplicitTLS: true,
	})
	defer stop()
	client, err := ldap.DialURL(
		"ldaps://"+address,
		ldap.DialWithTLSConfig(clientTLS),
	)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedSASLMechanisms"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 {
		t.Fatalf("Root DSE = %#v, %v", rootDSE, err)
	}
	if values := rootDSE.Entries[0].GetAttributeValues("supportedSASLMechanisms"); len(values) != 0 {
		t.Fatalf("unverified supportedSASLMechanisms = %q", values)
	}
	assertLDAPResultCode(t, client.ExternalBind(), ldap.LDAPResultInvalidCredentials)
}

func seedExternalDirectory(t *testing.T, store storage.Store) {
	t.Helper()

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "o=example",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("organization")},
					{Description: "o", Values: stringValues("example")},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("o=example")},
					{Description: "olcAccess", Values: stringValues("{0}to * by * none")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"o=example"})
	}); err != nil {
		t.Fatalf("seed EXTERNAL directory: %v", err)
	}
}

func testMutualTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()

	now := time.Now()
	caKey := generateECDSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "ldap-go test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER := createCertificate(t, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA): %v", err)
	}

	serverKey := generateECDSAKey(t)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	serverDER := createCertificate(
		t,
		serverTemplate,
		caCertificate,
		&serverKey.PublicKey,
		caKey,
	)
	clientKey := generateECDSAKey(t)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject: pkix.Name{
			CommonName:   "external-admin",
			Organization: []string{"example"},
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER := createCertificate(
		t,
		clientTemplate,
		caCertificate,
		&clientKey.PublicKey,
		caKey,
	)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCertificate)
	return &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{serverDER, caDER},
				PrivateKey:  serverKey,
			}},
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caPool,
			MinVersion: tls.VersionTLS12,
		}, &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{clientDER, caDER},
				PrivateKey:  clientKey,
			}},
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
}

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	return key
}

func createCertificate(
	t *testing.T,
	template, parent *x509.Certificate,
	publicKey any,
	parentKey any,
) []byte {
	t.Helper()

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		parent,
		publicKey,
		parentKey,
	)
	if err != nil {
		t.Fatalf("CreateCertificate(): %v", err)
	}
	return der
}
