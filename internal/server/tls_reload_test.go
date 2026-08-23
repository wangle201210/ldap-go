package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestGlobalTLSOnlineCertificateReload(t *testing.T) {
	for _, implicitTLS := range []bool{false, true} {
		name := "StartTLS"
		if implicitTLS {
			name = "LDAPS"
		}
		t.Run(name, func(t *testing.T) {
			authority := newGlobalTLSTestAuthority(t)
			first := authority.issue(t, "server-a", true)
			second := authority.issue(t, "server-b", true)
			directory := t.TempDir()
			firstCertificate, firstKey := writeGlobalTLSTestFiles(
				t,
				directory,
				"first",
				first,
			)
			secondCertificate, secondKey := writeGlobalTLSTestFiles(
				t,
				directory,
				"second",
				second,
			)

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			seedGlobalTLSAttributes(t, store, map[string][][]byte{
				"olcTLSCertificateFile":    {[]byte(firstCertificate)},
				"olcTLSCertificateKeyFile": {[]byte(firstKey)},
				"olcTLSProtocolMin":        {[]byte("3.3")},
			})

			address, stop := startServer(t, store, Config{ImplicitTLS: implicitTLS})
			defer stop()

			oldConnection := dialGlobalTLSTestClient(
				t,
				address,
				implicitTLS,
				nil,
			)
			defer oldConnection.Close()
			assertGlobalTLSPeerCommonName(t, oldConnection, "server-a")
			if err := oldConnection.Bind("cn=config", "config-secret"); err != nil {
				t.Fatalf("Bind(cn=config): %v", err)
			}

			rotate := ldap.NewModifyRequest("cn=config", nil)
			rotate.Replace("olcTLSCertificateFile", []string{secondCertificate})
			rotate.Replace("olcTLSCertificateKeyFile", []string{secondKey})
			if err := oldConnection.Modify(rotate); err != nil {
				t.Fatalf("rotate TLS certificate: %v", err)
			}

			assertGlobalTLSConnectionWorks(t, oldConnection)
			newConnection := dialGlobalTLSTestClient(
				t,
				address,
				implicitTLS,
				nil,
			)
			defer newConnection.Close()
			assertGlobalTLSPeerCommonName(t, newConnection, "server-b")

			invalid := ldap.NewModifyRequest("cn=config", nil)
			invalid.Replace("olcTLSCertificateFile", []string{firstCertificate})
			err := oldConnection.Modify(invalid)
			var ldapErr *ldap.Error
			if !errors.As(err, &ldapErr) ||
				ldapErr.ResultCode != ldap.LDAPResultConstraintViolation {
				t.Fatalf("invalid rotation error = %v, want constraintViolation", err)
			}
			if !strings.Contains(
				strings.ToLower(err.Error()),
				strings.ToLower("olcTLSCertificate"),
			) {
				t.Fatalf("invalid rotation diagnostic = %v", err)
			}
			assertGlobalTLSStoredFile(
				t,
				store,
				"olcTLSCertificateFile",
				secondCertificate,
			)

			afterRollback := dialGlobalTLSTestClient(
				t,
				address,
				implicitTLS,
				nil,
			)
			defer afterRollback.Close()
			assertGlobalTLSPeerCommonName(t, afterRollback, "server-b")
		})
	}
}

func TestGlobalTLSVerifyClientDemand(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	serverCertificate := authority.issue(t, "mutual-tls-server", true)
	trustedClient := authority.issue(t, "trusted-client", false)
	untrustedAuthority := newGlobalTLSTestAuthority(t)
	untrustedClient := untrustedAuthority.issue(t, "untrusted-client", false)
	directory := t.TempDir()
	serverCertificateFile, serverKeyFile := writeGlobalTLSTestFiles(
		t,
		directory,
		"server",
		serverCertificate,
	)
	caFile := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: authority.certificateDER,
	}), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(serverCertificateFile)},
		"olcTLSCertificateKeyFile": {[]byte(serverKeyFile)},
		"olcTLSCACertificateFile":  {[]byte(caFile)},
		"olcTLSVerifyClient":       {[]byte("demand")},
	})

	address, stop := startServer(t, store, Config{})
	defer stop()

	for _, test := range []struct {
		name         string
		certificates []tls.Certificate
		wantSuccess  bool
	}{
		{name: "missing certificate"},
		{
			name:         "untrusted certificate",
			certificates: []tls.Certificate{untrustedClient.tlsCertificate},
		},
		{
			name:         "trusted certificate",
			certificates: []tls.Certificate{trustedClient.tlsCertificate},
			wantSuccess:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatalf("DialURL(): %v", err)
			}
			defer client.Close()
			err = client.StartTLS(&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				Certificates:       test.certificates,
			})
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("StartTLS(): %v", err)
				}
				assertGlobalTLSConnectionWorks(t, client)
				return
			}
			if err == nil {
				_, err = client.Search(ldap.NewSearchRequest(
					"",
					ldap.ScopeBaseObject,
					ldap.NeverDerefAliases,
					0,
					0,
					false,
					"(objectClass=*)",
					[]string{"supportedLDAPVersion"},
					nil,
				))
			}
			if err == nil {
				t.Fatal("TLS connection accepted an untrusted client certificate")
			}
		})
	}
}

func TestGlobalTLSCRLMutualTLSTopology(t *testing.T) {
	for _, policy := range []string{"peer", "all"} {
		t.Run(policy, func(t *testing.T) {
			root := newGlobalTLSTestAuthority(t)
			issuer := root
			if policy == "all" {
				issuer = root.issueAuthority(t, "mTLS intermediate CA")
			}
			serverCertificate := root.issue(t, "crl-mtls-server", true)
			trustedClient := issuer.issue(t, "trusted-crl-client", false)
			revokedClient := issuer.issue(t, "revoked-crl-client", false)
			now := time.Now().UTC()
			leafCRL := createGlobalTLSTestCRL(
				t,
				issuer,
				issuer.privateKey,
				1,
				now.Add(-time.Minute),
				now.Add(time.Hour),
				[]x509.RevocationListEntry{{
					SerialNumber:   revokedClient.certificate.SerialNumber,
					RevocationTime: now.Add(-time.Minute),
				}},
			)
			crlData := append([]byte(nil), leafCRL.pem...)
			if policy == "all" {
				issuerCRL := createGlobalTLSTestCRL(
					t,
					root,
					root.privateKey,
					1,
					now.Add(-time.Minute),
					now.Add(time.Hour),
					nil,
				)
				crlData = append(crlData, issuerCRL.pem...)
				trustedClient.tlsCertificate.Certificate = append(
					trustedClient.tlsCertificate.Certificate,
					issuer.certificateDER,
				)
				revokedClient.tlsCertificate.Certificate = append(
					revokedClient.tlsCertificate.Certificate,
					issuer.certificateDER,
				)
			}

			directory := t.TempDir()
			serverCertificateFile, serverKeyFile := writeGlobalTLSTestFiles(
				t,
				directory,
				"server",
				serverCertificate,
			)
			caFile := writeGlobalTLSTestCAFile(t, directory, root)
			crlFile := writeGlobalTLSTestCRLFile(t, directory, "clients", crlData)
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			seedGlobalTLSAttributes(t, store, map[string][][]byte{
				"olcTLSCertificateFile":    {[]byte(serverCertificateFile)},
				"olcTLSCertificateKeyFile": {[]byte(serverKeyFile)},
				"olcTLSCACertificateFile":  {[]byte(caFile)},
				"olcTLSVerifyClient":       {[]byte("demand")},
				"olcTLSCRLCheck":           {[]byte(policy)},
				"olcTLSCRLFile":            {[]byte(crlFile)},
			})

			address, stop := startServer(t, store, Config{})
			defer stop()
			trusted := dialGlobalTLSTestClient(
				t,
				address,
				false,
				[]tls.Certificate{trustedClient.tlsCertificate},
			)
			assertGlobalTLSConnectionWorks(t, trusted)
			trusted.Close()
			assertGlobalTLSClientCertificateRejected(
				t,
				address,
				revokedClient.tlsCertificate,
			)
		})
	}
}

func TestGlobalTLSCRLOnlineRotationAndRollback(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	serverCertificate := authority.issue(t, "crl-rotation-server", true)
	clientCertificate := authority.issue(t, "crl-rotation-client", false)
	now := time.Now().UTC()
	validCRL := createGlobalTLSTestCRL(
		t,
		authority,
		authority.privateKey,
		1,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		nil,
	)
	revokedCRL := createGlobalTLSTestCRL(
		t,
		authority,
		authority.privateKey,
		2,
		now,
		now.Add(time.Hour),
		[]x509.RevocationListEntry{{
			SerialNumber:   clientCertificate.certificate.SerialNumber,
			RevocationTime: now.Add(-time.Minute),
		}},
	)
	directory := t.TempDir()
	serverCertificateFile, serverKeyFile := writeGlobalTLSTestFiles(
		t,
		directory,
		"server",
		serverCertificate,
	)
	caFile := writeGlobalTLSTestCAFile(t, directory, authority)
	validCRLFile := writeGlobalTLSTestCRLFile(t, directory, "valid", validCRL.pem)
	revokedCRLFile := writeGlobalTLSTestCRLFile(t, directory, "revoked", revokedCRL.pem)
	invalidCRLFile := writeGlobalTLSTestCRLFile(t, directory, "invalid", []byte("not a CRL"))

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificateFile":    {[]byte(serverCertificateFile)},
		"olcTLSCertificateKeyFile": {[]byte(serverKeyFile)},
		"olcTLSCACertificateFile":  {[]byte(caFile)},
		"olcTLSVerifyClient":       {[]byte("demand")},
		"olcTLSCRLCheck":           {[]byte("peer")},
		"olcTLSCRLFile":            {[]byte(validCRLFile)},
	})

	address, stop := startServer(t, store, Config{})
	defer stop()
	admin := dialGlobalTLSTestClient(
		t,
		address,
		false,
		[]tls.Certificate{clientCertificate.tlsCertificate},
	)
	defer admin.Close()
	if err := admin.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	rotate := ldap.NewModifyRequest("cn=config", nil)
	rotate.Replace("olcTLSCRLFile", []string{revokedCRLFile})
	if err := admin.Modify(rotate); err != nil {
		t.Fatalf("rotate to revoked CRL: %v", err)
	}
	assertGlobalTLSConnectionWorks(t, admin)
	assertGlobalTLSClientCertificateRejected(
		t,
		address,
		clientCertificate.tlsCertificate,
	)

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcTLSCRLFile", []string{invalidCRLFile})
	err := admin.Modify(invalid)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Fatalf("invalid CRL rotation error = %v, want constraintViolation", err)
	}
	assertGlobalTLSStoredFile(t, store, "olcTLSCRLFile", revokedCRLFile)
	assertGlobalTLSClientCertificateRejected(
		t,
		address,
		clientCertificate.tlsCertificate,
	)

	restore := ldap.NewModifyRequest("cn=config", nil)
	restore.Replace("olcTLSCRLFile", []string{validCRLFile})
	if err := admin.Modify(restore); err != nil {
		t.Fatalf("restore valid CRL: %v", err)
	}
	client := dialGlobalTLSTestClient(
		t,
		address,
		false,
		[]tls.Certificate{clientCertificate.tlsCertificate},
	)
	defer client.Close()
	assertGlobalTLSConnectionWorks(t, client)
}

func TestGlobalTLSOnlineEnableAndDisableStartTLS(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	certificate := authority.issue(t, "dynamic-server", true)
	certificateFile, keyFile := writeGlobalTLSTestFiles(
		t,
		t.TempDir(),
		"dynamic",
		certificate,
	)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(cn=config): %v", err)
	}

	before, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(before): %v", err)
	}
	if err := before.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
		before.Close()
		t.Fatal("StartTLS succeeded before TLS was configured")
	}
	before.Close()

	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Replace("olcTLSCertificateFile", []string{certificateFile})
	enable.Replace("olcTLSCertificateKeyFile", []string{keyFile})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable TLS: %v", err)
	}

	secured := dialGlobalTLSTestClient(t, address, false, nil)
	defer secured.Close()
	assertGlobalTLSPeerCommonName(t, secured, "dynamic-server")

	disable := ldap.NewModifyRequest("cn=config", nil)
	disable.Delete("olcTLSCertificateFile", nil)
	disable.Delete("olcTLSCertificateKeyFile", nil)
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable TLS: %v", err)
	}
	assertGlobalTLSConnectionWorks(t, secured)

	after, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(after): %v", err)
	}
	defer after.Close()
	if err := after.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("StartTLS succeeded after TLS was removed")
	}
}

func writeGlobalTLSTestFiles(
	t *testing.T,
	directory,
	prefix string,
	certificate globalTLSTestCertificate,
) (string, string) {
	t.Helper()
	certificatePath := filepath.Join(directory, prefix+".crt")
	keyPath := filepath.Join(directory, prefix+".key")
	if err := os.WriteFile(certificatePath, certificate.certificatePEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, certificate.privateKeyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certificatePath, keyPath
}

func writeGlobalTLSTestCAFile(
	t *testing.T,
	directory string,
	authority globalTLSTestAuthority,
) string {
	t.Helper()
	path := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: authority.certificateDER,
	}), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

func writeGlobalTLSTestCRLFile(
	t *testing.T,
	directory,
	prefix string,
	data []byte,
) string {
	t.Helper()
	path := filepath.Join(directory, prefix+".crl")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write CRL file: %v", err)
	}
	return path
}

func assertGlobalTLSClientCertificateRejected(
	t *testing.T,
	address string,
	certificate tls.Certificate,
) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	err = client.StartTLS(&tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{certificate},
	})
	if err == nil {
		_, err = client.Search(ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"supportedLDAPVersion"},
			nil,
		))
	}
	if err == nil {
		t.Fatal("TLS connection accepted a revoked client certificate")
	}
}

func dialGlobalTLSTestClient(
	t *testing.T,
	address string,
	implicitTLS bool,
	certificates []tls.Certificate,
) *ldap.Conn {
	t.Helper()
	configuration := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		Certificates:       certificates,
	}
	if implicitTLS {
		client, err := ldap.DialURL(
			"ldaps://"+address,
			ldap.DialWithTLSConfig(configuration),
		)
		if err != nil {
			t.Fatalf("DialURL(LDAPS): %v", err)
		}
		return client
	}
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.StartTLS(configuration); err != nil {
		client.Close()
		t.Fatalf("StartTLS(): %v", err)
	}
	return client
}

func assertGlobalTLSPeerCommonName(
	t *testing.T,
	client *ldap.Conn,
	want string,
) {
	t.Helper()
	state, ok := client.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		t.Fatal("LDAP client has no TLS peer certificate")
	}
	if got := state.PeerCertificates[0].Subject.CommonName; got != want {
		t.Fatalf("TLS peer common name = %q, want %q", got, want)
	}
}

func assertGlobalTLSConnectionWorks(t *testing.T, client *ldap.Conn) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedLDAPVersion"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("TLS root DSE Search() = %#v, %v", result, err)
	}
}

func assertGlobalTLSStoredFile(
	t *testing.T,
	store storage.Store,
	description,
	want string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		values := entry.Values(description)
		if len(values) != 1 || string(values[0]) != want {
			return errors.New("stored TLS file directive does not match active configuration")
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}
