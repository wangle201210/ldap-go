package server

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const autoCALocalTLSTestDN = "cn=localhost," + autoCATestBaseDN

func TestAutoCALocalTLSStartTLSAndLDAPSTopology(t *testing.T) {
	for _, implicitTLS := range []bool{false, true} {
		name := "StartTLS"
		if implicitTLS {
			name = "LDAPS"
		}
		t.Run(name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileOpenLDAPRSA, true)
			address, stop := startServer(t, store, Config{
				ImplicitTLS:  implicitTLS,
				Schema:       registry,
				RootDN:       autoCATestRootDN,
				RootPassword: []byte(autoCATestRootPW),
			})
			defer stop()

			material := readAutoCALocalTLSMaterial(t, store)
			certificate := assertAutoCALocalTLSMaterial(t, store, material)
			client := dialVerifiedAutoCALocalTLS(t, store, address, implicitTLS)
			defer client.Close()
			assertGlobalTLSConnectionWorks(t, client)
			state, ok := client.TLSConnectionState()
			if !ok || len(state.PeerCertificates) != 1 ||
				!bytes.Equal(state.PeerCertificates[0].Raw, certificate.Raw) {
				t.Fatal("listener did not present the persisted AutoCA local certificate")
			}
		})
	}
}

func TestAutoCALocalTLSRestartReusesDERAndNeverLeaksPrivateKey(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileOpenLDAPRSA, true)
	config := Config{
		Schema:       registry,
		RootDN:       autoCATestRootDN,
		RootPassword: []byte(autoCATestRootPW),
	}
	address, stop := startServer(t, store, config)
	first := readAutoCALocalTLSMaterial(t, store)
	assertAutoCALocalTLSMaterial(t, store, first)

	root := bindOverlayReferenceClient(t, "ldap://"+address, autoCATestRootPW)
	assertAutoCALocalTLSPrivateKeyHidden(t, root)
	root.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	second := readAutoCALocalTLSMaterial(t, store)
	if !bytes.Equal(first.CertificateDER, second.CertificateDER) ||
		!bytes.Equal(first.PrivateKeyDER, second.PrivateKeyDER) {
		t.Fatal("AutoCA local TLS DER changed across restart")
	}
	client := dialVerifiedAutoCALocalTLS(t, store, address, false)
	defer client.Close()
	assertAutoCALocalTLSPrivateKeyHidden(t, client)
}

func TestAutoCALocalTLSOnlineEnableAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry := seedAutoCALocalTLSFixture(t, store, "", false)
	address, stop := startServer(t, store, Config{
		Schema:       registry,
		RootDN:       autoCATestRootDN,
		RootPassword: []byte(autoCATestRootPW),
	})
	defer stop()

	configClient := bindOverlayReferenceClientWithDN(
		t,
		"ldap://"+address,
		"cn=config",
		"config-secret",
	)
	defer configClient.Close()
	overlay := autoCALocalTLSOverlay(autoCAProfileOpenLDAPRSA)
	if err := configClient.Add(autoCATestAddRequest(overlay)); err != nil {
		t.Fatalf("enable olcAutoCAlocalDN online: %v", err)
	}
	before := readAutoCALocalTLSMaterial(t, store)
	client := dialVerifiedAutoCALocalTLS(t, store, address, false)
	client.Close()
	rotate := ldap.NewModifyRequest(autoCATestOverlayDN, nil)
	rotate.Replace("olcAutoCAserverDays", []string{"30"})
	if err := configClient.Modify(rotate); err != nil {
		t.Fatalf("rotate AutoCA local TLS policy online: %v", err)
	}
	rotated := readAutoCALocalTLSMaterial(t, store)
	if bytes.Equal(before.CertificateDER, rotated.CertificateDER) ||
		bytes.Equal(before.PrivateKeyDER, rotated.PrivateKeyDER) || rotated.ServerDays != 30 {
		t.Fatal("successful online reload did not rotate AutoCA local TLS material")
	}
	client = dialVerifiedAutoCALocalTLS(t, store, address, false)
	state, ok := client.TLSConnectionState()
	if !ok || len(state.PeerCertificates) != 1 ||
		!bytes.Equal(state.PeerCertificates[0].Raw, rotated.CertificateDER) {
		client.Close()
		t.Fatal("online reload did not publish the rotated AutoCA certificate")
	}
	client.Close()

	invalid := ldap.NewModifyRequest(autoCATestOverlayDN, nil)
	invalid.Replace("olcAutoCAProfile", []string{autoCAProfileSM2SM3})
	invalid.Replace("olcAutoCAKeybits", []string{"256"})
	invalid.Replace("olcAutoCAuserKeybits", []string{"256"})
	invalid.Replace("olcAutoCAserverKeybits", []string{"256"})
	err := configClient.Modify(invalid)
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultConstraintViolation {
		t.Fatalf("SM2 local TLS reload error = %v, want constraintViolation", err)
	}
	after := readAutoCALocalTLSMaterial(t, store)
	if !bytes.Equal(rotated.CertificateDER, after.CertificateDER) ||
		!bytes.Equal(rotated.PrivateKeyDER, after.PrivateKeyDER) {
		t.Fatal("failed online reload changed active AutoCA local TLS material")
	}
	storedOverlay := readStoredEntry(t, store, autoCATestOverlayDN)
	if got := string(storedOverlay.Values("olcAutoCAProfile")[0]); got != autoCAProfileOpenLDAPRSA {
		t.Fatalf("rolled-back AutoCA profile = %q", got)
	}
	client = dialVerifiedAutoCALocalTLS(t, store, address, false)
	client.Close()
}

func TestAutoCALocalTLSExplicitServerMaterialTakesPriorityAndBoundsSM2(t *testing.T) {
	authority := newGlobalTLSTestAuthority(t)
	explicit := authority.issue(t, "explicit-autoca-server", true)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileSM2SM3, true)
	seedGlobalTLSAttributes(t, store, map[string][][]byte{
		"olcTLSCertificate;binary":    {explicit.certificateDER},
		"olcTLSCertificateKey;binary": {explicit.privateKeyDER},
	})
	address, stop := startServer(t, store, Config{Schema: registry})
	defer stop()
	client := dialGlobalTLSTestClient(t, address, false, nil)
	defer client.Close()
	assertGlobalTLSPeerCommonName(t, client, "explicit-autoca-server")
	if _, err := metadataAutoCALocalTLS(store); !errors.Is(err, storage.ErrMetadataNotFound) {
		t.Fatalf("explicit TLS unexpectedly created AutoCA listener metadata: %v", err)
	}

	unsupported := storage.NewMemory()
	t.Cleanup(func() { _ = unsupported.Close() })
	registry = seedAutoCALocalTLSFixture(t, unsupported, autoCAProfileSM2SM3, true)
	if _, err := New(Config{Store: unsupported, Schema: registry}); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("explicit TLS/TLCP material for SM2")) {
		t.Fatalf("SM2 AutoCA local TLS error = %v", err)
	}
}

func TestAutoCALocalTLSConcurrentFirstStartupUsesOnePair(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileOpenLDAPRSA, true)
	const workers = 8
	start := make(chan struct{})
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			instance, err := New(Config{Store: store, Schema: registry})
			if err == nil {
				instance.closeSQLBackends()
			}
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent New(): %v", err)
		}
	}
	material := readAutoCALocalTLSMaterial(t, store)
	assertAutoCALocalTLSMaterial(t, store, material)
}

func TestAutoCALocalTLSMetadataFailureRollsBackAllGeneratedState(t *testing.T) {
	memory := storage.NewMemory()
	t.Cleanup(func() { _ = memory.Close() })
	store := &autoCALocalTLSFailingStore{Store: memory}
	registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileOpenLDAPRSA, true)
	store.fail = true
	if _, err := New(Config{Store: store, Schema: registry}); err == nil {
		t.Fatal("AutoCA local TLS metadata failure was accepted")
	}
	base := readStoredEntry(t, memory, autoCATestBaseDN)
	if len(base.Values("cACertificate;binary")) != 0 || len(base.Values("cAPrivateKey;binary")) != 0 {
		t.Fatal("failed initialization left a generated AutoCA authority")
	}
	local := readStoredEntry(t, memory, autoCALocalTLSTestDN)
	if len(local.Values("userCertificate;binary")) != 0 ||
		len(local.Values("userPrivateKey;binary")) != 0 {
		t.Fatal("failed initialization left partial local TLS attributes")
	}
	if _, err := metadataAutoCALocalTLS(memory); !errors.Is(err, storage.ErrMetadataNotFound) {
		t.Fatalf("failed initialization left metadata: %v", err)
	}
}

func TestAutoCALocalTLSCorruptMetadataFailsClosed(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileOpenLDAPRSA, true)
	instance, err := New(Config{Store: store, Schema: registry})
	if err != nil {
		t.Fatalf("New(initial): %v", err)
	}
	instance.closeSQLBackends()
	before := readStoredEntry(t, store, autoCALocalTLSTestDN)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetMetadata(autoCALocalTLSMetadataKey, []byte("{not-json"))
	}); err != nil {
		t.Fatalf("corrupt AutoCA metadata: %v", err)
	}
	if _, err := New(Config{Store: store, Schema: registry}); err == nil ||
		!strings.Contains(err.Error(), "decode AutoCA local TLS metadata") {
		t.Fatalf("corrupt AutoCA metadata restart error = %v", err)
	}
	after := readStoredEntry(t, store, autoCALocalTLSTestDN)
	if !before.Equal(after) {
		t.Fatal("corrupt metadata restart rotated the LDAP-visible certificate")
	}
}

func TestAutoCALocalTLSExplicitMaterialRetiresMetadata(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	registry := seedAutoCALocalTLSFixture(t, store, autoCAProfileOpenLDAPRSA, true)
	instance, err := New(Config{Store: store, Schema: registry})
	if err != nil {
		t.Fatalf("New(AutoCA): %v", err)
	}
	instance.closeSQLBackends()
	if _, err := metadataAutoCALocalTLS(store); err != nil {
		t.Fatalf("initial AutoCA metadata: %v", err)
	}
	authority := newGlobalTLSTestAuthority(t)
	explicit := authority.issue(t, "explicit-after-autoca", true)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcTLSCertificate;binary", [][]byte{explicit.certificateDER})
		entry.ReplaceValues("olcTLSCertificateKey;binary", [][]byte{explicit.privateKeyDER})
		return writer.PutIn(configurationStoragePartition, entry, true)
	}); err != nil {
		t.Fatalf("configure explicit TLS: %v", err)
	}
	instance, err = New(Config{Store: store, Schema: registry})
	if err != nil {
		t.Fatalf("New(explicit TLS): %v", err)
	}
	instance.closeSQLBackends()
	if _, err := metadataAutoCALocalTLS(store); !errors.Is(err, storage.ErrMetadataNotFound) {
		t.Fatalf("retired AutoCA metadata error = %v, want metadata not found", err)
	}
}

func seedAutoCALocalTLSFixture(
	t *testing.T,
	store storage.Store,
	profile string,
	withOverlay bool,
) *schema.Registry {
	t.Helper()
	seedOnlineConfiguration(t, store)
	entries := []directory.Entry{{
		DN: autoCALocalTLSTestDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("organizationalRole", "ipHost")},
			{Description: "cn", Values: stringValues("localhost")},
			{Description: "ipHostNumber", Values: stringValues("127.0.0.1")},
		},
	}}
	if withOverlay {
		entries = append(entries, autoCALocalTLSOverlay(profile))
	}
	autoCATestSeedEntries(t, store, entries...)
	return autoCATestIPHostRegistry(t)
}

func autoCALocalTLSOverlay(profile string) directory.Entry {
	keyBits := 1024
	if profile == autoCAProfileSM2SM3 {
		keyBits = 0
	}
	overlay := autoCATestOverlayEntry(autoCATestOverlayDN, profile, keyBits)
	overlay.ReplaceValues("olcAutoCAserverClass", stringValues("ipHost"))
	overlay.ReplaceValues("olcAutoCAlocalDN", stringValues(autoCALocalTLSTestDN))
	return overlay
}

func readAutoCALocalTLSMaterial(t *testing.T, store storage.Store) autoCALocalTLSMaterial {
	t.Helper()
	material, err := metadataAutoCALocalTLS(store)
	if err != nil {
		t.Fatalf("read AutoCA local TLS metadata: %v", err)
	}
	return material
}

func metadataAutoCALocalTLS(store storage.Store) (autoCALocalTLSMaterial, error) {
	var material autoCALocalTLSMaterial
	err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		material, err = decodeAutoCALocalTLSMaterial(reader)
		return err
	})
	return material, err
}

func assertAutoCALocalTLSMaterial(
	t *testing.T,
	store storage.Store,
	material autoCALocalTLSMaterial,
) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(material.CertificateDER)
	if err != nil {
		t.Fatalf("parse local TLS certificate: %v", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(material.PrivateKeyDER)
	if err != nil {
		t.Fatalf("parse local TLS PKCS#8 key: %v", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Fatalf("local TLS private key type = %T", key)
	}
	if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("verify local TLS IP SAN: %v", err)
	}
	if err := certificate.VerifyHostname("localhost"); err != nil {
		t.Fatalf("verify local TLS DNS SAN: %v", err)
	}
	if !certificateSupportsServerAuthentication(certificate) ||
		certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatalf("local TLS usages = key %v extended %v", certificate.KeyUsage, certificate.ExtKeyUsage)
	}
	entry := readStoredEntry(t, store, autoCALocalTLSTestDN)
	if got := entry.Values("userCertificate;binary"); len(got) != 1 ||
		!bytes.Equal(got[0], material.CertificateDER) {
		t.Fatalf("localDN certificate values = %d", len(got))
	}
	if got := entry.Values("userPrivateKey;binary"); len(got) != 0 {
		t.Fatalf("localDN exposed %d stored private keys", len(got))
	}
	return certificate
}

func dialVerifiedAutoCALocalTLS(
	t *testing.T,
	store storage.Store,
	address string,
	implicitTLS bool,
) *ldap.Conn {
	t.Helper()
	pool := x509.NewCertPool()
	base := readStoredEntry(t, store, autoCATestBaseDN)
	values := base.Values("cACertificate;binary")
	if len(values) != 1 {
		t.Fatalf("AutoCA authority certificate count = %d", len(values))
	}
	authority, err := x509.ParseCertificate(values[0])
	if err != nil {
		t.Fatalf("parse AutoCA trust anchor: %v", err)
	}
	pool.AddCert(authority)
	return dialAutoCALocalTLSWithPool(t, address, implicitTLS, pool)
}

func dialAutoCALocalTLSWithPool(
	t *testing.T,
	address string,
	implicitTLS bool,
	pool *x509.CertPool,
) *ldap.Conn {
	t.Helper()
	configuration := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	}
	if implicitTLS {
		client, err := ldap.DialURL("ldaps://"+address, ldap.DialWithTLSConfig(configuration))
		if err != nil {
			t.Fatalf("DialURL(LDAPS AutoCA): %v", err)
		}
		return client
	}
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(AutoCA): %v", err)
	}
	if err := client.StartTLS(configuration); err != nil {
		client.Close()
		t.Fatalf("StartTLS(AutoCA): %v", err)
	}
	return client
}

func assertAutoCALocalTLSPrivateKeyHidden(t *testing.T, client *ldap.Conn) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		autoCALocalTLSTestDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search(local TLS private key): entries=%d err=%v", len(result.Entries), err)
	}
	if got := result.Entries[0].GetRawAttributeValues("userPrivateKey;binary"); len(got) != 0 {
		t.Fatalf("LDAP Search exposed %d AutoCA listener private keys", len(got))
	}
}

type autoCALocalTLSFailingStore struct {
	storage.Store
	fail bool
}

func (store *autoCALocalTLSFailingStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return update(autoCALocalTLSFailingWriter{Writer: writer, fail: store.fail})
	})
}

type autoCALocalTLSFailingWriter struct {
	storage.Writer
	fail bool
}

func (writer autoCALocalTLSFailingWriter) SetMetadata(key string, value []byte) error {
	if writer.fail && key == autoCALocalTLSMetadataKey {
		return fmt.Errorf("injected AutoCA local TLS metadata failure")
	}
	return writer.Writer.SetMetadata(key, value)
}
