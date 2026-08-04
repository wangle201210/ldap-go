package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/smx509"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	autoCATestOverlayDN = "olcOverlay={0}autoca,olcDatabase={1}mdb,cn=config"
	autoCATestBaseDN    = "dc=example,dc=com"
	autoCATestRootDN    = "cn=admin,dc=example,dc=com"
	autoCATestRootPW    = "autoca-admin-secret"
)

type autoCATestPair struct {
	certificateDER []byte
	privateKeyDER  []byte
}

func TestAutoCARuntimeConfiguration(t *testing.T) {
	t.Run("OpenLDAP defaults", func(t *testing.T) {
		configuration, err := loadAutoCARuntimeConfiguration(
			autoCATestOverlayEntry(autoCATestOverlayDN, "", 0),
		)
		if err != nil {
			t.Fatalf("loadAutoCARuntimeConfiguration(): %v", err)
		}
		if configuration.configDNKey == "" || configuration.disabled ||
			configuration.profile != autoCAProfileOpenLDAPRSA ||
			configuration.userClass != "person" || configuration.userClassConfigured ||
			configuration.serverClass != "ipHost" || configuration.serverClassConfigured ||
			configuration.userKeyBits != autoCADefaultKeyBits ||
			configuration.serverKeyBits != autoCADefaultKeyBits ||
			configuration.caKeyBits != autoCADefaultKeyBits ||
			configuration.userDays != autoCADefaultUserDays ||
			configuration.serverDays != autoCADefaultServerDays ||
			configuration.caDays != autoCADefaultCADays || configuration.localDN != nil {
			t.Fatalf("default configuration = %#v", configuration)
		}
	})

	for _, profile := range []string{"rsa", autoCAProfileOpenLDAPRSA} {
		t.Run("explicit "+profile, func(t *testing.T) {
			entry := autoCATestOverlayEntry(autoCATestOverlayDN, profile, 0)
			entry.ReplaceValues("olcAutoCAuserClass", stringValues("inetOrgPerson"))
			entry.ReplaceValues("olcAutoCAserverClass", stringValues("organizationalUnit"))
			entry.ReplaceValues("olcAutoCAuserKeybits", stringValues("1024"))
			entry.ReplaceValues("olcAutoCAserverKeybits", stringValues("1536"))
			entry.ReplaceValues("olcAutoCAKeybits", stringValues("2048"))
			entry.ReplaceValues("olcAutoCAuserDays", stringValues("30"))
			entry.ReplaceValues("olcAutoCAserverDays", stringValues("60"))
			entry.ReplaceValues("olcAutoCADays", stringValues("90"))
			entry.ReplaceValues("olcAutoCAlocalDN", stringValues(
				"cn=ldap,dc=example,dc=com",
			))

			configuration, err := loadAutoCARuntimeConfiguration(entry)
			if err != nil {
				t.Fatalf("loadAutoCARuntimeConfiguration(): %v", err)
			}
			if configuration.profile != autoCAProfileOpenLDAPRSA ||
				configuration.userClass != "inetOrgPerson" ||
				!configuration.userClassConfigured ||
				configuration.serverClass != "organizationalUnit" ||
				!configuration.serverClassConfigured ||
				configuration.userKeyBits != 1024 ||
				configuration.serverKeyBits != 1536 ||
				configuration.caKeyBits != 2048 ||
				configuration.userDays != 30 ||
				configuration.serverDays != 60 ||
				configuration.caDays != 90 || configuration.localDN == nil ||
				configuration.localDN.String() != "cn=ldap,dc=example,dc=com" {
				t.Fatalf("explicit configuration = %#v", configuration)
			}
		})
	}
}

func TestAutoCARuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*directory.Entry)
	}{
		{
			name: "unknown attribute",
			mutate: func(entry *directory.Entry) {
				entry.Attributes = append(entry.Attributes, directory.Attribute{
					Description: "olcAutoCAEntropy",
					Values:      stringValues("external"),
				})
			},
		},
		{
			name: "unknown profile",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCAProfile", stringValues("ed25519"))
			},
		},
		{
			name: "small RSA user key",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCAuserKeybits", stringValues("512"))
			},
		},
		{
			name: "large RSA CA key",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCAKeybits", stringValues("16385"))
			},
		},
		{
			name: "SM2 key size override",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCAProfile", stringValues(autoCAProfileSM2SM3))
				entry.ReplaceValues("olcAutoCAserverKeybits", stringValues("1024"))
			},
		},
		{
			name: "zero user days",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCAuserDays", stringValues("0"))
			},
		},
		{
			name: "negative CA days",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCADays", stringValues("-1"))
			},
		},
		{
			name: "malformed local DN",
			mutate: func(entry *directory.Entry) {
				entry.ReplaceValues("olcAutoCAlocalDN", stringValues("cn=ldap,"))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := autoCATestOverlayEntry(autoCATestOverlayDN, "", 0)
			test.mutate(&entry)
			if configuration, err := loadAutoCARuntimeConfiguration(entry); err == nil {
				t.Fatalf("invalid configuration was accepted: %#v", configuration)
			}
		})
	}
}

func TestAutoCAOnlineConfigurationRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)

	address, stop := startServer(t, store, Config{
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

	valid := autoCATestOverlayEntry(
		autoCATestOverlayDN,
		autoCAProfileOpenLDAPRSA,
		1024,
	)
	if err := configClient.Add(autoCATestAddRequest(valid)); err != nil {
		t.Fatalf("Add(valid autoca): %v", err)
	}
	caBefore := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)

	duplicate := autoCATestOverlayEntry(
		"olcOverlay={1}autoca,olcDatabase={1}mdb,cn=config",
		autoCAProfileOpenLDAPRSA,
		1024,
	)
	if code := autoCATestLDAPCode(configClient.Add(autoCATestAddRequest(duplicate))); code == ldap.LDAPResultSuccess {
		t.Fatal("duplicate AutoCA overlay was accepted")
	}
	if autoCATestStoredEntryExists(t, store, duplicate.DN) {
		t.Fatal("duplicate AutoCA overlay survived configuration rollback")
	}

	invalidDatabase := autoCATestOverlayEntry(
		"olcOverlay={0}autoca,olcDatabase={0}config,cn=config",
		autoCAProfileOpenLDAPRSA,
		1024,
	)
	if code := autoCATestLDAPCode(configClient.Add(autoCATestAddRequest(invalidDatabase))); code == ldap.LDAPResultSuccess {
		t.Fatal("AutoCA overlay on the config database was accepted")
	}
	if autoCATestStoredEntryExists(t, store, invalidDatabase.DN) {
		t.Fatal("invalid-database AutoCA overlay survived configuration rollback")
	}

	outsideSuffix := ldap.NewModifyRequest(autoCATestOverlayDN, nil)
	outsideSuffix.Replace("olcAutoCAlocalDN", []string{"cn=ldap,dc=outside,dc=invalid"})
	if code := autoCATestLDAPCode(configClient.Modify(outsideSuffix)); code == ldap.LDAPResultSuccess {
		t.Fatal("out-of-suffix olcAutoCAlocalDN was accepted")
	}
	storedConfig := readStoredEntry(t, store, autoCATestOverlayDN)
	if values := storedConfig.Values("olcAutoCAlocalDN"); len(values) != 0 {
		t.Fatalf("rolled-back olcAutoCAlocalDN = %q", values)
	}

	caAfter := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertPairEqual(t, caAfter, caBefore)
	root := bindOverlayReferenceClient(t, "ldap://"+address, autoCATestRootPW)
	defer root.Close()
	issued := autoCATestSearchPair(
		t,
		root,
		"uid=alice,ou=people,"+autoCATestBaseDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	autoCATestAssertRSAIssued(t, issued, caBefore)
}

func TestAutoCAStartupCreatesAuthorityAndReusesDERAfterRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	autoCATestSeedEntries(
		t,
		store,
		autoCATestOverlayEntry(autoCATestOverlayDN, "", 0),
	)

	_, stop := startServer(t, store, Config{})
	first := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertRSAAuthority(t, first)
	base := readStoredEntry(t, store, autoCATestBaseDN)
	if !autoCATestContainsString(base.Values("objectClass"), "autoCA") {
		t.Fatalf("startup CA objectClass values = %q", base.Values("objectClass"))
	}
	stop()

	_, stop = startServer(t, store, Config{})
	defer stop()
	second := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertPairEqual(t, second, first)
}

func TestAutoCAStrictAttributeOrderControlsIssuance(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	okDN := "uid=autoca-order-ok,ou=people," + autoCATestBaseDN
	wrongDN := "uid=autoca-order-wrong,ou=people," + autoCATestBaseDN
	missingDN := "uid=autoca-order-missing,ou=people," + autoCATestBaseDN
	autoCATestSeedEntries(
		t,
		store,
		autoCATestOverlayEntry(
			autoCATestOverlayDN,
			autoCAProfileOpenLDAPRSA,
			1024,
		),
		autoCATestUserEntry(okDN, "autoca-order-ok", "order-ok@example.com", "secret"),
		autoCATestUserEntry(wrongDN, "autoca-order-wrong", "order-wrong@example.com", "secret"),
		autoCATestUserEntry(missingDN, "autoca-order-missing", "order-missing@example.com", "secret"),
	)

	address, stop := startServer(t, store, Config{
		RootDN:       autoCATestRootDN,
		RootPassword: []byte(autoCATestRootPW),
	})
	defer stop()
	root := bindOverlayReferenceClient(t, "ldap://"+address, autoCATestRootPW)
	defer root.Close()

	wrong := autoCATestSearchPair(
		t,
		root,
		wrongDN,
		[]string{"userPrivateKey;binary", "userCertificate;binary"},
	)
	autoCATestAssertPairEmpty(t, wrong)
	autoCATestAssertPairEmpty(t, autoCATestStoredOptionalPair(t, store, wrongDN))

	missing := autoCATestSearchPair(
		t,
		root,
		missingDN,
		[]string{"userCertificate;binary"},
	)
	autoCATestAssertPairEmpty(t, missing)
	autoCATestAssertPairEmpty(t, autoCATestStoredOptionalPair(t, store, missingDN))

	issued := autoCATestSearchPair(
		t,
		root,
		okDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	ca := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertRSAIssued(t, issued, ca)
	stored := autoCATestStoredPair(
		t,
		store,
		okDN,
		"userCertificate;binary",
		"userPrivateKey;binary",
	)
	autoCATestAssertPairEqual(t, stored, issued)
	second := autoCATestSearchPair(
		t,
		root,
		okDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	autoCATestAssertPairEqual(t, second, issued)
}

func TestAutoCAConcurrentSearchPersistsOnePair(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	userDN := "uid=autoca-concurrent,ou=people," + autoCATestBaseDN
	autoCATestSeedEntries(
		t,
		store,
		autoCATestOverlayEntry(
			autoCATestOverlayDN,
			autoCAProfileOpenLDAPRSA,
			1024,
		),
		autoCATestUserEntry(
			userDN,
			"autoca-concurrent",
			"concurrent@example.com",
			"secret",
		),
	)
	address, stop := startServer(t, store, Config{
		RootDN:       autoCATestRootDN,
		RootPassword: []byte(autoCATestRootPW),
	})
	defer stop()

	const workers = 16
	type workerResult struct {
		pair autoCATestPair
		err  error
	}
	ready := make(chan struct{}, workers)
	start := make(chan struct{})
	results := make(chan workerResult, workers)
	for range workers {
		go func() {
			client, err := ldap.DialURL("ldap://" + address)
			if err == nil {
				err = client.Bind(autoCATestRootDN, autoCATestRootPW)
			}
			ready <- struct{}{}
			<-start
			if client != nil {
				defer client.Close()
			}
			if err != nil {
				results <- workerResult{err: err}
				return
			}
			pair, searchErr := autoCATestSearchPairFromClient(
				client,
				userDN,
				[]string{"userCertificate;binary", "userPrivateKey;binary"},
			)
			results <- workerResult{pair: pair, err: searchErr}
		}()
	}
	for range workers {
		<-ready
	}
	close(start)

	var first autoCATestPair
	for worker := range workers {
		result := <-results
		if result.err != nil {
			t.Fatalf("worker %d Search: %v", worker, result.err)
		}
		if worker == 0 {
			first = result.pair
			continue
		}
		autoCATestAssertPairEqual(t, result.pair, first)
	}
	stored := autoCATestStoredPair(
		t,
		store,
		userDN,
		"userCertificate;binary",
		"userPrivateKey;binary",
	)
	autoCATestAssertPairEqual(t, stored, first)
	ca := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertRSAIssued(t, stored, ca)
}

func TestAutoCASelfSearchHidesPrivateKeyButPersistsPair(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	autoCATestSetDataACL(t, store,
		"{0}to attrs=userPrivateKey by self none by * none",
		"{1}to attrs=userPassword by self write by anonymous auth by * none",
		"{2}to * by * read",
	)
	userDN := "uid=autoca-self,ou=people," + autoCATestBaseDN
	autoCATestSeedEntries(
		t,
		store,
		autoCATestOverlayEntry(
			autoCATestOverlayDN,
			autoCAProfileOpenLDAPRSA,
			1024,
		),
		autoCATestUserEntry(
			userDN,
			"autoca-self",
			"self@example.com",
			"self-secret",
		),
	)
	address, stop := startServer(t, store, Config{})
	defer stop()

	self := bindOverlayReferenceClientWithDN(
		t,
		"ldap://"+address,
		userDN,
		"self-secret",
	)
	defer self.Close()
	visible := autoCATestSearchPair(
		t,
		self,
		userDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	if len(visible.certificateDER) == 0 || len(visible.privateKeyDER) != 0 {
		t.Fatalf(
			"self-visible pair has certificate=%t privateKey=%t",
			len(visible.certificateDER) != 0,
			len(visible.privateKeyDER) != 0,
		)
	}
	stored := autoCATestStoredPair(
		t,
		store,
		userDN,
		"userCertificate;binary",
		"userPrivateKey;binary",
	)
	if !bytes.Equal(visible.certificateDER, stored.certificateDER) {
		t.Fatal("self-visible certificate differs from the persisted certificate")
	}
	ca := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertRSAIssued(t, stored, ca)
}

func TestAutoCASM2RuntimeIssuanceAndRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	userDN := "uid=autoca-sm2,ou=people," + autoCATestBaseDN
	autoCATestSeedEntries(
		t,
		store,
		autoCATestOverlayEntry(
			autoCATestOverlayDN,
			autoCAProfileSM2SM3,
			0,
		),
		autoCATestUserEntry(
			userDN,
			"autoca-sm2",
			"sm2@example.com",
			"secret",
		),
	)
	config := Config{
		RootDN:       autoCATestRootDN,
		RootPassword: []byte(autoCATestRootPW),
	}
	address, stop := startServer(t, store, config)
	firstCA := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	caCertificate := autoCATestAssertSM2Authority(t, firstCA)
	root := bindOverlayReferenceClient(t, "ldap://"+address, autoCATestRootPW)
	firstUser := autoCATestSearchPair(
		t,
		root,
		userDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	autoCATestAssertSM2Issued(t, firstUser, caCertificate)
	root.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	secondCA := autoCATestStoredPair(
		t,
		store,
		autoCATestBaseDN,
		"cACertificate;binary",
		"cAPrivateKey;binary",
	)
	autoCATestAssertPairEqual(t, secondCA, firstCA)
	secondStoredUser := autoCATestStoredPair(
		t,
		store,
		userDN,
		"userCertificate;binary",
		"userPrivateKey;binary",
	)
	autoCATestAssertPairEqual(t, secondStoredUser, firstUser)
	root = bindOverlayReferenceClient(t, "ldap://"+address, autoCATestRootPW)
	defer root.Close()
	secondUser := autoCATestSearchPair(
		t,
		root,
		userDN,
		[]string{"userCertificate;binary", "userPrivateKey;binary"},
	)
	autoCATestAssertPairEqual(t, secondUser, firstUser)
	autoCATestAssertSM2Issued(t, secondUser, caCertificate)
}

func TestAutoCAServerClassIPHostNumberRSAAndSM2(t *testing.T) {
	profiles := []struct {
		name    string
		profile string
		keyBits int
		address string
	}{
		{name: "RSA", profile: autoCAProfileOpenLDAPRSA, keyBits: 1024, address: "192.0.2.45"},
		{name: "SM2", profile: autoCAProfileSM2SM3, address: "2001:db8::45"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			overlay := autoCATestOverlayEntry(
				autoCATestOverlayDN,
				profile.profile,
				profile.keyBits,
			)
			overlay.ReplaceValues("olcAutoCAserverClass", stringValues("ipHost"))
			serverDN := "ou=autoca-server-" + strings.ToLower(profile.name) + "," + autoCATestBaseDN
			autoCATestSeedEntries(
				t,
				store,
				overlay,
				directory.Entry{
					DN: serverDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("organizationalUnit", "ipHost")},
						{Description: "ou", Values: stringValues("autoca-server-" + strings.ToLower(profile.name))},
						{Description: "cn", Values: stringValues("ldap-" + strings.ToLower(profile.name))},
						{Description: "ipHostNumber", Values: stringValues(profile.address)},
					},
				},
			)
			address, stop := startServer(t, store, Config{
				RootDN:       autoCATestRootDN,
				RootPassword: []byte(autoCATestRootPW),
				Schema:       autoCATestIPHostRegistry(t),
			})
			defer stop()
			root := bindOverlayReferenceClient(t, "ldap://"+address, autoCATestRootPW)
			defer root.Close()
			pair := autoCATestSearchPair(
				t,
				root,
				serverDN,
				[]string{"userCertificate;binary", "userPrivateKey;binary"},
			)
			ca := autoCATestStoredPair(
				t,
				store,
				autoCATestBaseDN,
				"cACertificate;binary",
				"cAPrivateKey;binary",
			)
			switch profile.profile {
			case autoCAProfileSM2SM3:
				caCertificate := autoCATestAssertSM2Authority(t, ca)
				certificate := autoCATestAssertSM2Issued(t, pair, caCertificate)
				if len(certificate.IPAddresses) != 1 ||
					certificate.IPAddresses[0].String() != profile.address {
					t.Fatalf("SM2 server IP SAN = %v, want %s", certificate.IPAddresses, profile.address)
				}
				if !autoCATestContainsSM2Usage(certificate.ExtKeyUsage, smx509.ExtKeyUsageServerAuth) {
					t.Fatalf("SM2 server EKU = %v", certificate.ExtKeyUsage)
				}
			default:
				autoCATestAssertRSAAuthority(t, ca)
				certificate := autoCATestAssertRSAIssued(t, pair, ca)
				if len(certificate.IPAddresses) != 1 ||
					certificate.IPAddresses[0].String() != profile.address {
					t.Fatalf("RSA server IP SAN = %v, want %s", certificate.IPAddresses, profile.address)
				}
				if !autoCATestContainsX509Usage(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
					t.Fatalf("RSA server EKU = %v", certificate.ExtKeyUsage)
				}
			}
			stored := autoCATestStoredPair(
				t,
				store,
				serverDN,
				"userCertificate;binary",
				"userPrivateKey;binary",
			)
			autoCATestAssertPairEqual(t, stored, pair)
		})
	}
}

func autoCATestOverlayEntry(dn, profile string, keyBits int) directory.Entry {
	parsed, _ := directory.ParseDN(dn)
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcAutoCAConfig")},
			{Description: "olcOverlay", Values: stringValues(string(parsed.RDNValues()[0].Value))},
		},
	}
	if profile != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcAutoCAProfile",
			Values:      stringValues(profile),
		})
	}
	if keyBits > 0 {
		value := fmt.Sprint(keyBits)
		for _, attribute := range []string{
			"olcAutoCAuserKeybits",
			"olcAutoCAserverKeybits",
			"olcAutoCAKeybits",
		} {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description: attribute,
				Values:      stringValues(value),
			})
		}
	}
	return entry
}

func autoCATestUserEntry(dn, uid, mail, password string) directory.Entry {
	attributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("inetOrgPerson")},
		{Description: "uid", Values: stringValues(uid)},
		{Description: "cn", Values: stringValues("AutoCA " + uid)},
		{Description: "sn", Values: stringValues("User")},
		{Description: "userPassword", Values: stringValues(password)},
	}
	if mail != "" {
		attributes = append(attributes, directory.Attribute{
			Description: "mail",
			Values:      stringValues(mail),
		})
	}
	return directory.Entry{DN: dn, Attributes: attributes}
}

func autoCATestAddRequest(entry directory.Entry) *ldap.AddRequest {
	request := ldap.NewAddRequest(entry.DN, nil)
	for _, attribute := range entry.Attributes {
		values := make([]string, len(attribute.Values))
		for index := range attribute.Values {
			values[index] = string(attribute.Values[index])
		}
		request.Attribute(attribute.Description, values)
	}
	return request
}

func autoCATestSeedEntries(
	t *testing.T,
	store storage.Store,
	entries ...directory.Entry,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed AutoCA entries: %v", err)
	}
}

func autoCATestSetDataACL(t *testing.T, store storage.Store, values ...string) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure AutoCA ACL: %v", err)
	}
}

func autoCATestSearchPair(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
) autoCATestPair {
	t.Helper()
	pair, err := autoCATestSearchPairFromClient(client, dn, attributes)
	if err != nil {
		t.Fatalf("Search(%s, %v): %v", dn, attributes, err)
	}
	return pair
}

func autoCATestSearchPairFromClient(
	client *ldap.Conn,
	dn string,
	attributes []string,
) (autoCATestPair, error) {
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
	if err != nil {
		return autoCATestPair{}, err
	}
	if len(result.Entries) != 1 {
		return autoCATestPair{}, fmt.Errorf("entry count = %d, want 1", len(result.Entries))
	}
	entry := result.Entries[0]
	certificates := entry.GetRawAttributeValues("userCertificate;binary")
	privateKeys := entry.GetRawAttributeValues("userPrivateKey;binary")
	if len(certificates) > 1 || len(privateKeys) > 1 {
		return autoCATestPair{}, fmt.Errorf(
			"certificate count = %d, private-key count = %d",
			len(certificates),
			len(privateKeys),
		)
	}
	pair := autoCATestPair{}
	if len(certificates) == 1 {
		pair.certificateDER = bytes.Clone(certificates[0])
	}
	if len(privateKeys) == 1 {
		pair.privateKeyDER = bytes.Clone(privateKeys[0])
	}
	return pair, nil
}

func autoCATestStoredPair(
	t *testing.T,
	store storage.Store,
	dn,
	certificateAttribute,
	privateKeyAttribute string,
) autoCATestPair {
	t.Helper()
	entry := readStoredEntry(t, store, dn)
	certificates := entry.Values(certificateAttribute)
	privateKeys := entry.Values(privateKeyAttribute)
	if len(certificates) != 1 || len(privateKeys) != 1 {
		t.Fatalf(
			"stored %s pair counts = certificate:%d privateKey:%d",
			dn,
			len(certificates),
			len(privateKeys),
		)
	}
	return autoCATestPair{
		certificateDER: bytes.Clone(certificates[0]),
		privateKeyDER:  bytes.Clone(privateKeys[0]),
	}
}

func autoCATestStoredOptionalPair(
	t *testing.T,
	store storage.Store,
	dn string,
) autoCATestPair {
	t.Helper()
	entry := readStoredEntry(t, store, dn)
	certificates := entry.Values("userCertificate;binary")
	privateKeys := entry.Values("userPrivateKey;binary")
	if len(certificates) > 1 || len(privateKeys) > 1 {
		t.Fatalf(
			"stored %s pair counts = certificate:%d privateKey:%d",
			dn,
			len(certificates),
			len(privateKeys),
		)
	}
	pair := autoCATestPair{}
	if len(certificates) == 1 {
		pair.certificateDER = bytes.Clone(certificates[0])
	}
	if len(privateKeys) == 1 {
		pair.privateKeyDER = bytes.Clone(privateKeys[0])
	}
	return pair
}

func autoCATestStoredEntryExists(t *testing.T, store storage.Store, rawDN string) bool {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	found := false
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		switch {
		case err == nil:
			found = true
			return nil
		case errors.Is(err, storage.ErrEntryNotFound):
			return nil
		default:
			return err
		}
	}); err != nil {
		t.Fatalf("read %s: %v", rawDN, err)
	}
	return found
}

func autoCATestAssertPairEmpty(t *testing.T, pair autoCATestPair) {
	t.Helper()
	if len(pair.certificateDER) != 0 || len(pair.privateKeyDER) != 0 {
		t.Fatalf(
			"unexpected AutoCA pair: certificate=%d privateKey=%d",
			len(pair.certificateDER),
			len(pair.privateKeyDER),
		)
	}
}

func autoCATestAssertPairEqual(t *testing.T, got, want autoCATestPair) {
	t.Helper()
	if len(got.certificateDER) == 0 || len(got.privateKeyDER) == 0 ||
		!bytes.Equal(got.certificateDER, want.certificateDER) ||
		!bytes.Equal(got.privateKeyDER, want.privateKeyDER) {
		t.Fatalf(
			"AutoCA DER pair differs: got certificate=%d privateKey=%d, want certificate=%d privateKey=%d",
			len(got.certificateDER),
			len(got.privateKeyDER),
			len(want.certificateDER),
			len(want.privateKeyDER),
		)
	}
}

func autoCATestAssertRSAAuthority(t *testing.T, pair autoCATestPair) *x509.Certificate {
	t.Helper()
	certificate, signer := autoCATestParseRSAKeyPair(t, pair)
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		t.Fatalf("RSA authority constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatalf("verify RSA authority self-signature: %v", err)
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		t.Fatalf("RSA authority private key type = %T", signer)
	}
	return certificate
}

func autoCATestAssertRSAIssued(
	t *testing.T,
	pair,
	caPair autoCATestPair,
) *x509.Certificate {
	t.Helper()
	certificate, signer := autoCATestParseRSAKeyPair(t, pair)
	if certificate.IsCA {
		t.Fatal("issued RSA certificate is a CA")
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		t.Fatalf("issued RSA private key type = %T", signer)
	}
	ca := autoCATestAssertRSAAuthority(t, caPair)
	if err := certificate.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("verify issued RSA certificate: %v", err)
	}
	return certificate
}

func autoCATestParseRSAKeyPair(
	t *testing.T,
	pair autoCATestPair,
) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	certificate, err := x509.ParseCertificate(pair.certificateDER)
	if err != nil {
		t.Fatalf("parse RSA certificate: %v", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pair.privateKeyDER)
	if err != nil {
		t.Fatalf("parse RSA PKCS#8 private key: %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("RSA PKCS#8 key type = %T, want crypto.Signer", privateKey)
	}
	autoCATestAssertPublicKeysEqual(t, certificate.PublicKey, signer.Public())
	return certificate, signer
}

func autoCATestAssertPublicKeysEqual(t *testing.T, left, right crypto.PublicKey) {
	t.Helper()
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		t.Fatalf("marshal certificate public key: %v", err)
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		t.Fatalf("marshal private-key public key: %v", err)
	}
	if !bytes.Equal(leftDER, rightDER) {
		t.Fatal("certificate and private-key public keys differ")
	}
}

func autoCATestAssertSM2Authority(
	t *testing.T,
	pair autoCATestPair,
) *smx509.Certificate {
	t.Helper()
	certificate := autoCATestParseSM2KeyPair(t, pair)
	if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("SM2 authority signature algorithm = %v", certificate.SignatureAlgorithm)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		t.Fatalf("SM2 authority constraints = valid:%t isCA:%t", certificate.BasicConstraintsValid, certificate.IsCA)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatalf("verify SM2 authority self-signature: %v", err)
	}
	return certificate
}

func autoCATestAssertSM2Issued(
	t *testing.T,
	pair autoCATestPair,
	ca *smx509.Certificate,
) *smx509.Certificate {
	t.Helper()
	certificate := autoCATestParseSM2KeyPair(t, pair)
	if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("issued SM2 signature algorithm = %v", certificate.SignatureAlgorithm)
	}
	if certificate.IsCA {
		t.Fatal("issued SM2 certificate is a CA")
	}
	if err := certificate.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("verify issued SM2 certificate: %v", err)
	}
	return certificate
}

func autoCATestParseSM2KeyPair(
	t *testing.T,
	pair autoCATestPair,
) *smx509.Certificate {
	t.Helper()
	certificate, err := smx509.ParseCertificate(pair.certificateDER)
	if err != nil {
		t.Fatalf("parse SM2 certificate: %v", err)
	}
	privateKey, err := smx509.ParsePKCS8PrivateKey(pair.privateKeyDER)
	if err != nil {
		t.Fatalf("parse SM2 PKCS#8 private key: %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("SM2 PKCS#8 key type = %T, want crypto.Signer", privateKey)
	}
	equal, err := autoCASM2PublicKeysEqual(certificate.PublicKey, signer.Public())
	if err != nil {
		t.Fatalf("compare SM2 public keys: %v", err)
	}
	if !equal {
		t.Fatal("SM2 certificate and private-key public keys differ")
	}
	return certificate
}

func autoCATestIPHostRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.3.6.1.1.1.1.19 NAME 'ipHostNumber' " +
			"EQUALITY caseIgnoreIA5Match SYNTAX " + schema.SyntaxIA5String + " )",
	); err != nil {
		t.Fatalf("register ipHostNumber: %v", err)
	}
	if err := registry.ParseAndRegisterObjectClass(
		"( 1.3.6.1.1.1.2.6 NAME 'ipHost' SUP top AUXILIARY " +
			"MUST cn MAY ipHostNumber )",
	); err != nil {
		t.Fatalf("register ipHost: %v", err)
	}
	return registry
}

func autoCATestLDAPCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapError.ResultCode
	}
	return ldap.LDAPResultOther
}

func autoCATestContainsString(values [][]byte, want string) bool {
	for _, value := range values {
		if strings.EqualFold(string(value), want) {
			return true
		}
	}
	return false
}

func autoCATestContainsX509Usage(values []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func autoCATestContainsSM2Usage(values []smx509.ExtKeyUsage, want smx509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
