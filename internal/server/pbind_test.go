package server

import (
	"context"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadPBindRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcDbURI",
				Values: stringValues(
					"ldap://127.0.0.1:1389 ldaps://ldap.example.test",
				),
			},
			{
				Description: "olcDbStartTLS",
				Values: stringValues(
					"try-start tls_reqcert=demand tls_reqsan=try tls_crlcheck=peer",
				),
			},
			{Description: "olcDbNetworkTimeout", Values: stringValues("2s")},
			{Description: "olcDbQuarantine", Values: stringValues("1s,2 5s,+")},
		},
	}
	configuration, err := loadPBindRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadPBindRuntimeConfiguration(): %v", err)
	}
	if len(configuration.providers) != 2 ||
		configuration.connection.startTLS != syncConsumerStartTLSYes ||
		configuration.connection.tls.requireCert != "demand" ||
		configuration.connection.tls.requireSAN != "try" ||
		configuration.connection.tls.crlCheck != "peer" ||
		configuration.connection.networkTimeout.Seconds() != 2 ||
		configuration.connection.operationTimeout.Seconds() != 2 ||
		len(configuration.quarantine) != 2 || configuration.health == nil {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestPBindQuarantineSchedule(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	configuration := pbindRuntimeConfiguration{
		quarantine: []syncConsumerRetry{
			{interval: time.Second, attempts: 2},
			{interval: 5 * time.Second, attempts: -1},
		},
		health: &pbindQuarantineState{now: func() time.Time { return now }},
	}
	if !configuration.beginPBindAttempt() {
		t.Fatal("initial pbind attempt was quarantined")
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	if configuration.beginPBindAttempt() {
		t.Fatal("pbind retry was allowed before the first interval")
	}

	now = now.Add(time.Second)
	if !configuration.beginPBindAttempt() {
		t.Fatal("first scheduled retry was not allowed")
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	now = now.Add(time.Second)
	if !configuration.beginPBindAttempt() {
		t.Fatal("second scheduled retry was not allowed")
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	if configuration.health.index != 1 {
		t.Fatalf("quarantine index = %d, want 1", configuration.health.index)
	}

	now = now.Add(time.Second)
	if configuration.beginPBindAttempt() {
		t.Fatal("pbind retry ignored the second interval")
	}
	now = now.Add(4 * time.Second)
	if !configuration.beginPBindAttempt() {
		t.Fatal("permanent scheduled retry was not allowed")
	}
	configuration.finishPBindAttempt(ldapwire.ResultInvalidCredentials)
	if configuration.health.quarantined || configuration.health.index != 0 {
		t.Fatalf("successful target contact did not clear quarantine: %#v", configuration.health)
	}
}

func TestPBindQuarantineAllowsOneConcurrentProbe(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	configuration := pbindRuntimeConfiguration{
		quarantine: []syncConsumerRetry{{interval: time.Second, attempts: -1}},
		health:     &pbindQuarantineState{now: func() time.Time { return now }},
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	now = now.Add(time.Second)

	const callers = 32
	var wait sync.WaitGroup
	results := make(chan bool, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- configuration.beginPBindAttempt()
		}()
	}
	wait.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("concurrent quarantine probes allowed = %d, want 1", allowed)
	}
}

func TestLoadPBindRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		attributes []directory.Attribute
	}{
		{name: "missing URI"},
		{
			name: "URI with search base",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("ldap://127.0.0.1/dc=example,dc=com"),
			}},
		},
		{
			name: "unsupported URI",
			attributes: []directory.Attribute{{
				Description: "olcDbURI",
				Values:      stringValues("https://ldap.example.test"),
			}},
		},
		{
			name: "invalid TLS mode",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbStartTLS", Values: stringValues("required")},
			},
		},
		{
			name: "unknown TLS option",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbStartTLS", Values: stringValues("start tls_magic=yes")},
			},
		},
		{
			name: "invalid quarantine",
			attributes: []directory.Attribute{
				{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
				{Description: "olcDbQuarantine", Values: stringValues("invalid")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadPBindRuntimeConfiguration(directory.Entry{
				DN:         "olcOverlay=pbind,olcDatabase=mdb,cn=config",
				Attributes: test.attributes,
			})
			if err == nil {
				t.Fatal("invalid pbind configuration was accepted")
			}
		})
	}
}

func TestLDAPClientPBindUsesRemoteCredentialsAndFailover(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedDirectory(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{})
	providerRunning := true
	t.Cleanup(func() {
		if providerRunning {
			stopProvider()
		}
	})

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedDirectory(t, consumerStore)
	seedPBindConfiguration(
		t,
		consumerStore,
		"ldap://127.0.0.1:1 ldap://"+providerAddress,
		"local-only",
	)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
	defer stopConsumer()

	client, err := ldap.DialURL("ldap://" + consumerAddress)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	userDN := "uid=alice,ou=people,dc=example,dc=com"
	if err := client.Bind(userDN, "secret"); err != nil {
		t.Fatalf("remote credential Bind(): %v", err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:"+userDN {
		t.Fatalf("WhoAmI() = %#v, %v", identity, err)
	}

	if err := client.Bind(userDN, "local-only"); err == nil {
		t.Fatal("pbind accepted the local-only password")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}

	stopProvider()
	providerRunning = false
	if err := client.Bind(userDN, "secret"); err == nil {
		t.Fatal("pbind succeeded after every provider stopped")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
	}
}

func TestLDAPClientPBindStartTLSModes(t *testing.T) {
	t.Run("critical with trusted peer", func(t *testing.T) {
		providerTLS := testServerTLSConfig(t)
		providerStore := storage.NewMemory()
		t.Cleanup(func() { _ = providerStore.Close() })
		seedDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(
			t,
			providerStore,
			Config{TLSConfig: providerTLS},
		)
		defer stopProvider()

		certificatePath := writePBindTestCertificate(
			t,
			providerTLS.Certificates[0].Certificate[0],
		)
		_, port, err := net.SplitHostPort(providerAddress)
		if err != nil {
			t.Fatalf("SplitHostPort(): %v", err)
		}
		consumerStore := storage.NewMemory()
		t.Cleanup(func() { _ = consumerStore.Close() })
		seedDirectory(t, consumerStore)
		seedPBindConfiguration(
			t,
			consumerStore,
			"ldap://localhost:"+port,
			"local-only",
		)
		setPBindStartTLS(
			t,
			consumerStore,
			"start tls_cacert="+certificatePath+
				" tls_reqcert=demand tls_reqsan=demand",
		)
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
		defer stopConsumer()

		client, err := ldap.DialURL("ldap://" + consumerAddress)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		if err := client.Bind(
			"uid=alice,ou=people,dc=example,dc=com",
			"secret",
		); err != nil {
			t.Fatalf("StartTLS pbind: %v", err)
		}
	})

	t.Run("critical rejects untrusted peer", func(t *testing.T) {
		providerTLS := testServerTLSConfig(t)
		providerStore := storage.NewMemory()
		t.Cleanup(func() { _ = providerStore.Close() })
		seedDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(
			t,
			providerStore,
			Config{TLSConfig: providerTLS},
		)
		defer stopProvider()

		untrustedTLS := testServerTLSConfig(t)
		certificatePath := writePBindTestCertificate(
			t,
			untrustedTLS.Certificates[0].Certificate[0],
		)
		_, port, err := net.SplitHostPort(providerAddress)
		if err != nil {
			t.Fatalf("SplitHostPort(): %v", err)
		}
		consumerStore := storage.NewMemory()
		t.Cleanup(func() { _ = consumerStore.Close() })
		seedDirectory(t, consumerStore)
		seedPBindConfiguration(
			t,
			consumerStore,
			"ldap://localhost:"+port,
			"local-only",
		)
		setPBindStartTLS(
			t,
			consumerStore,
			"start tls_cacert="+certificatePath+" tls_reqcert=demand",
		)
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
		defer stopConsumer()

		client, err := ldap.DialURL("ldap://" + consumerAddress)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		err = client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret")
		if err == nil {
			t.Fatal("pbind accepted an untrusted StartTLS provider")
		}
		assertLDAPResultCode(t, err, ldap.LDAPResultUnavailable)
	})

	t.Run("try-start falls back to cleartext", func(t *testing.T) {
		providerStore := storage.NewMemory()
		t.Cleanup(func() { _ = providerStore.Close() })
		seedDirectory(t, providerStore)
		providerAddress, stopProvider := startServer(t, providerStore, Config{})
		defer stopProvider()

		consumerStore := storage.NewMemory()
		t.Cleanup(func() { _ = consumerStore.Close() })
		seedDirectory(t, consumerStore)
		seedPBindConfiguration(
			t,
			consumerStore,
			"ldap://"+providerAddress,
			"local-only",
		)
		setPBindStartTLS(t, consumerStore, "try-start")
		consumerAddress, stopConsumer := startServer(t, consumerStore, Config{})
		defer stopConsumer()

		client, err := ldap.DialURL("ldap://" + consumerAddress)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer client.Close()
		if err := client.Bind(
			"uid=alice,ou=people,dc=example,dc=com",
			"secret",
		); err != nil {
			t.Fatalf("noncritical StartTLS pbind fallback: %v", err)
		}
	})
}

func TestPBindOverlayConfigurationValidation(t *testing.T) {
	t.Parallel()

	t.Run("duplicate", func(t *testing.T) {
		store := storage.NewMemory()
		defer store.Close()
		seedDirectory(t, store)
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			for _, index := range []string{"{0}", "{1}"} {
				if err := writer.Put(directory.Entry{
					DN: "olcOverlay=" + index + "pbind,olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: stringValues(index + "pbind")},
						{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
					},
				}, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed duplicate overlays: %v", err)
		}
		if _, err := New(Config{Store: store}); err == nil {
			t.Fatal("New() accepted duplicate pbind overlays")
		}
	})

	t.Run("global", func(t *testing.T) {
		store := storage.NewMemory()
		defer store.Close()
		if err := store.Update(context.Background(), func(writer storage.Writer) error {
			entries := []directory.Entry{
				{
					DN: "olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{{
						Description: "olcDatabase",
						Values:      stringValues("{-1}frontend"),
					}},
				},
				{
					DN: "olcOverlay={0}pbind,olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcOverlay", Values: stringValues("{0}pbind")},
						{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1")},
					},
				},
			}
			for _, entry := range entries {
				if err := writer.Put(entry, false); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed global overlay: %v", err)
		}
		if _, err := New(Config{Store: store}); err == nil {
			t.Fatal("New() accepted a global pbind overlay")
		}
	})
}

func TestDecodePBindResponseControls(t *testing.T) {
	t.Parallel()

	response := ber.NewSequence("LDAPMessage")
	response.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"messageID",
	))
	response.AppendChild(ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindResponse,
		nil,
		"BindResponse",
	))
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	control := ber.NewSequence("Control")
	control.AppendChild(syncConsumerOctetString([]byte("1.2.3"), "OID"))
	control.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"critical",
	))
	control.AppendChild(syncConsumerOctetString(nil, "value"))
	wrapper.AppendChild(control)
	response.AppendChild(wrapper)

	controls, err := decodePBindResponseControls(response)
	if err != nil || len(controls) != 1 || controls[0].OID != "1.2.3" ||
		!controls[0].Critical || !controls[0].HasValue || len(controls[0].Value) != 0 {
		t.Fatalf("decodePBindResponseControls() = %#v, %v", controls, err)
	}
}

func seedPBindConfiguration(
	t *testing.T,
	store storage.Store,
	providers,
	localPassword string,
) {
	t.Helper()
	userDN, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		user, err := writer.Get(userDN)
		if err != nil {
			return err
		}
		user.ReplaceValues("userPassword", stringValues(localPassword))
		if err := writer.Put(user, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}pbind")},
				{Description: "olcDbURI", Values: stringValues(providers)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed pbind configuration: %v", err)
	}
}

func setPBindStartTLS(t *testing.T, store storage.Store, value string) {
	t.Helper()
	dn, err := directory.ParseDN(
		"olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbStartTLS", stringValues(value))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure pbind StartTLS: %v", err)
	}
}

func writePBindTestCertificate(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	return path
}
