package server

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	totpPasswordOverlayDN = "olcOverlay={0}totp,olcDatabase={1}mdb,cn=config"
	totpPasswordUserDN    = "uid=alice,ou=people,dc=example,dc=com"
	totpPasswordTestUnix  = int64(1_800_000_000)
)

var totpPasswordTestSecret = []byte("12345678901234567890")

func TestTOTPPasswordRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	configuration, err := loadTOTPPasswordRuntimeConfiguration(
		totpPasswordOverlayEntry(false),
	)
	if err != nil || configuration.disabled || configuration.configDNKey == "" {
		t.Fatalf("configuration = %#v, error = %v", configuration, err)
	}
	disabled, err := loadTOTPPasswordRuntimeConfiguration(
		totpPasswordOverlayEntry(true),
	)
	if err != nil || !disabled.disabled {
		t.Fatalf("disabled configuration = %#v, error = %v", disabled, err)
	}
	invalid := totpPasswordOverlayEntry(false)
	invalid.ReplaceValues("olcTotpWindow", stringValues("1"))
	if _, err := loadTOTPPasswordRuntimeConfiguration(invalid); err == nil {
		t.Fatal("unsupported totp configuration attribute was accepted")
	}
}

func TestTOTPPasswordSimpleBindReplayAndNoReplication(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	stored, err := auth.HashPassword(
		totpPasswordTestSecret,
		auth.TOTP1HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(TOTP1): %v", err)
	}
	seedTOTPPasswordConfiguration(t, store, stored, false, "")

	var unix atomic.Int64
	unix.Store(totpPasswordTestUnix)
	address, stop := startServer(t, store, Config{
		Clock: func() time.Time {
			return time.Unix(unix.Load(), 0).UTC()
		},
	})
	defer stop()
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		unix.Load()/30,
		otpHMACSHA1OID,
		"",
	)
	client := dialTOTPPasswordClient(t, address)
	defer client.Close()
	if err := client.Bind(totpPasswordUserDN, credential); err != nil {
		t.Fatalf("TOTP Bind(): %v", err)
	}
	assertLDAPResultCode(
		t,
		client.Bind(totpPasswordUserDN, credential),
		ldap.LDAPResultInvalidCredentials,
	)

	entry := readStoredEntry(t, store, totpPasswordUserDN)
	assertTOTPPasswordTimestamp(t, entry, unix.Load())
	if len(entry.Values("entryCSN")) != 0 ||
		len(entry.Values("modifyTimestamp")) != 0 {
		t.Fatalf("authTimestamp update generated replicated LastMod state: %#v", entry)
	}

}

func TestTOTPPasswordOrdinaryBindUpdatesTimestamp(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedTOTPPasswordConfiguration(
		t,
		store,
		[]byte("ordinary-secret"),
		false,
		"",
	)
	address, stop := startServer(t, store, Config{
		Clock: func() time.Time {
			return time.Unix(totpPasswordTestUnix, 0).UTC()
		},
	})
	defer stop()
	client := dialTOTPPasswordClient(t, address)
	defer client.Close()
	if err := client.Bind(totpPasswordUserDN, "ordinary-secret"); err != nil {
		t.Fatalf("ordinary Bind with totp overlay: %v", err)
	}
	assertTOTPPasswordTimestamp(
		t,
		readStoredEntry(t, store, totpPasswordUserDN),
		totpPasswordTestUnix,
	)
}

func TestTOTPPasswordGeneralizedAuthenticationTimesPreventReplay(t *testing.T) {
	now := time.Unix(totpPasswordTestUnix, 0).UTC()
	for _, test := range []struct {
		name      string
		timestamp string
	}{
		{
			name:      "fractional seconds",
			timestamp: now.Format("20060102150405") + ".123456789012345678Z",
		},
		{
			name:      "timezone offset",
			timestamp: now.In(time.FixedZone("UTC+8", 8*60*60)).Format("20060102150405-0700"),
		},
		{
			name:      "leap second",
			timestamp: now.Add(-time.Minute).Format("200601021504") + "60Z",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			stored, err := auth.HashPassword(
				totpPasswordTestSecret,
				auth.TOTP1HashScheme,
				nil,
			)
			if err != nil {
				t.Fatalf("HashPassword(TOTP1): %v", err)
			}
			seedTOTPPasswordConfiguration(t, store, stored, false, "")
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				entry, err := writer.Get(mustTOTPPasswordDN(t, totpPasswordUserDN))
				if err != nil {
					return err
				}
				entry.ReplaceValues("authTimestamp", stringValues(test.timestamp))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("seed authTimestamp: %v", err)
			}
			address, stop := startServer(t, store, Config{Clock: func() time.Time {
				return now
			}})
			defer stop()
			credential := totpPasswordCredential(
				t,
				totpPasswordTestSecret,
				now.Unix()/30,
				otpHMACSHA1OID,
				"",
			)
			assertTOTPPasswordBindCode(
				t,
				address,
				credential,
				ldap.LDAPResultInvalidCredentials,
			)
		})
	}
}

func TestTOTPPasswordDatabaseRootBindAndReplay(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	stored, err := auth.HashPassword(totpPasswordTestSecret, auth.TOTP1HashScheme, nil)
	if err != nil {
		t.Fatalf("HashPassword(TOTP1): %v", err)
	}
	seedTOTPPasswordConfiguration(t, store, []byte("ordinary"), false, "")
	const rootDN = "cn=admin,dc=example,dc=com"
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: rootDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("person")},
				{Description: "cn", Values: stringValues("admin")},
				{Description: "sn", Values: stringValues("admin")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed root DN entry: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: stored,
		Clock: func() time.Time {
			return time.Unix(totpPasswordTestUnix, 0).UTC()
		},
	})
	defer stop()
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		totpPasswordTestUnix/30,
		otpHMACSHA1OID,
		"",
	)
	client := dialTOTPPasswordClient(t, address)
	defer client.Close()
	if err := client.Bind(rootDN, credential); err != nil {
		t.Fatalf("TOTP root Bind(): %v", err)
	}
	assertLDAPResultCode(
		t,
		client.Bind(rootDN, credential),
		ldap.LDAPResultInvalidCredentials,
	)
	assertTOTPPasswordTimestamp(
		t,
		readStoredEntry(t, store, rootDN),
		totpPasswordTestUnix,
	)
}

func TestTOTPPasswordHardenedConcurrentReplay(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{
			name: "memory",
			open: func(*testing.T) storage.Store {
				return storage.NewMemory()
			},
		},
		{
			name: "bbolt",
			open: func(t *testing.T) storage.Store {
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	} {
		t.Run(backend.name, func(t *testing.T) {
			exerciseTOTPPasswordHardenedConcurrentReplay(t, backend.open(t))
		})
	}
}

func exerciseTOTPPasswordHardenedConcurrentReplay(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	stored, err := auth.HashPassword(
		totpPasswordTestSecret,
		auth.TOTP256HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(TOTP256): %v", err)
	}
	seedTOTPPasswordConfiguration(t, store, stored, false, "")
	address, stop := startServer(t, store, Config{
		Clock: func() time.Time {
			return time.Unix(totpPasswordTestUnix, 0).UTC()
		},
	})
	defer stop()
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		totpPasswordTestUnix/30,
		otpHMACSHA256OID,
		"",
	)

	const clients = 16
	start := make(chan struct{})
	results := make(chan uint16, clients)
	var ready sync.WaitGroup
	ready.Add(clients)
	for range clients {
		go func() {
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				ready.Done()
				results <- ldap.LDAPResultUnavailable
				return
			}
			defer client.Close()
			ready.Done()
			<-start
			results <- otpLDAPResultCode(client.Bind(
				totpPasswordUserDN,
				credential,
			))
		}()
	}
	ready.Wait()
	close(start)
	successes := 0
	for range clients {
		switch code := <-results; code {
		case ldap.LDAPResultSuccess:
			successes++
		case ldap.LDAPResultInvalidCredentials:
		default:
			t.Fatalf("concurrent TOTP Bind result = %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successful TOTP Binds = %d, want 1", successes)
	}
}

func TestTOTPPasswordStateWriteFailureReturnsInvalidCredentials(t *testing.T) {
	memory := storage.NewMemory()
	store := &otpFailingStore{Store: memory, targetDN: totpPasswordUserDN}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	stored, err := auth.HashPassword(
		totpPasswordTestSecret,
		auth.TOTP512HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(TOTP512): %v", err)
	}
	seedTOTPPasswordConfiguration(t, store, stored, false, "")
	address, stop := startServer(t, store, Config{
		Clock: func() time.Time {
			return time.Unix(totpPasswordTestUnix, 0).UTC()
		},
	})
	defer stop()
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		totpPasswordTestUnix/30,
		otpHMACSHA512OID,
		"",
	)
	client := dialTOTPPasswordClient(t, address)
	defer client.Close()
	store.fail.Store(true)
	assertLDAPResultCode(
		t,
		client.Bind(totpPasswordUserDN, credential),
		ldap.LDAPResultInvalidCredentials,
	)
	store.fail.Store(false)
	if len(readStoredEntry(t, store, totpPasswordUserDN).Values("authTimestamp")) != 0 {
		t.Fatal("failed authTimestamp transaction was not rolled back")
	}
	if err := client.Bind(totpPasswordUserDN, credential); err != nil {
		t.Fatalf("TOTP Bind after state store recovery: %v", err)
	}
}

func TestTOTPPasswordEarlierBindStateWriteFailureReturnsInvalidCredentials(t *testing.T) {
	memory := storage.NewMemory()
	store := &otpFailingStore{Store: memory, targetDN: totpPasswordUserDN}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	stored, err := auth.HashPassword(totpPasswordTestSecret, auth.TOTP256HashScheme, nil)
	if err != nil {
		t.Fatalf("HashPassword(TOTP256): %v", err)
	}
	seedTOTPPasswordConfiguration(t, store, stored, false, "")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		database, err := writer.Get(mustTOTPPasswordDN(
			t,
			"olcDatabase={1}mdb,cn=config",
		))
		if err != nil {
			return err
		}
		database.ReplaceValues("olcLastBind", stringValues("TRUE"))
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("enable lastbind: %v", err)
	}
	address, stop := startServer(t, store, Config{Clock: func() time.Time {
		return time.Unix(totpPasswordTestUnix, 0).UTC()
	}})
	defer stop()
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		totpPasswordTestUnix/30,
		otpHMACSHA256OID,
		"",
	)
	client := dialTOTPPasswordClient(t, address)
	defer client.Close()
	store.fail.Store(true)
	assertLDAPResultCode(
		t,
		client.Bind(totpPasswordUserDN, credential),
		ldap.LDAPResultInvalidCredentials,
	)
	store.fail.Store(false)
	entry := readStoredEntry(t, store, totpPasswordUserDN)
	if entry.HasAttribute("pwdLastSuccess") || entry.HasAttribute("authTimestamp") {
		t.Fatalf("failed Bind state transaction was not rolled back: %#v", entry)
	}
	if err := client.Bind(totpPasswordUserDN, credential); err != nil {
		t.Fatalf("TOTP Bind after lastbind store recovery: %v", err)
	}
}

func TestTOTPPasswordModifyUsesConfiguredANDPWScheme(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedTOTPPasswordConfiguration(
		t,
		store,
		[]byte("secret"),
		false,
		auth.TOTP1AndPWHashScheme,
	)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Clock: func() time.Time {
			return time.Unix(totpPasswordTestUnix, 0).UTC()
		},
	})
	defer stop()
	admin := dialTOTPPasswordClient(t, address)
	defer admin.Close()
	if err := admin.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("admin Bind(): %v", err)
	}
	newPassword := string(totpPasswordTestSecret) + "|static-secret"
	if _, err := admin.PasswordModify(ldap.NewPasswordModifyRequest(
		totpPasswordUserDN,
		"",
		newPassword,
	)); err != nil {
		t.Fatalf("PasswordModify(TOTP1ANDPW): %v", err)
	}
	stored := readStoredEntry(t, store, totpPasswordUserDN).Values("userPassword")
	if len(stored) != 1 ||
		!strings.HasPrefix(string(stored[0]), auth.TOTP1AndPWHashScheme) ||
		!strings.Contains(string(stored[0]), "|{SSHA}") {
		t.Fatalf("stored TOTP1ANDPW password = %q", stored)
	}
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		totpPasswordTestUnix/30,
		otpHMACSHA1OID,
		"static-secret",
	)
	user := dialTOTPPasswordClient(t, address)
	defer user.Close()
	if err := user.Bind(totpPasswordUserDN, credential); err != nil {
		t.Fatalf("Bind with Password Modify TOTP1ANDPW value: %v", err)
	}
}

func TestTOTPPasswordDisabledOrMissingOverlayDoesNotAuthenticate(t *testing.T) {
	for _, test := range []struct {
		name        string
		withOverlay bool
		disabled    bool
	}{
		{name: "missing"},
		{name: "disabled", withOverlay: true, disabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			stored, err := auth.HashPassword(
				totpPasswordTestSecret,
				auth.TOTP1HashScheme,
				nil,
			)
			if err != nil {
				t.Fatalf("HashPassword(TOTP1): %v", err)
			}
			if test.withOverlay {
				seedTOTPPasswordConfiguration(t, store, stored, test.disabled, "")
			} else if err := store.Update(context.Background(), func(writer storage.Writer) error {
				entry, err := writer.Get(mustTOTPPasswordDN(t, totpPasswordUserDN))
				if err != nil {
					return err
				}
				entry.ReplaceValues("userPassword", [][]byte{stored})
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("seed TOTP password: %v", err)
			}
			address, stop := startServer(t, store, Config{
				Clock: func() time.Time {
					return time.Unix(totpPasswordTestUnix, 0).UTC()
				},
			})
			defer stop()
			credential := totpPasswordCredential(
				t,
				totpPasswordTestSecret,
				totpPasswordTestUnix/30,
				otpHMACSHA1OID,
				"",
			)
			client := dialTOTPPasswordClient(t, address)
			defer client.Close()
			assertLDAPResultCode(
				t,
				client.Bind(totpPasswordUserDN, credential),
				ldap.LDAPResultInvalidCredentials,
			)
		})
	}
}

func TestTOTPPasswordOnlineLifecycleRollbackAndRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	stored, err := auth.HashPassword(
		totpPasswordTestSecret,
		auth.TOTP1HashScheme,
		nil,
	)
	if err != nil {
		t.Fatalf("HashPassword(TOTP1): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(mustTOTPPasswordDN(t, totpPasswordUserDN))
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", [][]byte{stored})
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed TOTP password: %v", err)
	}

	var unix atomic.Int64
	unix.Store(totpPasswordTestUnix)
	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Clock: func() time.Time {
			return time.Unix(unix.Load(), 0).UTC()
		},
	}
	address, stop := startServer(t, store, config)
	configClient := bindOverlayReferenceClientWithDN(
		t,
		"ldap://"+address,
		"cn=config",
		"config-secret",
	)
	credential := func() string {
		return totpPasswordCredential(
			t,
			totpPasswordTestSecret,
			unix.Load()/30,
			otpHMACSHA1OID,
			"",
		)
	}
	assertTOTPPasswordBindCode(
		t,
		address,
		credential(),
		ldap.LDAPResultInvalidCredentials,
	)
	if err := configClient.Add(totpPasswordOverlayAddRequest(
		totpPasswordOverlayDN,
		false,
	)); err != nil {
		t.Fatalf("Add(totp): %v", err)
	}
	assertTOTPPasswordBindCode(t, address, credential(), ldap.LDAPResultSuccess)

	duplicate := totpPasswordOverlayAddRequest(
		"olcOverlay={1}totp,olcDatabase={1}mdb,cn=config",
		false,
	)
	if err := configClient.Add(duplicate); err != nil {
		t.Fatalf("Add(second totp): %v", err)
	}
	if !otpStoredEntryExists(t, store, duplicate.DN) {
		t.Fatal("second totp overlay was not stored")
	}
	summary, err := ValidateConfiguration(context.Background(), Config{Store: store})
	if err != nil {
		t.Fatalf("ValidateConfiguration(two totp overlays): %v", err)
	}
	if summary.Overlays != 2 {
		t.Fatalf("overlay count with two totp instances = %d, want 2", summary.Overlays)
	}
	if err := configClient.Del(ldap.NewDelRequest(duplicate.DN, nil)); err != nil {
		t.Fatalf("Delete(second totp): %v", err)
	}

	unix.Add(30)
	disable := ldap.NewModifyRequest(totpPasswordOverlayDN, nil)
	disable.Replace("olcDisabled", []string{"TRUE"})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable totp: %v", err)
	}
	assertTOTPPasswordBindCode(
		t,
		address,
		credential(),
		ldap.LDAPResultInvalidCredentials,
	)
	invalid := ldap.NewModifyRequest(totpPasswordOverlayDN, nil)
	invalid.Replace("olcDisabled", []string{"sometimes"})
	if otpLDAPResultCode(configClient.Modify(invalid)) == ldap.LDAPResultSuccess {
		t.Fatal("invalid totp olcDisabled was accepted")
	}
	enable := ldap.NewModifyRequest(totpPasswordOverlayDN, nil)
	enable.Replace("olcDisabled", []string{"FALSE"})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	assertTOTPPasswordBindCode(t, address, credential(), ldap.LDAPResultSuccess)
	configClient.Close()
	stop()

	unix.Add(30)
	address, stop = startServer(t, store, config)
	defer stop()
	assertTOTPPasswordBindCode(t, address, credential(), ldap.LDAPResultSuccess)
	configClient = bindOverlayReferenceClientWithDN(
		t,
		"ldap://"+address,
		"cn=config",
		"config-secret",
	)
	defer configClient.Close()
	if err := configClient.Del(ldap.NewDelRequest(totpPasswordOverlayDN, nil)); err != nil {
		t.Fatalf("Delete(totp): %v", err)
	}
	unix.Add(30)
	assertTOTPPasswordBindCode(
		t,
		address,
		credential(),
		ldap.LDAPResultInvalidCredentials,
	)
}

func TestTOTPPasswordFrontendOverlayAppliesGlobally(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	stored, err := auth.HashPassword(totpPasswordTestSecret, auth.TOTP512HashScheme, nil)
	if err != nil {
		t.Fatalf("HashPassword(TOTP512): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(mustTOTPPasswordDN(t, totpPasswordUserDN))
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", [][]byte{stored})
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcDatabase",
				Values:      stringValues("{-1}frontend"),
			}},
		}, false); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}totp,olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}totp")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed frontend totp configuration: %v", err)
	}
	address, stop := startServer(t, store, Config{Clock: func() time.Time {
		return time.Unix(totpPasswordTestUnix, 0).UTC()
	}})
	defer stop()
	credential := totpPasswordCredential(
		t,
		totpPasswordTestSecret,
		totpPasswordTestUnix/30,
		otpHMACSHA512OID,
		"",
	)
	assertTOTPPasswordBindCode(t, address, credential, ldap.LDAPResultSuccess)
	assertTOTPPasswordTimestamp(
		t,
		readStoredEntry(t, store, totpPasswordUserDN),
		totpPasswordTestUnix,
	)
}

func TestTOTPPasswordConfigurationSummaryAndOperationalAttribute(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedTOTPPasswordConfiguration(t, store, []byte("ordinary"), false, "")
	summary, err := ValidateConfiguration(context.Background(), Config{Store: store})
	if err != nil {
		t.Fatalf("ValidateConfiguration(): %v", err)
	}
	if summary.Overlays != 1 {
		t.Fatalf("overlay count = %d, want 1", summary.Overlays)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if !isProtectedOperationalAttribute(registry, "authTimestamp") ||
		!isManageableOperationalAttribute(registry, "authTimestamp") {
		t.Fatal("authTimestamp is not a protected manageable operational attribute")
	}
}

func TestTOTPPasswordAuthTimestampRequiresRelax(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedTOTPPasswordConfiguration(t, store, []byte("ordinary"), false, "")
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	admin := dialTOTPPasswordClient(t, address)
	defer admin.Close()
	if err := admin.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("admin Bind(): %v", err)
	}

	const uid = "totp-timestamp"
	dn := "uid=" + uid + ",ou=people,dc=example,dc=com"
	timestamp := formatPasswordPolicyTime(time.Unix(totpPasswordTestUnix, 0))
	request := newPersonAddRequest(uid)
	request.Attribute("authTimestamp", []string{timestamp})
	assertLDAPResultCode(t, admin.Add(request), ldap.LDAPResultConstraintViolation)

	request = newPersonAddRequest(uid)
	request.Controls = []ldap.Control{relaxLDAPControl()}
	request.Attribute("authTimestamp", []string{timestamp})
	if err := admin.Add(request); err != nil {
		t.Fatalf("Add(authTimestamp with Relax): %v", err)
	}

	nextTimestamp := formatPasswordPolicyTime(time.Unix(totpPasswordTestUnix+30, 0))
	modify := ldap.NewModifyRequest(dn, nil)
	modify.Replace("authTimestamp", []string{nextTimestamp})
	assertLDAPResultCode(t, admin.Modify(modify), ldap.LDAPResultConstraintViolation)
	modify = ldap.NewModifyRequest(dn, []ldap.Control{relaxLDAPControl()})
	modify.Replace("authTimestamp", []string{nextTimestamp})
	if err := admin.Modify(modify); err != nil {
		t.Fatalf("Modify(authTimestamp with Relax): %v", err)
	}
	values := readStoredEntry(t, store, dn).Values("authTimestamp")
	if len(values) != 1 || string(values[0]) != nextTimestamp {
		t.Fatalf("authTimestamp = %q, want %q", values, nextTimestamp)
	}
}

func seedTOTPPasswordConfiguration(
	t *testing.T,
	store storage.Store,
	stored []byte,
	disabled bool,
	passwordHash string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(mustTOTPPasswordDN(t, totpPasswordUserDN))
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", [][]byte{stored})
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		if err := writer.Put(totpPasswordOverlayEntry(disabled), false); err != nil {
			return err
		}
		if passwordHash == "" {
			return nil
		}
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				{Description: "olcPasswordHash", Values: stringValues(passwordHash)},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed totp password configuration: %v", err)
	}
}

func totpPasswordOverlayEntry(disabled bool) directory.Entry {
	entry := directory.Entry{
		DN: totpPasswordOverlayDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}totp")},
		},
	}
	if disabled {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcDisabled",
			Values:      stringValues("TRUE"),
		})
	}
	return entry
}

func totpPasswordOverlayAddRequest(dn string, disabled bool) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"olcOverlayConfig"})
	parsed, _ := directory.ParseDN(dn)
	request.Attribute("olcOverlay", []string{string(parsed.RDNValues()[0].Value)})
	if disabled {
		request.Attribute("olcDisabled", []string{"TRUE"})
	}
	return request
}

func totpPasswordCredential(
	t *testing.T,
	secret []byte,
	step int64,
	algorithmOID,
	staticPassword string,
) string {
	t.Helper()
	token, err := generateOTP(secret, uint64(step), 6, algorithmOID)
	if err != nil {
		t.Fatalf("generate TOTP credential: %v", err)
	}
	return staticPassword + token
}

func dialTOTPPasswordClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	return client
}

func assertTOTPPasswordBindCode(
	t *testing.T,
	address,
	credential string,
	want uint16,
) {
	t.Helper()
	client := dialTOTPPasswordClient(t, address)
	defer client.Close()
	if got := otpLDAPResultCode(client.Bind(totpPasswordUserDN, credential)); got != want {
		t.Fatalf("TOTP Bind result = %d, want %d", got, want)
	}
}

func assertTOTPPasswordTimestamp(
	t *testing.T,
	entry directory.Entry,
	unix int64,
) {
	t.Helper()
	values := entry.Values("authTimestamp")
	want := formatPasswordPolicyTime(time.Unix(unix, 0))
	if len(values) != 1 || string(values[0]) != want {
		t.Fatalf("authTimestamp = %q, want %q", values, want)
	}
}

func mustTOTPPasswordDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", raw, err)
	}
	return dn
}
