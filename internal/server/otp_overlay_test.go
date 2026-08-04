package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const otpTestOverlayDN = "olcOverlay={0}otp,olcDatabase={1}mdb,cn=config"

func TestOTPRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	entry := otpOverlayEntry(false)
	configuration, err := loadOTPRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadOTPRuntimeConfiguration(): %v", err)
	}
	if configuration.disabled || configuration.configDNKey == "" {
		t.Fatalf("configuration = %#v", configuration)
	}

	disabled := otpOverlayEntry(true)
	configuration, err = loadOTPRuntimeConfiguration(disabled)
	if err != nil || !configuration.disabled {
		t.Fatalf("disabled configuration = %#v, error = %v", configuration, err)
	}

	invalid := entry.Clone()
	invalid.ReplaceValues("olcDisabled", stringValues("sometimes"))
	if _, err := loadOTPRuntimeConfiguration(invalid); err == nil {
		t.Fatal("invalid olcDisabled was accepted")
	}
	unsupported := entry.Clone()
	unsupported.ReplaceValues("olcOTPSecret", stringValues("hidden"))
	if _, err := loadOTPRuntimeConfiguration(unsupported); err == nil {
		t.Fatal("unsupported private configuration was accepted")
	}
}

func TestOTPHardenedConcurrentReplay(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedOTPEntries(t, store, true, false)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	credential := openLDAPOTPHOTPPassword +
		openLDAPOTPToken(openLDAPOTPSecret, 4, 6)
	const clients = 16
	start := make(chan struct{})
	results := make(chan uint16, clients)
	var ready sync.WaitGroup
	ready.Add(clients)
	for range clients {
		go func() {
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				results <- ldap.LDAPResultUnavailable
				ready.Done()
				return
			}
			defer client.Close()
			ready.Done()
			<-start
			results <- otpLDAPResultCode(client.Bind(
				openLDAPOTPHOTPUserDN,
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
			t.Fatalf("concurrent Bind result = %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successful Binds = %d, want 1", successes)
	}
	entry := readStoredEntry(t, store, openLDAPOTPHOTPTokenDN)
	if got := string(entry.Values("oathHOTPCounter")[0]); got != "4" {
		t.Fatalf("oathHOTPCounter = %q, want 4", got)
	}
}

func TestOTPBindPrefersTOTPThenFallsBackToHOTP(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedOTPEntries(t, store, true, true)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, _ := directory.ParseDN(openLDAPOTPHOTPUserDN)
		user, err := writer.Get(dn)
		if err != nil {
			return err
		}
		user.ReplaceValues(
			"objectClass",
			stringValues("inetOrgPerson", "oathHOTPUser", "oathTOTPUser"),
		)
		user.ReplaceValues("oathTOTPToken", stringValues(openLDAPOTPTOTPTokenDN))
		return writer.Put(user, true)
	}); err != nil {
		t.Fatalf("configure dual OTP user: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	step := time.Now().Unix() / openLDAPOTPTOTPPeriod
	assertOTPBindCode(
		t,
		address,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, uint64(step), 6),
		ldap.LDAPResultSuccess,
	)
	hotp := readStoredEntry(t, store, openLDAPOTPHOTPTokenDN)
	if got := string(hotp.Values("oathHOTPCounter")[0]); got != "3" {
		t.Fatalf("HOTP counter after TOTP success = %q, want 3", got)
	}
	assertOTPBindCode(
		t,
		address,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
		ldap.LDAPResultSuccess,
	)
	hotp = readStoredEntry(t, store, openLDAPOTPHOTPTokenDN)
	if got := string(hotp.Values("oathHOTPCounter")[0]); got != "4" {
		t.Fatalf("HOTP counter after fallback = %q, want 4", got)
	}
}

func TestOTPStateWriteFailureCannotAuthenticate(t *testing.T) {
	memory := storage.NewMemory()
	store := &otpFailingStore{Store: memory, targetDN: openLDAPOTPHOTPTokenDN}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedOTPEntries(t, store, true, false)

	address, stop := startServer(t, store, Config{})
	defer stop()
	credential := openLDAPOTPHOTPPassword +
		openLDAPOTPToken(openLDAPOTPSecret, 4, 6)
	store.fail.Store(true)
	assertOTPBindCode(t, address, credential, ldap.LDAPResultOther)
	store.fail.Store(false)
	entry := readStoredEntry(t, store, openLDAPOTPHOTPTokenDN)
	if got := string(entry.Values("oathHOTPCounter")[0]); got != "3" {
		t.Fatalf("counter after failed state write = %q, want 3", got)
	}
	assertOTPBindCode(t, address, credential, ldap.LDAPResultSuccess)
}

func TestOTPOnlineLifecycleRollbackAndRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedOTPEntries(t, store, false, false)

	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}
	address, stop := startServer(t, store, config)
	configClient := bindOverlayReferenceClientWithDN(
		t,
		"ldap://"+address,
		"cn=config",
		"config-secret",
	)

	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultSuccess)
	if err := configClient.Add(otpOverlayAddRequest(otpTestOverlayDN, false)); err != nil {
		t.Fatalf("Add(otp): %v", err)
	}
	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultInvalidCredentials)
	assertOTPBindCode(
		t,
		address,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
		ldap.LDAPResultSuccess,
	)

	duplicate := otpOverlayAddRequest(
		"olcOverlay={1}otp,olcDatabase={1}mdb,cn=config",
		false,
	)
	if code := otpLDAPResultCode(configClient.Add(duplicate)); code == ldap.LDAPResultSuccess {
		t.Fatal("duplicate otp overlay was accepted")
	}
	if otpStoredEntryExists(t, store, duplicate.DN) {
		t.Fatal("duplicate otp overlay survived configuration rollback")
	}

	disable := ldap.NewModifyRequest(otpTestOverlayDN, nil)
	disable.Replace("olcDisabled", []string{"TRUE"})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable otp: %v", err)
	}
	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultSuccess)

	invalid := ldap.NewModifyRequest(otpTestOverlayDN, nil)
	invalid.Replace("olcDisabled", []string{"sometimes"})
	if code := otpLDAPResultCode(configClient.Modify(invalid)); code == ldap.LDAPResultSuccess {
		t.Fatal("invalid olcDisabled was accepted")
	}
	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultSuccess)

	enable := ldap.NewModifyRequest(otpTestOverlayDN, nil)
	enable.Replace("olcDisabled", []string{"FALSE"})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable otp: %v", err)
	}
	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultInvalidCredentials)

	if err := configClient.Del(ldap.NewDelRequest(otpTestOverlayDN, nil)); err != nil {
		t.Fatalf("Delete(otp): %v", err)
	}
	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultSuccess)
	if err := configClient.Add(otpOverlayAddRequest(otpTestOverlayDN, false)); err != nil {
		t.Fatalf("re-add otp: %v", err)
	}
	configClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	assertOTPBindCode(t, address, openLDAPOTPHOTPPassword, ldap.LDAPResultInvalidCredentials)
	assertOTPBindCode(
		t,
		address,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 5, 6),
		ldap.LDAPResultSuccess,
	)
}

func TestOTPInvalidInternalsDoNotLeak(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*directory.Entry)
	}{
		{name: "unsupported algorithm", mutate: func(entry *directory.Entry) {
			entry.ReplaceValues("oathHMACAlgorithm", stringValues("1.2.3.4"))
		}},
		{name: "invalid digits", mutate: func(entry *directory.Entry) {
			entry.ReplaceValues("oathOTPLength", stringValues("9"))
		}},
		{name: "invalid look ahead", mutate: func(entry *directory.Entry) {
			entry.ReplaceValues("oathHOTPLookAhead", stringValues("-1"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			seedOTPEntries(t, store, true, false)
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				dn, _ := directory.ParseDN(openLDAPOTPHOTPParamsDN)
				entry, err := writer.Get(dn)
				if err != nil {
					return err
				}
				test.mutate(&entry)
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("mutate params: %v", err)
			}
			address, stop := startServer(t, store, Config{})
			defer stop()
			assertOTPBindCode(
				t,
				address,
				openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
				ldap.LDAPResultInvalidCredentials,
			)
		})
	}
}

func TestOTPSchemaAcceptsNormalLDAPEntries(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(otpOverlayEntry(false), false)
	}); err != nil {
		t.Fatalf("seed otp overlay: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	root := bindOverlayReferenceClient(
		t,
		"ldap://"+address,
		"admin-secret",
	)
	defer root.Close()
	for _, entry := range otpHOTPEntries() {
		request := ldap.NewAddRequest(entry.DN, nil)
		for _, attribute := range entry.Attributes {
			values := make([]string, len(attribute.Values))
			for index := range attribute.Values {
				values[index] = string(attribute.Values[index])
			}
			request.Attribute(attribute.Description, values)
		}
		if err := root.Add(request); err != nil {
			t.Fatalf("Add(%s): %v", entry.DN, err)
		}
	}
	assertOTPBindCode(
		t,
		address,
		openLDAPOTPHOTPPassword+openLDAPOTPToken(openLDAPOTPSecret, 4, 6),
		ldap.LDAPResultSuccess,
	)
}

func seedOTPEntries(
	t *testing.T,
	store storage.Store,
	withOverlay bool,
	withTOTP bool,
) {
	t.Helper()
	entries := otpHOTPEntries()
	if withTOTP {
		entries = append(entries, otpTOTPEntries()...)
	}
	if withOverlay {
		entries = append(entries, otpOverlayEntry(false))
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed OTP entries: %v", err)
	}
}

func otpHOTPEntries() []directory.Entry {
	return []directory.Entry{
		{
			DN: openLDAPOTPHOTPParamsDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPParams")},
				{Description: "ou", Values: stringValues("hotp-params")},
				{Description: "oathOTPLength", Values: stringValues("6")},
				{Description: "oathHOTPLookAhead", Values: stringValues("3")},
				{Description: "oathHMACAlgorithm", Values: stringValues(otpHMACSHA1OID)},
			},
		},
		{
			DN: openLDAPOTPHOTPTokenDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathHOTPToken")},
				{Description: "ou", Values: stringValues("hotp-token")},
				{Description: "oathHOTPParams", Values: stringValues(openLDAPOTPHOTPParamsDN)},
				{Description: "oathSecret", Values: stringValues(openLDAPOTPSecret)},
				{Description: "oathHOTPCounter", Values: stringValues("3")},
			},
		},
		{
			DN: openLDAPOTPHOTPUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson", "oathHOTPUser")},
				{Description: "uid", Values: stringValues("otp-hotp")},
				{Description: "cn", Values: stringValues("OTP HOTP")},
				{Description: "sn", Values: stringValues("HOTP")},
				{Description: "userPassword", Values: stringValues(openLDAPOTPHOTPPassword)},
				{Description: "oathHOTPToken", Values: stringValues(openLDAPOTPHOTPTokenDN)},
			},
		},
	}
}

func otpTOTPEntries() []directory.Entry {
	return []directory.Entry{
		{
			DN: openLDAPOTPTOTPParamsDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathTOTPParams")},
				{Description: "ou", Values: stringValues("totp-params")},
				{Description: "oathOTPLength", Values: stringValues("6")},
				{Description: "oathTOTPTimeStepPeriod", Values: stringValues("315360000")},
				{Description: "oathTOTPTimeStepWindow", Values: stringValues("1")},
				{Description: "oathHMACAlgorithm", Values: stringValues(otpHMACSHA1OID)},
			},
		},
		{
			DN: openLDAPOTPTOTPTokenDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit", "oathTOTPToken")},
				{Description: "ou", Values: stringValues("totp-token")},
				{Description: "oathTOTPParams", Values: stringValues(openLDAPOTPTOTPParamsDN)},
				{Description: "oathSecret", Values: stringValues(openLDAPOTPSecret)},
			},
		},
		{
			DN: openLDAPOTPTOTPUserDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson", "oathTOTPUser")},
				{Description: "uid", Values: stringValues("otp-totp")},
				{Description: "cn", Values: stringValues("OTP TOTP")},
				{Description: "sn", Values: stringValues("TOTP")},
				{Description: "userPassword", Values: stringValues(openLDAPOTPTOTPPassword)},
				{Description: "oathTOTPToken", Values: stringValues(openLDAPOTPTOTPTokenDN)},
			},
		},
	}
}

func otpOverlayEntry(disabled bool) directory.Entry {
	entry := directory.Entry{
		DN: otpTestOverlayDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}otp")},
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

func otpOverlayAddRequest(dn string, disabled bool) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"olcOverlayConfig"})
	rdn, _ := directory.ParseDN(dn)
	request.Attribute("olcOverlay", []string{string(rdn.RDNValues()[0].Value)})
	if disabled {
		request.Attribute("olcDisabled", []string{"TRUE"})
	}
	return request
}

func assertOTPBindCode(t *testing.T, address, credential string, want uint16) {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if got := otpLDAPResultCode(client.Bind(openLDAPOTPHOTPUserDN, credential)); got != want {
		t.Fatalf("Bind result = %d, want %d", got, want)
	}
}

func otpLDAPResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode
	}
	return ldap.LDAPResultOther
}

func TestOTPConfigurationSummaryCount(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedOTPEntries(t, store, true, false)
	summary, err := ValidateConfiguration(context.Background(), Config{Store: store})
	if err != nil {
		t.Fatalf("ValidateConfiguration(): %v", err)
	}
	if summary.Overlays != 1 {
		t.Fatalf("overlay count = %d, want 1", summary.Overlays)
	}
}

func TestOTPConfigurationRejectsFrontendAndLDAPBackend(t *testing.T) {
	tests := []struct {
		name     string
		database directory.Entry
		overlay  directory.Entry
	}{
		{
			name: "frontend",
			database: directory.Entry{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				},
			},
			overlay: directory.Entry{
				DN: "olcOverlay={0}otp,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
					{Description: "olcOverlay", Values: stringValues("{0}otp")},
				},
			},
		},
		{
			name: "ldap backend",
			database: ldapBackendDatabaseEntry(
				"{1}ldap",
				ldapBackendTestSuffix,
				"ldap://127.0.0.1:1389",
			),
			overlay: directory.Entry{
				DN: "olcOverlay={0}otp," + ldapBackendTestDatabaseDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
					{Description: "olcOverlay", Values: stringValues("{0}otp")},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if err := writer.Put(test.database, false); err != nil {
					return err
				}
				return writer.Put(test.overlay, false)
			}); err != nil {
				t.Fatalf("seed configuration: %v", err)
			}
			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatal("unsupported OTP mount was accepted")
			}
		})
	}
}

func otpStoredEntryExists(t *testing.T, store storage.Store, rawDN string) bool {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%s): %v", rawDN, err)
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

type otpFailingStore struct {
	storage.Store
	targetDN string
	fail     atomic.Bool
}

func (store *otpFailingStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return update(&otpFailingWriter{Writer: writer, store: store})
	})
}

type otpFailingWriter struct {
	storage.Writer
	store *otpFailingStore
}

func (writer *otpFailingWriter) Put(
	entry directory.Entry,
	replace bool,
) error {
	if writer.shouldFail(entry) {
		return errors.New("injected OTP state write failure")
	}
	return writer.Writer.Put(entry, replace)
}

func (writer *otpFailingWriter) PutIn(
	partition string,
	entry directory.Entry,
	replace bool,
) error {
	if writer.shouldFail(entry) {
		return errors.New("injected OTP state write failure")
	}
	return writer.Writer.PutIn(partition, entry, replace)
}

func (writer *otpFailingWriter) shouldFail(entry directory.Entry) bool {
	if !writer.store.fail.Load() {
		return false
	}
	target, err := directory.ParseDN(writer.store.targetDN)
	if err != nil {
		return false
	}
	dn, err := directory.ParseDN(entry.DN)
	return err == nil && target.Equal(dn)
}
