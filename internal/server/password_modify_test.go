package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const aliceDN = "uid=alice,ou=people,dc=example,dc=com"

func TestLDAPClientPasswordModifySelf(t *testing.T) {
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
		[]string{"supportedExtension"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedExtension"),
			passwordModifyOID,
		) {
		t.Fatalf("Password Modify Root DSE = %#v, %v", rootDSE, err)
	}

	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest("", "", "new-secret"))
	assertLDAPResultCode(t, err, ldap.LDAPResultStrongAuthRequired)
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"wrong",
		"not-stored",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)

	if _, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"secret",
		"new-secret",
	)); err != nil {
		t.Fatalf("PasswordModify(): %v", err)
	}
	entry := readStoredEntry(t, store, aliceDN)
	stored := entry.Values("userPassword")
	if len(stored) != 1 ||
		!strings.HasPrefix(string(stored[0]), auth.OpenLDAPDefaultHashScheme) ||
		!auth.VerifyPassword(stored[0], []byte("new-secret")) ||
		len(entry.Values("modifyTimestamp")) == 0 ||
		len(entry.Values("entryCSN")) == 0 {
		t.Fatalf("password-modified entry = %#v", entry)
	}

	assertBindPassword(t, address, aliceDN, "secret", false)
	assertBindPassword(t, address, aliceDN, "new-secret", true)
}

func TestLDAPClientPasswordModifyUsesConfiguredSM3Hash(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				},
				{
					Description: "olcPasswordHash",
					Values:      stringValues(auth.SMPBKDF2HashScheme),
				},
			},
		}, false)
	}); err != nil {
		t.Fatalf("configure password hash: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	admin, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(admin): %v", err)
	}
	defer admin.Close()
	if err := admin.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("admin Bind(): %v", err)
	}
	if _, err := admin.PasswordModify(ldap.NewPasswordModifyRequest(
		aliceDN,
		"",
		"admin-set-secret",
	)); err != nil {
		t.Fatalf("admin PasswordModify(): %v", err)
	}
	assertStoredSMPBKDF2Password(t, store, "admin-set-secret")

	user, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(user): %v", err)
	}
	defer user.Close()
	if err := user.Bind(aliceDN, "admin-set-secret"); err != nil {
		t.Fatalf("user Bind(): %v", err)
	}
	result, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"admin-set-secret",
		"",
	))
	if err != nil {
		t.Fatalf("generated PasswordModify(): %v", err)
	}
	if len(result.GeneratedPassword) != generatedPasswordLength {
		t.Fatalf("generated password = %q", result.GeneratedPassword)
	}
	assertStoredSMPBKDF2Password(t, store, result.GeneratedPassword)
	assertBindPassword(t, address, aliceDN, "admin-set-secret", false)
	assertBindPassword(t, address, aliceDN, result.GeneratedPassword, true)
}

func TestLDAPClientPasswordHashConfigurationReloadsAtomically(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	const frontendDN = "olcDatabase={-1}frontend,cn=config"
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(directory.Entry{
			DN: frontendDN,
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("olcDatabaseConfig"),
				},
				{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				},
				{
					Description: "olcPasswordHash",
					Values:      stringValues(auth.OpenLDAPDefaultHashScheme),
				},
			},
		}, false); err != nil {
			return err
		}
		dataDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		data, err := writer.Get(dataDN)
		if err != nil {
			return err
		}
		data.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
			"{1}to * by self write by users read by * none",
		))
		return writer.Put(data, true)
	}); err != nil {
		t.Fatalf("seed frontend configuration: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config Bind(): %v", err)
	}
	useSM3 := ldap.NewModifyRequest(frontendDN, nil)
	useSM3.Replace("olcPasswordHash", []string{auth.SMPBKDF2HashScheme})
	if err := configClient.Modify(useSM3); err != nil {
		t.Fatalf("configure PBKDF2-SM3: %v", err)
	}

	user, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(user): %v", err)
	}
	defer user.Close()
	if err := user.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("user Bind(): %v", err)
	}
	if _, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"secret",
		"online-sm3-secret",
	)); err != nil {
		t.Fatalf("PasswordModify() after config reload: %v", err)
	}
	assertStoredSMPBKDF2Password(t, store, "online-sm3-secret")

	useCrypt := ldap.NewModifyRequest(frontendDN, nil)
	useCrypt.Replace("olcPasswordHash", []string{auth.OpenLDAPCryptHashScheme})
	if err := configClient.Modify(useCrypt); err != nil {
		t.Fatalf("configure CRYPT: %v", err)
	}
	if _, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"online-sm3-secret",
		"online-crypt-secret",
	)); err != nil {
		t.Fatalf("PasswordModify() after CRYPT reload: %v", err)
	}
	assertStoredCryptPassword(t, store, "online-crypt-secret")
	assertStoredCryptPasswordPrefix(
		t,
		store,
		"online-crypt-secret",
		"{CRYPT}$6$rounds=100000$",
	)
	assertBindPassword(t, address, aliceDN, "online-crypt-secret", true)
	assertBindPassword(t, address, aliceDN, "online-sm3-secret", false)

	const customSaltFormat = "$5$rounds=2000$%.16s"
	customSalt := ldap.NewModifyRequest("cn=config", nil)
	customSalt.Replace("olcPasswordCryptSaltFormat", []string{customSaltFormat})
	if err := configClient.Modify(customSalt); err != nil {
		t.Fatalf("configure CRYPT salt format: %v", err)
	}
	if _, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"online-crypt-secret",
		"custom-crypt-secret",
	)); err != nil {
		t.Fatalf("PasswordModify() after salt format reload: %v", err)
	}
	assertStoredCryptPasswordPrefix(
		t,
		store,
		"custom-crypt-secret",
		"{CRYPT}$5$rounds=2000$",
	)

	invalidSalt := ldap.NewModifyRequest("cn=config", nil)
	invalidSalt.Replace("olcPasswordCryptSaltFormat", []string{"fixed-salt"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalidSalt),
		ldap.LDAPResultConstraintViolation,
	)
	if _, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"custom-crypt-secret",
		"salt-rollback-secret",
	)); err != nil {
		t.Fatalf("PasswordModify() after salt rollback: %v", err)
	}
	assertStoredCryptPasswordPrefix(
		t,
		store,
		"salt-rollback-secret",
		"{CRYPT}$5$rounds=2000$",
	)
	global := readStoredEntry(t, store, "cn=config")
	saltValues := global.Values("olcPasswordCryptSaltFormat")
	if len(saltValues) != 1 || string(saltValues[0]) != customSaltFormat {
		t.Fatalf("rolled-back olcPasswordCryptSaltFormat = %q", saltValues)
	}

	invalid := ldap.NewModifyRequest(frontendDN, nil)
	invalid.Replace("olcPasswordHash", []string{"{UNKNOWN}"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	if _, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"salt-rollback-secret",
		"after-rollback-secret",
	)); err != nil {
		t.Fatalf("PasswordModify() after config rollback: %v", err)
	}
	assertStoredCryptPassword(t, store, "after-rollback-secret")

	config := readStoredEntry(t, store, frontendDN)
	values := config.Values("olcPasswordHash")
	if len(values) != 1 || string(values[0]) != auth.OpenLDAPCryptHashScheme {
		t.Fatalf("rolled-back olcPasswordHash = %q", values)
	}
}

func TestLDAPClientPasswordModifyRejectsInvalidRequestData(t *testing.T) {
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
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	emptyValue := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		"",
		"requestValue",
	)
	_, err = client.Extended(ldap.NewExtendedRequest(passwordModifyOID, emptyValue))
	assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)

	for _, tag := range []ber.Tag{1, 2} {
		sequence := ber.NewSequence("PasswordModifyRequestValue")
		sequence.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			tag,
			"",
			"empty password",
		))
		value := ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			1,
			string(sequence.Bytes()),
			"requestValue",
		)
		_, err := client.Extended(ldap.NewExtendedRequest(passwordModifyOID, value))
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	}

	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		"not-a-distinguished-name",
		"",
		"not-stored",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultInvalidDNSyntax)
	assertBindPassword(t, address, aliceDN, "secret", true)
	assertBindPassword(t, address, aliceDN, "not-stored", false)
}

func assertStoredSMPBKDF2Password(
	t *testing.T,
	store storage.Store,
	password string,
) {
	t.Helper()

	entry := readStoredEntry(t, store, aliceDN)
	stored := entry.Values("userPassword")
	if len(stored) != 1 ||
		!strings.HasPrefix(string(stored[0]), auth.SMPBKDF2HashScheme) ||
		!auth.VerifyPassword(stored[0], []byte(password)) {
		t.Fatalf("stored userPassword = %q", stored)
	}
}

func assertBindPassword(
	t *testing.T,
	address, dn, password string,
	want bool,
) {
	t.Helper()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	err = client.Bind(dn, password)
	if want && err != nil {
		t.Fatalf("Bind(%q): %v", password, err)
	}
	if !want {
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}
}

func assertStoredCryptPassword(
	t *testing.T,
	store storage.Store,
	password string,
) {
	t.Helper()

	entry := readStoredEntry(t, store, aliceDN)
	stored := entry.Values("userPassword")
	if len(stored) != 1 ||
		!bytes.HasPrefix(stored[0], []byte(auth.OpenLDAPCryptHashScheme)) ||
		!auth.VerifyPassword(stored[0], []byte(password)) {
		t.Fatalf("stored CRYPT userPassword = %q", stored)
	}
}

func assertStoredCryptPasswordPrefix(
	t *testing.T,
	store storage.Store,
	password,
	prefix string,
) {
	t.Helper()
	entry := readStoredEntry(t, store, aliceDN)
	stored := entry.Values("userPassword")
	if len(stored) != 1 || !bytes.HasPrefix(stored[0], []byte(prefix)) ||
		!auth.VerifyPassword(stored[0], []byte(password)) {
		t.Fatalf("stored CRYPT userPassword = %q, want prefix %q", stored, prefix)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
