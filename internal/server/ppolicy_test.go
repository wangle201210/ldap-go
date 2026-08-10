package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const passwordPolicyDN = "cn=default,ou=policies,dc=example,dc=com"

func TestLoadRuntimeDatabasesLoadsPasswordPolicyOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMaxAge", Values: stringValues("3600")},
		},
		[]directory.Attribute{
			{
				Description: "olcPPolicyHashCleartext",
				Values:      stringValues("TRUE"),
			},
			{
				Description: "olcPPolicyUseLockout",
				Values:      stringValues("TRUE"),
			},
		},
	)

	databases, err := loadRuntimeDatabases(
		context.Background(),
		store,
	)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	dn, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databases[databaseIndexForDN(databases, dn)]
	if database.ppolicy == nil ||
		database.ppolicy.defaultPolicy == nil ||
		database.ppolicy.defaultPolicy.String() != passwordPolicyDN ||
		!database.ppolicy.hashCleartext ||
		!database.ppolicy.useLockout {
		t.Fatalf("password policy database = %#v", database)
	}
}

func TestLoadRuntimeDatabasesRejectsInvalidPasswordPolicyOverlay(
	t *testing.T,
) {
	t.Parallel()

	dataDatabase := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
		},
	}
	frontendDatabase := directory.Entry{
		DN: "olcDatabase={-1}frontend,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcDatabase",
			Values:      stringValues("{-1}frontend"),
		}},
	}
	overlay := func(index, parent string, attributes ...directory.Attribute) directory.Entry {
		entry := directory.Entry{
			DN: "olcOverlay={" + index + "}ppolicy," + parent,
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      stringValues("{" + index + "}ppolicy"),
			}},
		}
		entry.Attributes = append(entry.Attributes, attributes...)
		return entry
	}
	const dataParent = "olcDatabase={1}mdb,cn=config"
	tests := []struct {
		name    string
		entries []directory.Entry
		want    string
	}{
		{
			name: "duplicate overlay",
			entries: []directory.Entry{
				overlay("0", dataParent),
				overlay("1", dataParent),
			},
			want: "duplicate ppolicy overlay",
		},
		{
			name: "global overlay",
			entries: []directory.Entry{
				frontendDatabase,
				overlay("0", frontendDatabase.DN),
			},
			want: "ppolicy overlay cannot be global",
		},
		{
			name: "invalid default policy DN",
			entries: []directory.Entry{overlay(
				"0",
				dataParent,
				directory.Attribute{
					Description: "olcPPolicyDefault",
					Values:      stringValues("not-a-dn"),
				},
			)},
			want: "olcPPolicyDefault",
		},
		{
			name: "multiple default policies",
			entries: []directory.Entry{overlay(
				"0",
				dataParent,
				directory.Attribute{
					Description: "olcPPolicyDefault",
					Values: stringValues(
						"cn=one,dc=example,dc=com",
						"cn=two,dc=example,dc=com",
					),
				},
			)},
			want: "olcPPolicyDefault must be single-valued",
		},
		{
			name: "invalid boolean",
			entries: []directory.Entry{overlay(
				"0",
				dataParent,
				directory.Attribute{
					Description: "olcPPolicyHashCleartext",
					Values:      stringValues("sometimes"),
				},
			)},
			want: "olcPPolicyHashCleartext has invalid value",
		},
		{
			name: "multiple booleans",
			entries: []directory.Entry{overlay(
				"0",
				dataParent,
				directory.Attribute{
					Description: "olcPPolicyUseLockout",
					Values:      stringValues("TRUE", "FALSE"),
				},
			)},
			want: "olcPPolicyUseLockout must be single-valued",
		},
		{
			name: "multiple check modules",
			entries: []directory.Entry{overlay(
				"0",
				dataParent,
				directory.Attribute{
					Description: "olcPPolicyCheckModule",
					Values:      stringValues("one.so", "two.so"),
				},
			)},
			want: "olcPPolicyCheckModule must be single-valued",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if err := writer.Put(dataDatabase, false); err != nil {
					return err
				}
				for _, entry := range test.entries {
					if err := writer.Put(entry, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("seed configuration: %v", err)
			}
			_, err := loadRuntimeDatabases(context.Background(), store)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("loadRuntimeDatabases() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParsePasswordPolicyEntryRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		attributes []directory.Attribute
	}{
		{
			name: "integer overflow",
			attributes: []directory.Attribute{{
				Description: "pwdMaxAge",
				Values:      stringValues("2147483648"),
			}},
		},
		{
			name: "invalid integer",
			attributes: []directory.Attribute{{
				Description: "pwdMaxAge",
				Values:      stringValues("forever"),
			}},
		},
		{
			name: "multiple integers",
			attributes: []directory.Attribute{{
				Description: "pwdMaxAge",
				Values:      stringValues("1", "2"),
			}},
		},
		{
			name: "invalid boolean",
			attributes: []directory.Attribute{{
				Description: "pwdLockout",
				Values:      stringValues("yes"),
			}},
		},
		{
			name: "multiple checker arguments",
			attributes: []directory.Attribute{{
				Description: "pwdCheckModuleArg",
				Values:      stringValues("one", "two"),
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := defaultPasswordPolicy()
			entry := directory.Entry{DN: passwordPolicyDN}
			entry.Attributes = append(entry.Attributes, test.attributes...)
			if err := parsePasswordPolicyEntry(entry, &policy); !errors.Is(err, errInvalidPasswordPolicy) {
				t.Fatalf("parsePasswordPolicyEntry() error = %v", err)
			}
		})
	}
}

func TestPasswordPolicyOnlineConfigurationReloadsAtomically(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
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
			"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
			"{1}to * by self write by users read by * none",
		))
		if err := writer.Put(data, true); err != nil {
			return err
		}
		for _, entry := range []directory.Entry{
			{
				DN: "ou=policies,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("organizationalUnit")},
					{Description: "ou", Values: stringValues("policies")},
				},
			},
			{
				DN: passwordPolicyDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("top", "device", "pwdPolicy")},
					{Description: "cn", Values: stringValues("default")},
					{Description: "pwdAttribute", Values: stringValues("2.5.4.35")},
					{Description: "pwdCheckQuality", Values: stringValues("2")},
					{Description: "pwdMinLength", Values: stringValues("8")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed online password policy: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	user, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(user): %v", err)
	}
	defer user.Close()
	if err := user.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("user Bind(): %v", err)
	}
	replacePassword := func(value string) error {
		request := ldap.NewModifyRequest(aliceDN, nil)
		request.Replace("userPassword", []string{value})
		return user.Modify(request)
	}
	if err := replacePassword("short"); err != nil {
		t.Fatalf("Modify() before ppolicy enable: %v", err)
	}
	if values := readStoredEntry(t, store, aliceDN).Values("userPassword"); len(values) != 1 || string(values[0]) != "short" {
		t.Fatalf("password before ppolicy enable = %q", values)
	}

	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config Bind(): %v", err)
	}
	const overlayDN = "olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
	addOverlay := ldap.NewAddRequest(overlayDN, nil)
	addOverlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	addOverlay.Attribute("olcOverlay", []string{"{0}ppolicy"})
	addOverlay.Attribute("olcPPolicyDefault", []string{passwordPolicyDN})
	addOverlay.Attribute("olcPPolicyHashCleartext", []string{"TRUE"})
	if err := configClient.Add(addOverlay); err != nil {
		t.Fatalf("Add(ppolicy overlay): %v", err)
	}
	assertLDAPResultCode(
		t,
		replacePassword("tiny"),
		ldap.LDAPResultConstraintViolation,
	)
	if err := replacePassword("long-password"); err != nil {
		t.Fatalf("Modify() after ppolicy enable: %v", err)
	}
	stored := readStoredEntry(t, store, aliceDN).Values("userPassword")
	if len(stored) != 1 ||
		bytes.Equal(stored[0], []byte("long-password")) ||
		!auth.VerifyPassword(stored[0], []byte("long-password")) {
		t.Fatalf("hashed password after ppolicy enable = %q", stored)
	}

	invalid := ldap.NewModifyRequest(overlayDN, nil)
	invalid.Replace("olcPPolicyHashCleartext", []string{"sometimes"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	configured := readStoredEntry(t, store, overlayDN).
		Values("olcPPolicyHashCleartext")
	if len(configured) != 1 || string(configured[0]) != "TRUE" {
		t.Fatalf("rolled-back olcPPolicyHashCleartext = %q", configured)
	}
	assertLDAPResultCode(
		t,
		replacePassword("small"),
		ldap.LDAPResultConstraintViolation,
	)

	if err := configClient.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("Delete(ppolicy overlay): %v", err)
	}
	if err := replacePassword("tiny"); err != nil {
		t.Fatalf("Modify() after ppolicy disable: %v", err)
	}
	if values := readStoredEntry(t, store, aliceDN).Values("userPassword"); len(values) != 1 || string(values[0]) != "tiny" {
		t.Fatalf("password after ppolicy disable = %q", values)
	}
}

func TestPasswordPolicyBindLockoutAndUnlock(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdLockout", Values: stringValues("TRUE")},
			{Description: "pwdLockoutDuration", Values: stringValues("0")},
			{Description: "pwdMaxFailure", Values: stringValues("2")},
			{
				Description: "pwdMaxRecordedFailure",
				Values:      stringValues("3"),
			},
		},
		[]directory.Attribute{{
			Description: "olcPPolicyUseLockout",
			Values:      stringValues("TRUE"),
		}},
	)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	requestControl := ldap.NewControlBeheraPasswordPolicy()
	for attempt := 0; attempt < 2; attempt++ {
		_, err = client.SimpleBind(ldap.NewSimpleBindRequest(
			aliceDN,
			"wrong",
			[]ldap.Control{requestControl},
		))
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	}
	result, err := client.SimpleBind(ldap.NewSimpleBindRequest(
		aliceDN,
		"secret",
		[]ldap.Control{requestControl},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	policyControl := requirePasswordPolicyControl(t, result.Controls)
	if policyControl.Error != ldap.BeheraAccountLocked {
		t.Fatalf("password policy error = %d", policyControl.Error)
	}

	entry := readStoredEntry(t, store, aliceDN)
	if len(entry.Values("pwdFailureTime")) != 2 ||
		len(entry.Values("pwdAccountLockedTime")) != 1 {
		t.Fatalf("locked entry = %#v", entry)
	}

	admin, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(admin): %v", err)
	}
	defer admin.Close()
	if err := admin.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		t.Fatalf("admin Bind(): %v", err)
	}
	unlock := ldap.NewModifyRequest(aliceDN, nil)
	unlock.Delete("pwdAccountLockedTime", nil)
	if err := admin.Modify(unlock); err != nil {
		t.Fatalf("unlock Modify(): %v", err)
	}
	entry = readStoredEntry(t, store, aliceDN)
	if entry.HasAttribute("pwdAccountLockedTime") ||
		entry.HasAttribute("pwdFailureTime") {
		t.Fatalf("unlocked entry = %#v", entry)
	}
	assertBindPassword(t, address, aliceDN, "secret", true)
}

func TestPasswordPolicyExpiredPasswordGraceAuthentication(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMaxAge", Values: stringValues("10")},
			{
				Description: "pwdGraceAuthNLimit",
				Values:      stringValues("1"),
			},
		},
		nil,
	)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdChangedTime": stringValues(formatPasswordPolicyTime(
			time.Now().Add(-20 * time.Second),
		)),
	})
	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	requestControl := ldap.NewControlBeheraPasswordPolicy()
	first, err := client.SimpleBind(ldap.NewSimpleBindRequest(
		aliceDN,
		"secret",
		[]ldap.Control{requestControl},
	))
	if err != nil {
		t.Fatalf("first grace Bind(): %v", err)
	}
	if control := requirePasswordPolicyControl(t, first.Controls); control.Grace != 0 || control.Error != -1 {
		t.Fatalf("first grace control = %#v", control)
	}
	second, err := client.SimpleBind(ldap.NewSimpleBindRequest(
		aliceDN,
		"secret",
		[]ldap.Control{requestControl},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	if control := requirePasswordPolicyControl(t, second.Controls); control.Error != ldap.BeheraPasswordExpired {
		t.Fatalf("expired control = %#v", control)
	}
	entry := readStoredEntry(t, store, aliceDN)
	if len(entry.Values("pwdGraceUseTime")) != 1 {
		t.Fatalf("pwdGraceUseTime = %q", entry.Values("pwdGraceUseTime"))
	}
}

func TestPasswordPolicyResetRestrictionQualityAndHistory(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdSafeModify", Values: stringValues("TRUE")},
			{Description: "pwdMustChange", Values: stringValues("TRUE")},
			{Description: "pwdCheckQuality", Values: stringValues("2")},
			{Description: "pwdMinLength", Values: stringValues("8")},
			{Description: "pwdInHistory", Values: stringValues("2")},
		},
		[]directory.Attribute{{
			Description: "olcPPolicyHashCleartext",
			Values:      stringValues("TRUE"),
		}},
	)
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
	if err := admin.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		t.Fatalf("admin Bind(): %v", err)
	}
	if _, err := admin.PasswordModify(ldap.NewPasswordModifyRequest(
		aliceDN,
		"",
		"admin-password",
	)); err != nil {
		t.Fatalf("admin PasswordModify(): %v", err)
	}
	entry := readStoredEntry(t, store, aliceDN)
	if values := entry.Values("pwdReset"); len(values) != 1 || string(values[0]) != "TRUE" {
		t.Fatalf("pwdReset = %q", values)
	}

	user, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(user): %v", err)
	}
	defer user.Close()
	bindResult, err := user.SimpleBind(ldap.NewSimpleBindRequest(
		aliceDN,
		"admin-password",
		[]ldap.Control{ldap.NewControlBeheraPasswordPolicy()},
	))
	if err != nil {
		t.Fatalf("reset Bind(): %v", err)
	}
	if control := requirePasswordPolicyControl(t, bindResult.Controls); control.Error != ldap.BeheraChangeAfterReset {
		t.Fatalf("reset control = %#v", control)
	}
	_, err = user.Search(ldap.NewSearchRequest(
		aliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)

	_, err = user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"admin-password",
		"short",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
	if _, err := user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"admin-password",
		"user-password",
	)); err != nil {
		t.Fatalf("self PasswordModify(): %v", err)
	}
	result, err := user.Search(ldap.NewSearchRequest(
		aliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search() after password change = %#v, %v", result, err)
	}
	_, err = user.PasswordModify(ldap.NewPasswordModifyRequest(
		"",
		"user-password",
		"secret",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)

	entry = readStoredEntry(t, store, aliceDN)
	stored := entry.Values("userPassword")
	if len(stored) != 1 ||
		!auth.VerifyPassword(stored[0], []byte("user-password")) ||
		entry.HasAttribute("pwdReset") ||
		len(entry.Values("pwdHistory")) != 2 {
		t.Fatalf("password-policy entry = %#v", entry)
	}
}

func TestPasswordPolicyModifyFailureResponseControl(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdCheckQuality", Values: stringValues("2")},
			{Description: "pwdMinLength", Values: stringValues("8")},
		},
		nil,
	)
	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
	defer connection.Close()

	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(aliceDN, "userPassword", "short"),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	assertRawLDAPResult(
		t,
		response,
		int64(ldap.LDAPResultConstraintViolation),
	)
	got := rawLDAPResponseControl(t, response, passwordPolicyControlOID)
	want := ldapwire.EncodePasswordPolicyResponseValue(
		-1,
		-1,
		int64(passwordPolicyTooShort),
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("password policy response = %x, want %x", got, want)
	}
	assertBindPassword(t, address, aliceDN, "secret", true)
}

func TestPasswordPolicyPasswordModifyWrongOldPasswordResponseControl(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(t, store, nil, nil)
	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
	defer connection.Close()

	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawExtendedRequest(
			passwordModifyOID,
			rawPasswordModifyRequestValue(
				[]byte("wrong"),
				[]byte("new-password"),
			),
			true,
		),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	assertRawLDAPResult(
		t,
		response,
		int64(ldap.LDAPResultUnwillingToPerform),
	)
	got := rawLDAPResponseControl(t, response, passwordPolicyControlOID)
	want := ldapwire.EncodePasswordPolicyResponseValue(
		-1,
		-1,
		int64(passwordPolicyMustSupplyOldPassword),
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("password policy response = %x, want %x", got, want)
	}
	assertBindPassword(t, address, aliceDN, "secret", true)
}

func TestPasswordPolicyAccountUsabilityControl(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMaxAge", Values: stringValues("3600")},
			{Description: "pwdLockout", Values: stringValues("TRUE")},
			{Description: "pwdLockoutDuration", Values: stringValues("60")},
		},
		nil,
	)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdChangedTime": stringValues(formatPasswordPolicyTime(time.Now())),
	})
	const rootDN = "cn=admin,dc=example,dc=com"
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, rootDN, "admin-secret")
	defer connection.Close()

	available := searchAccountUsability(t, connection, 2)
	if available.ClassType != ber.ClassContext ||
		available.Tag != 0 ||
		available.TagType != ber.TypePrimitive {
		t.Fatalf("available account usability = %#v", available)
	}
	remaining, err := ber.ParseInt64(available.Data.Bytes())
	if err != nil || remaining < 3500 || remaining > 3600 {
		t.Fatalf("seconds remaining = %d, %v", remaining, err)
	}

	lockResponse := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawModifyReplaceRequest(
			aliceDN,
			"pwdAccountLockedTime",
			formatPasswordPolicyTime(time.Now()),
		),
	)
	assertRawLDAPResult(
		t,
		lockResponse,
		int64(ldap.LDAPResultSuccess),
	)
	unavailable := searchAccountUsability(t, connection, 4)
	if unavailable.ClassType != ber.ClassContext ||
		unavailable.Tag != 1 ||
		unavailable.TagType != ber.TypeConstructed ||
		len(unavailable.Children) != 5 {
		t.Fatalf("unavailable account usability = %#v", unavailable)
	}
	if !bytes.Equal(unavailable.Children[0].Data.Bytes(), []byte{0xff}) ||
		!bytes.Equal(unavailable.Children[1].Data.Bytes(), []byte{0x00}) ||
		!bytes.Equal(unavailable.Children[2].Data.Bytes(), []byte{0x00}) {
		t.Fatalf("account usability flags = %#v", unavailable.Children[:3])
	}
	grace, err := ber.ParseInt64(unavailable.Children[3].Data.Bytes())
	if err != nil || grace != -1 {
		t.Fatalf("remaining grace = %d, %v", grace, err)
	}
	unlock, err := ber.ParseInt64(unavailable.Children[4].Data.Bytes())
	if err != nil || unlock <= 0 || unlock > 60 {
		t.Fatalf("seconds before unlock = %d, %v", unlock, err)
	}
}

func TestPasswordPolicyExpiredAccountUsabilityMatchesOpenLDAP(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	entry := directory.Entry{
		DN: aliceDN,
		Attributes: []directory.Attribute{
			{
				Description: "pwdChangedTime",
				Values: stringValues(formatPasswordPolicyTime(
					now.Add(-20 * time.Second),
				)),
			},
			{
				Description: "pwdGraceUseTime",
				Values: stringValues(
					"20260731115950.000000Z",
					"20260731115951.000000Z",
				),
			},
		},
	}
	policy := defaultPasswordPolicy()
	policy.maxAge = 10
	policy.graceAuthentication = 3
	got := encodePasswordPolicyAccountUsability(
		entry,
		policy,
		runtimeDatabase{},
		now,
	)
	want := ldapwire.EncodeAccountUsabilityUnavailable(
		ldapwire.AccountUsabilityMoreInfo{
			RemainingGrace:      2,
			SecondsBeforeUnlock: -1,
		},
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("expired account usability = %x, want %x", got, want)
	}
}

func TestPasswordPolicyWarningAndNetscapeControls(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMaxAge", Values: stringValues("300")},
			{Description: "pwdExpireWarning", Values: stringValues("600")},
		},
		[]directory.Attribute{{
			Description: "olcPPolicySendNetscapeControls",
			Values:      stringValues("TRUE"),
		}},
	)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdChangedTime": stringValues(formatPasswordPolicyTime(time.Now())),
	})
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial password warning server: %v", err)
	}
	response := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(3, aliceDN, "secret"),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	_ = connection.Close()
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	seconds := passwordPolicyWarningSeconds(
		t,
		rawLDAPResponseControl(t, response, passwordPolicyControlOID),
	)
	if seconds < 295 || seconds > 300 {
		t.Fatalf("password expiration warning = %d seconds", seconds)
	}
	if controls := rawLDAPResponseControls(response); len(controls) != 1 {
		t.Fatalf("password policy response controls = %#v", controls)
	}

	connection, err = net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial Netscape warning server: %v", err)
	}
	response = sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(3, aliceDN, "secret"),
	)
	_ = connection.Close()
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	controls := rawLDAPResponseControls(response)
	warning, exists := controls[netscapePasswordExpiringOID]
	if !exists {
		t.Fatalf("Netscape expiring control missing from %#v", controls)
	}
	warningSeconds, err := strconv.Atoi(string(warning))
	if err != nil || warningSeconds < 295 || warningSeconds > 300 {
		t.Fatalf("Netscape expiration warning = %q, %v", warning, err)
	}
	if _, exists := controls[passwordPolicyControlOID]; exists {
		t.Fatalf("unsolicited password policy control = %#v", controls)
	}
}

func TestPasswordPolicyAccountValidityDelayAndIdle(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	policy := defaultPasswordPolicy()
	policy.lockout = true
	policy.lockoutDuration = 60
	policy.maxIdle = 120
	database := runtimeDatabase{lastBind: true}
	tests := []struct {
		name   string
		values map[string][][]byte
		locked bool
	}{
		{
			name: "not started",
			values: map[string][][]byte{
				"pwdStartTime": stringValues(formatPasswordPolicyTime(
					now.Add(time.Minute),
				)),
			},
			locked: true,
		},
		{
			name: "ended",
			values: map[string][][]byte{
				"pwdEndTime": stringValues(formatPasswordPolicyTime(now)),
			},
			locked: true,
		},
		{
			name: "temporary delay",
			values: map[string][][]byte{
				"pwdAccountTmpLockoutEnd": stringValues(
					formatPasswordPolicyTime(now.Add(time.Minute)),
				),
			},
			locked: true,
		},
		{
			name: "idle using last success",
			values: map[string][][]byte{
				"pwdLastSuccess": stringValues(formatPasswordPolicyTime(
					now.Add(-121 * time.Second),
				)),
			},
			locked: true,
		},
		{
			name: "idle fallback to changed time",
			values: map[string][][]byte{
				"pwdChangedTime": stringValues(formatPasswordPolicyTime(
					now.Add(-121 * time.Second),
				)),
			},
			locked: true,
		},
		{
			name: "active",
			values: map[string][][]byte{
				"pwdLastSuccess": stringValues(formatPasswordPolicyTime(
					now.Add(-119 * time.Second),
				)),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{DN: aliceDN}
			for description, values := range test.values {
				entry.ReplaceValues(description, values)
			}
			locked, _ := evaluatePasswordPolicyAccountLock(
				entry,
				policy,
				database,
				now,
			)
			if locked != test.locked {
				t.Fatalf("account locked = %t, want %t", locked, test.locked)
			}
		})
	}

	entry := directory.Entry{DN: aliceDN}
	delayPolicy := defaultPasswordPolicy()
	delayPolicy.minDelay = 30
	delayPolicy.maxDelay = 120
	delayPolicy.maxRecordedFailure = 5
	applyPasswordPolicyBindFailure(&entry, delayPolicy, now)
	first, present := singlePasswordPolicyTime(entry, "pwdAccountTmpLockoutEnd")
	firstEnd, valid := parsePasswordPolicyTime(first)
	if !present || !valid || !firstEnd.Equal(now.Add(30*time.Second)) {
		t.Fatalf("first temporary lockout = %q", first)
	}
	applyPasswordPolicyBindFailure(&entry, delayPolicy, now.Add(time.Second))
	second, _ := singlePasswordPolicyTime(entry, "pwdAccountTmpLockoutEnd")
	secondEnd, valid := parsePasswordPolicyTime(second)
	if !valid || !secondEnd.Equal(now.Add(61*time.Second)) {
		t.Fatalf("second temporary lockout = %q", second)
	}

	resetEntry := directory.Entry{DN: aliceDN}
	resetEntry.ReplaceValues("pwdReset", stringValues("TRUE"))
	resetEntry.ReplaceValues(
		"pwdChangedTime",
		stringValues(formatPasswordPolicyTime(now)),
	)
	resetPolicy := defaultPasswordPolicy()
	resetPolicy.mustChange = true
	resetPolicy.maxAge = 300
	resetPolicy.expireWarning = 600
	resetEvaluation := passwordBindEvaluation{
		policyError:          passwordPolicyNoError,
		expirationSeconds:    -1,
		graceAuthentications: -1,
		authenticated:        true,
	}
	evaluateSuccessfulPasswordPolicyBind(
		&resetEntry,
		resetPolicy,
		now,
		&resetEvaluation,
		true,
	)
	if !resetEvaluation.authenticated ||
		!resetEvaluation.restricted ||
		resetEvaluation.policyError != passwordPolicyChangeAfterReset ||
		resetEvaluation.expirationSeconds != 300 {
		t.Fatalf("reset warning evaluation = %#v", resetEvaluation)
	}
}

func TestPasswordPolicyStateBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	lockPolicy := defaultPasswordPolicy()
	lockPolicy.lockout = true
	lockPolicy.lockoutDuration = 60
	lockedEntry := directory.Entry{DN: aliceDN}
	lockedEntry.ReplaceValues(
		"pwdAccountLockedTime",
		stringValues(formatPasswordPolicyTime(now.Add(-60*time.Second))),
	)
	locked, clearLock := evaluatePasswordPolicyAccountLock(
		lockedEntry,
		lockPolicy,
		runtimeDatabase{},
		now,
	)
	if locked || !clearLock {
		t.Fatalf("expired timed lock = locked %t, clear %t", locked, clearLock)
	}

	failurePolicy := defaultPasswordPolicy()
	failurePolicy.maxFailure = 2
	failurePolicy.maxRecordedFailure = 2
	failurePolicy.failureCountInterval = 60
	failureEntry := directory.Entry{DN: aliceDN}
	failureEntry.ReplaceValues("pwdFailureTime", stringValues(
		formatPasswordPolicyFailureTime(now.Add(-61*time.Second)),
		formatPasswordPolicyFailureTime(now.Add(-30*time.Second)),
	))
	applyPasswordPolicyBindFailure(&failureEntry, failurePolicy, now)
	if len(failureEntry.Values("pwdFailureTime")) != 2 ||
		len(failureEntry.Values("pwdAccountLockedTime")) != 1 {
		t.Fatalf("windowed failure state = %#v", failureEntry)
	}

	graceEntry := directory.Entry{DN: aliceDN}
	graceEntry.ReplaceValues(
		"pwdChangedTime",
		stringValues(formatPasswordPolicyTime(now.Add(-20*time.Second))),
	)
	gracePolicy := defaultPasswordPolicy()
	gracePolicy.maxAge = 10
	gracePolicy.graceAuthentication = 5
	gracePolicy.graceExpiry = 5
	graceEvaluation := passwordBindEvaluation{
		policyError:          passwordPolicyNoError,
		expirationSeconds:    -1,
		graceAuthentications: -1,
		authenticated:        true,
	}
	evaluateSuccessfulPasswordPolicyBind(
		&graceEntry,
		gracePolicy,
		now,
		&graceEvaluation,
		true,
	)
	if graceEvaluation.authenticated ||
		graceEvaluation.policyError != passwordPolicyPasswordExpired ||
		graceEvaluation.graceAuthentications != -1 ||
		graceEntry.HasAttribute("pwdGraceUseTime") {
		t.Fatalf("expired grace window = %#v, entry %#v", graceEvaluation, graceEntry)
	}

	qualityPolicy := defaultPasswordPolicy()
	qualityPolicy.checkQuality = 2
	qualityPolicy.maxLength = 8
	if got := checkPasswordPolicyQuality(
		[]byte("ninechars"),
		qualityPolicy,
	); got != passwordPolicyTooLong {
		t.Fatalf("maximum-length quality result = %d", got)
	}
}

func TestPasswordPolicyLastBindAndMaxIdle(t *testing.T) {
	t.Parallel()

	t.Run("records successful bind with configured precision", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedPasswordPolicyDirectory(
			t,
			store,
			[]directory.Attribute{
				{Description: "pwdLockout", Values: stringValues("TRUE")},
				{Description: "pwdMaxIdle", Values: stringValues("600")},
			},
			nil,
		)
		setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
			"pwdChangedTime": stringValues(formatPasswordPolicyTime(time.Now())),
		})
		setPasswordPolicyEntryValues(
			t,
			store,
			"olcDatabase={1}mdb,cn=config",
			map[string][][]byte{
				"olcLastBind":          stringValues("TRUE"),
				"olcLastBindPrecision": stringValues("3600"),
			},
		)
		address, stop := startServer(t, store, Config{})
		defer stop()
		assertBindPassword(t, address, aliceDN, "secret", true)
		first := readStoredEntry(t, store, aliceDN).Values("pwdLastSuccess")
		if len(first) != 1 {
			t.Fatalf("pwdLastSuccess = %q", first)
		}
		assertBindPassword(t, address, aliceDN, "secret", true)
		second := readStoredEntry(t, store, aliceDN).Values("pwdLastSuccess")
		if len(second) != 1 || !bytes.Equal(first[0], second[0]) {
			t.Fatalf("precision changed pwdLastSuccess from %q to %q", first, second)
		}
	})

	t.Run("rejects idle account", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedPasswordPolicyDirectory(
			t,
			store,
			[]directory.Attribute{
				{Description: "pwdLockout", Values: stringValues("TRUE")},
				{Description: "pwdMaxIdle", Values: stringValues("10")},
			},
			nil,
		)
		setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
			"pwdChangedTime": stringValues(formatPasswordPolicyTime(
				time.Now().Add(-20 * time.Second),
			)),
		})
		setPasswordPolicyEntryValues(
			t,
			store,
			"olcDatabase={1}mdb,cn=config",
			map[string][][]byte{"olcLastBind": stringValues("TRUE")},
		)
		address, stop := startServer(t, store, Config{})
		defer stop()
		assertBindPassword(t, address, aliceDN, "secret", false)
	})
}

func TestPasswordPolicySelfModificationRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		policyAttributes []directory.Attribute
		state            map[string][][]byte
		wantCode         int64
		wantPolicyError  passwordPolicyError
	}{
		{
			name: "safe modify requires old password",
			policyAttributes: []directory.Attribute{{
				Description: "pwdSafeModify",
				Values:      stringValues("TRUE"),
			}},
			wantCode:        int64(ldap.LDAPResultInsufficientAccessRights),
			wantPolicyError: passwordPolicyMustSupplyOldPassword,
		},
		{
			name: "user change disabled",
			policyAttributes: []directory.Attribute{{
				Description: "pwdAllowUserChange",
				Values:      stringValues("FALSE"),
			}},
			wantCode:        int64(ldap.LDAPResultInsufficientAccessRights),
			wantPolicyError: passwordPolicyModificationNotAllowed,
		},
		{
			name: "minimum age",
			policyAttributes: []directory.Attribute{{
				Description: "pwdMinAge",
				Values:      stringValues("300"),
			}},
			state: map[string][][]byte{
				"pwdChangedTime": stringValues(formatPasswordPolicyTime(time.Now())),
			},
			wantCode:        int64(ldap.LDAPResultConstraintViolation),
			wantPolicyError: passwordPolicyTooYoung,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedPasswordPolicyDirectory(
				t,
				store,
				test.policyAttributes,
				nil,
			)
			if test.state != nil {
				setPasswordPolicyEntryValues(t, store, aliceDN, test.state)
			}
			address, stop := startServer(t, store, Config{})
			defer stop()
			connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
			defer connection.Close()
			response := sendRawLDAPOperation(
				t,
				connection,
				2,
				rawModifyReplaceRequest(
					aliceDN,
					"userPassword",
					"long-password",
				),
				rawControlWithoutValue(passwordPolicyControlOID),
			)
			assertRawLDAPResult(t, response, test.wantCode)
			want := ldapwire.EncodePasswordPolicyResponseValue(
				-1,
				-1,
				int64(test.wantPolicyError),
			)
			if got := rawLDAPResponseControl(
				t,
				response,
				passwordPolicyControlOID,
			); !bytes.Equal(got, want) {
				t.Fatalf("password policy response = %x, want %x", got, want)
			}
		})
	}
}

func TestPasswordPolicySubentrySelection(t *testing.T) {
	t.Parallel()

	const strictPolicyDN = "cn=strict,ou=policies,dc=example,dc=com"
	tests := []struct {
		name       string
		assignedDN string
		wantCode   int64
	}{
		{
			name:       "explicit policy overrides default",
			assignedDN: strictPolicyDN,
			wantCode:   int64(ldap.LDAPResultConstraintViolation),
		},
		{
			name:       "missing explicit policy disables policy",
			assignedDN: "cn=missing,ou=policies,dc=example,dc=com",
			wantCode:   int64(ldap.LDAPResultSuccess),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedPasswordPolicyDirectory(
				t,
				store,
				[]directory.Attribute{
					{Description: "pwdCheckQuality", Values: stringValues("2")},
					{Description: "pwdMinLength", Values: stringValues("8")},
				},
				nil,
			)
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return writer.Put(directory.Entry{
					DN: strictPolicyDN,
					Attributes: []directory.Attribute{
						{
							Description: "objectClass",
							Values:      stringValues("top", "device", "pwdPolicy"),
						},
						{Description: "cn", Values: stringValues("strict")},
						{Description: "pwdAttribute", Values: stringValues("2.5.4.35")},
						{Description: "pwdCheckQuality", Values: stringValues("2")},
						{Description: "pwdMinLength", Values: stringValues("12")},
					},
				}, false)
			}); err != nil {
				t.Fatalf("seed strict password policy: %v", err)
			}
			setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
				"pwdPolicySubentry": stringValues(test.assignedDN),
			})
			address, stop := startServer(t, store, Config{})
			defer stop()
			connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
			defer connection.Close()
			response := sendRawLDAPOperation(
				t,
				connection,
				2,
				rawModifyReplaceRequest(
					aliceDN,
					"userPassword",
					"ninechars",
				),
				rawControlWithoutValue(passwordPolicyControlOID),
			)
			assertRawLDAPResult(t, response, test.wantCode)
			if test.wantCode == int64(ldap.LDAPResultConstraintViolation) {
				want := ldapwire.EncodePasswordPolicyResponseValue(
					-1,
					-1,
					int64(passwordPolicyTooShort),
				)
				if got := rawLDAPResponseControl(
					t,
					response,
					passwordPolicyControlOID,
				); !bytes.Equal(got, want) {
					t.Fatalf("explicit policy response = %x, want %x", got, want)
				}
			}
		})
	}
}

func TestPasswordPolicyAddQualityHashAndDisableWrite(t *testing.T) {
	t.Parallel()

	t.Run("add quality and hash", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedPasswordPolicyDirectory(
			t,
			store,
			[]directory.Attribute{
				{Description: "pwdMinAge", Values: stringValues("1")},
				{Description: "pwdCheckQuality", Values: stringValues("2")},
				{Description: "pwdMinLength", Values: stringValues("8")},
			},
			[]directory.Attribute{{
				Description: "olcPPolicyHashCleartext",
				Values:      stringValues("TRUE"),
			}},
		)
		setPasswordPolicyEntryValues(
			t,
			store,
			"olcDatabase={1}mdb,cn=config",
			map[string][][]byte{
				"olcAccess": stringValues(
					"{0}to * by users write by anonymous auth by * none",
				),
			},
		)
		address, stop := startServer(t, store, Config{})
		defer stop()
		connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
		defer connection.Close()

		entry := passwordPolicyTestPerson("short-add", "short")
		response := sendRawLDAPOperation(
			t,
			connection,
			2,
			rawAddRequest(entry),
			rawControlWithoutValue(passwordPolicyControlOID),
		)
		assertRawLDAPResult(
			t,
			response,
			int64(ldap.LDAPResultConstraintViolation),
		)
		want := ldapwire.EncodePasswordPolicyResponseValue(
			-1,
			-1,
			int64(passwordPolicyTooShort),
		)
		if got := rawLDAPResponseControl(
			t,
			response,
			passwordPolicyControlOID,
		); !bytes.Equal(got, want) {
			t.Fatalf("Add password policy response = %x, want %x", got, want)
		}

		entry = passwordPolicyTestPerson("long-add", "long-password")
		response = sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(entry),
		)
		assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
		stored := readStoredEntry(t, store, entry.DN)
		passwords := stored.Values("userPassword")
		if len(passwords) != 1 ||
			bytes.Equal(passwords[0], []byte("long-password")) ||
			!auth.VerifyPassword(passwords[0], []byte("long-password")) ||
			len(stored.Values("pwdChangedTime")) != 1 {
			t.Fatalf("stored password-policy Add entry = %#v", stored)
		}
	})

	t.Run("disable write bypasses modify policy and bind state", func(t *testing.T) {
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedPasswordPolicyDirectory(
			t,
			store,
			[]directory.Attribute{
				{Description: "pwdCheckQuality", Values: stringValues("2")},
				{Description: "pwdMinLength", Values: stringValues("20")},
				{Description: "pwdMaxRecordedFailure", Values: stringValues("3")},
			},
			[]directory.Attribute{{
				Description: "olcPPolicyDisableWrite",
				Values:      stringValues("TRUE"),
			}},
		)
		address, stop := startServer(t, store, Config{})
		defer stop()
		user, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatalf("DialURL(disable write): %v", err)
		}
		if err := user.Bind(aliceDN, "secret"); err != nil {
			user.Close()
			t.Fatalf("Bind(disable write): %v", err)
		}
		modify := ldap.NewModifyRequest(aliceDN, nil)
		modify.Replace("userPassword", []string{"short"})
		if err := user.Modify(modify); err != nil {
			user.Close()
			t.Fatalf("Modify(disable write): %v", err)
		}
		_ = user.Close()
		assertBindPassword(t, address, aliceDN, "wrong", false)
		stored := readStoredEntry(t, store, aliceDN)
		if values := stored.Values("userPassword"); len(values) != 1 ||
			string(values[0]) != "short" {
			t.Fatalf("disable-write password = %q", values)
		}
		if stored.HasAttribute("pwdFailureTime") ||
			stored.HasAttribute("pwdChangedTime") {
			t.Fatalf("disable-write state = %#v", stored)
		}
	})
}

func TestPasswordPolicyControlParsing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		oid       string
		supported requestControlSupport
	}{
		{
			name:      "password policy",
			oid:       passwordPolicyControlOID,
			supported: supportsPasswordPolicy,
		},
		{
			name:      "account usability",
			oid:       accountUsabilityControlOID,
			supported: supportsAccountUsability,
		},
	} {
		t.Run(test.name+" value", func(t *testing.T) {
			_, result := parseRequestControls(
				[]ldapwire.Control{{
					OID:      test.oid,
					HasValue: true,
					Value:    nil,
				}},
				test.supported,
			)
			if result == nil || result.Code != ldapwire.ResultProtocolError ||
				!strings.Contains(result.DiagnosticMessage, "value not absent") {
				t.Fatalf("control value result = %#v", result)
			}
		})
		t.Run(test.name+" duplicate", func(t *testing.T) {
			control := ldapwire.Control{OID: test.oid}
			_, result := parseRequestControls(
				[]ldapwire.Control{control, control},
				test.supported,
			)
			if result == nil || result.Code != ldapwire.ResultProtocolError ||
				!strings.Contains(result.DiagnosticMessage, "multiple times") {
				t.Fatalf("duplicate control result = %#v", result)
			}
		})
	}
}

func TestPasswordPolicyCheckerAndForwardWriteSafety(t *testing.T) {
	t.Parallel()

	checkerPolicy := defaultPasswordPolicy()
	checkerPolicy.checkQuality = 2
	checkerPolicy.useCheckModule = true
	if got := checkPasswordPolicyQuality(
		[]byte("valid-length-password"),
		checkerPolicy,
	); got != passwordPolicyInsufficientQuality {
		t.Fatalf("missing checker quality result = %d", got)
	}
	checkerPolicy.checkQuality = 1
	if got := checkPasswordPolicyQuality(
		[]byte("{SSHA}uninspectable"),
		checkerPolicy,
	); got != passwordPolicyNoError {
		t.Fatalf("optional hashed checker quality result = %d", got)
	}
	checkerPolicy.checkQuality = 0
	if got := checkPasswordPolicyQuality(
		[]byte("valid-length-password"),
		checkerPolicy,
	); got != passwordPolicyNoError {
		t.Fatalf("disabled checker quality result = %d", got)
	}

	configuration := &passwordPolicyRuntimeConfiguration{}
	for _, test := range []struct {
		name     string
		database runtimeDatabase
		want     bool
	}{
		{
			name:     "ordinary database",
			database: runtimeDatabase{ppolicy: configuration},
			want:     true,
		},
		{
			name: "disabled writes",
			database: runtimeDatabase{ppolicy: &passwordPolicyRuntimeConfiguration{
				disableWrite: true,
			}},
		},
		{
			name: "shadow local writes",
			database: runtimeDatabase{
				shadow:  true,
				ppolicy: configuration,
			},
			want: true,
		},
		{
			name: "shadow forwarded writes",
			database: runtimeDatabase{
				shadow: true,
				ppolicy: &passwordPolicyRuntimeConfiguration{
					forwardUpdates: true,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := passwordPolicyWritesLocally(test.database); got != test.want {
				t.Fatalf("passwordPolicyWritesLocally() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPasswordPolicyConfiguredCheckerFailsClosed(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdCheckQuality", Values: stringValues("1")},
			{Description: "pwdUseCheckModule", Values: stringValues("TRUE")},
		},
		[]directory.Attribute{{
			Description: "olcPPolicyCheckModule",
			Values:      stringValues("check_password.so"),
		}},
	)
	setPasswordPolicyEntryValues(t, store, passwordPolicyDN, map[string][][]byte{
		"objectClass": stringValues(
			"top",
			"device",
			"pwdPolicy",
			"pwdPolicyChecker",
		),
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawModifyReplaceRequest(
			aliceDN,
			"userPassword",
			"valid-length-password",
		),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	assertRawLDAPResult(
		t,
		response,
		int64(ldap.LDAPResultConstraintViolation),
	)
	want := ldapwire.EncodePasswordPolicyResponseValue(
		-1,
		-1,
		int64(passwordPolicyInsufficientQuality),
	)
	if got := rawLDAPResponseControl(
		t,
		response,
		passwordPolicyControlOID,
	); !bytes.Equal(got, want) {
		t.Fatalf("configured checker response = %x, want %x", got, want)
	}
}

func TestPasswordPolicyTransactionPasswordChangeClearsRestriction(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedPasswordPolicyDirectory(
		t,
		store,
		[]directory.Attribute{
			{Description: "pwdMustChange", Values: stringValues("TRUE")},
		},
		nil,
	)
	setPasswordPolicyEntryValues(t, store, aliceDN, map[string][][]byte{
		"pwdReset": stringValues("TRUE"),
	})
	address, stop := startServer(t, store, Config{})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, aliceDN, "secret")
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	queued := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawExtendedRequest(
			passwordModifyOID,
			rawPasswordModifyRequestValue(
				[]byte("secret"),
				[]byte("transaction-password"),
			),
			true,
		),
		rawTransactionSpecificationControl(identifier, true, true),
		rawControlWithoutValue(passwordPolicyControlOID),
	)
	assertRawLDAPResult(t, queued, int64(ldap.LDAPResultSuccess))
	committed := endRawLDAPTransaction(t, connection, 4, true, identifier)
	assertRawLDAPResult(t, committed, int64(ldap.LDAPResultSuccess))

	compare := sendRawLDAPOperation(
		t,
		connection,
		5,
		rawDontUseCopyCompareRequest(aliceDN, "uid", "alice"),
	)
	assertRawLDAPResult(t, compare, int64(ldap.LDAPResultCompareTrue))
	assertBindPassword(
		t,
		address,
		aliceDN,
		"transaction-password",
		true,
	)
}

func passwordPolicyWarningSeconds(t *testing.T, value []byte) int64 {
	t.Helper()
	packet, err := ber.DecodePacketErr(value)
	if err != nil || len(packet.Children) != 1 ||
		packet.Children[0].ClassType != ber.ClassContext ||
		packet.Children[0].Tag != 0 ||
		len(packet.Children[0].Children) != 1 ||
		packet.Children[0].Children[0].Tag != 0 {
		t.Fatalf("password policy warning value = %x, %v", value, err)
	}
	seconds, err := ber.ParseInt64(
		packet.Children[0].Children[0].Data.Bytes(),
	)
	if err != nil {
		t.Fatalf("parse password policy warning: %v", err)
	}
	return seconds
}

func passwordPolicyTestPerson(uid, password string) directory.Entry {
	return directory.Entry{
		DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues("Policy Test")},
			{Description: "sn", Values: stringValues("Test")},
			{Description: "userPassword", Values: stringValues(password)},
		},
	}
}

func searchAccountUsability(
	t *testing.T,
	connection net.Conn,
	messageID int64,
) *ber.Packet {
	t.Helper()

	writeRawLDAPRequest(
		t,
		connection,
		messageID,
		rawSyncSearchRequestFor(
			t,
			aliceDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		rawControlWithoutValue(accountUsabilityControlOID),
	)
	entry := readRawLDAPPacket(t, connection)
	if len(entry.Children) < 2 ||
		entry.Children[1].Tag != ldapwire.ApplicationSearchResultEntry {
		t.Fatalf("account usability SearchResultEntry = %#v", entry)
	}
	value := rawLDAPResponseControl(t, entry, accountUsabilityControlOID)
	done := readRawLDAPPacket(t, connection)
	if len(done.Children) < 2 ||
		done.Children[1].Tag != ldapwire.ApplicationSearchResultDone {
		t.Fatalf("account usability SearchResultDone = %#v", done)
	}
	if code := rawLDAPResultCode(t, done.Children[1]); code != int64(ldap.LDAPResultSuccess) {
		t.Fatalf("account usability result code = %d", code)
	}
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		t.Fatalf("decode account usability control: %v", err)
	}
	return packet
}

func rawControlWithoutValue(oid string) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(rawOctetString([]byte(oid)))
	return control
}

func requirePasswordPolicyControl(
	t *testing.T,
	controls []ldap.Control,
) *ldap.ControlBeheraPasswordPolicy {
	t.Helper()
	control, ok := ldap.FindControl(
		controls,
		ldap.ControlTypeBeheraPasswordPolicy,
	).(*ldap.ControlBeheraPasswordPolicy)
	if !ok {
		t.Fatalf("password policy control missing from %#v", controls)
	}
	return control
}

func seedPasswordPolicyDirectory(
	t *testing.T,
	store storage.Store,
	policyAttributes []directory.Attribute,
	overlayAttributes []directory.Attribute,
) {
	t.Helper()
	seedDirectory(t, store)
	policy := directory.Entry{
		DN: passwordPolicyDN,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: stringValues(
					"top",
					"device",
					"pwdPolicy",
				),
			},
			{Description: "cn", Values: stringValues("default")},
			{
				Description: "pwdAttribute",
				Values:      stringValues("2.5.4.35"),
			},
		},
	}
	policy.Attributes = append(policy.Attributes, policyAttributes...)
	overlay := directory.Entry{
		DN: "olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcOverlay",
				Values:      stringValues("{0}ppolicy"),
			},
			{
				Description: "olcPPolicyDefault",
				Values:      stringValues(passwordPolicyDN),
			},
		},
	}
	overlay.Attributes = append(overlay.Attributes, overlayAttributes...)
	entries := []directory.Entry{
		{
			DN: "ou=policies,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("organizationalUnit"),
				},
				{
					Description: "ou",
					Values:      stringValues("policies"),
				},
			},
		},
		policy,
		overlay,
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed password policy: %v", err)
	}
}

func setPasswordPolicyEntryValues(
	t *testing.T,
	store storage.Store,
	rawDN string,
	values map[string][][]byte,
) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		for description, attributeValues := range values {
			entry.ReplaceValues(description, attributeValues)
		}
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set password policy entry values: %v", err)
	}
}
