package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const testConstraintOverlayDN = "olcOverlay={0}constraint,olcDatabase={1}mdb,cn=config"

func TestConstraintOverlayOnlineLifecycleAndWrites(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}
	address, stop := startServer(t, store, config)

	configClient := bindConstraintClient(
		t,
		address,
		"cn=config",
		"config-secret",
	)
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	for _, uid := range []string{"allowed", "mailbad", "sizebad", "jane"} {
		if err := dataClient.Add(constraintCatalogAdd(uid)); err != nil {
			t.Fatalf("Add(catalog %s): %v", uid, err)
		}
	}

	addOverlay := ldap.NewAddRequest(testConstraintOverlayDN, nil)
	addOverlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	addOverlay.Attribute("olcOverlay", []string{"{0}constraint"})
	addOverlay.Attribute("olcConstraintAttribute", constraintTestRules(false))
	if err := configClient.Add(addOverlay); err != nil {
		t.Fatalf("Add(constraint overlay): %v", err)
	}

	validDN := "uid=allowed,ou=people,dc=example,dc=com"
	valid := constraintPersonAdd(validDN, "allowed", "John", "Doe")
	valid.Attribute("mail", []string{"john.doe@example.com"})
	valid.Attribute("description", []string{"one", "two"})
	valid.Attribute("jpegPhoto", []string{"1234"})
	if err := dataClient.Add(valid); err != nil {
		t.Fatalf("Add(valid constrained entry): %v", err)
	}

	badMail := ldap.NewModifyRequest(validDN, nil)
	badMail.Add("mail", []string{"john@invalid.test"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(badMail),
		ldap.LDAPResultConstraintViolation,
	)
	blockedMail := ldap.NewModifyRequest(validDN, nil)
	blockedMail.Add("mail", []string{"blocked@example.com"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(blockedMail),
		ldap.LDAPResultConstraintViolation,
	)
	oversizedPhoto := ldap.NewModifyRequest(validDN, nil)
	oversizedPhoto.Replace("jpegPhoto", []string{"12345"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(oversizedPhoto),
		ldap.LDAPResultConstraintViolation,
	)
	tooManyDescriptions := ldap.NewModifyRequest(validDN, nil)
	tooManyDescriptions.Add("description", []string{"three"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(tooManyDescriptions),
		ldap.LDAPResultConstraintViolation,
	)
	wrongName := ldap.NewModifyRequest(validDN, nil)
	wrongName.Replace("cn", []string{"John Wrong"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(wrongName),
		ldap.LDAPResultConstraintViolation,
	)

	stored := readStoredEntry(t, store, validDN)
	if values := stored.Values("mail"); len(values) != 1 ||
		string(values[0]) != "john.doe@example.com" {
		t.Fatalf("mail after rejected modifications = %q", values)
	}
	if values := stored.Values("description"); len(values) != 2 {
		t.Fatalf("description after rejected count = %q", values)
	}
	if values := stored.Values("cn"); len(values) != 1 ||
		string(values[0]) != "John Doe" {
		t.Fatalf("cn after rejected set = %q", values)
	}

	deleteDescription := ldap.NewModifyRequest(validDN, nil)
	deleteDescription.Delete("description", []string{"one"})
	if err := dataClient.Modify(deleteDescription); err != nil {
		t.Fatalf("Modify(delete constrained value): %v", err)
	}
	if err := dataClient.Modify(tooManyDescriptions); err != nil {
		t.Fatalf("Modify(add after count deletion): %v", err)
	}

	missingCatalog := constraintPersonAdd(
		"uid=missing,ou=people,dc=example,dc=com",
		"missing",
		"Missing",
		"User",
	)
	missingCatalog.Attribute("mail", []string{"missing@example.com"})
	assertLDAPResultCode(
		t,
		dataClient.Add(missingCatalog),
		ldap.LDAPResultConstraintViolation,
	)

	restrictedOut := constraintPersonAdd(
		"uid=outside,ou=archive,dc=example,dc=com",
		"outside",
		"Outside",
		"User",
	)
	restrictedOut.Attribute("mail", []string{"not-an-address"})
	restrictedOut.Attribute("description", []string{"one", "two", "three"})
	restrictedOut.Attribute("jpegPhoto", []string{"far-too-large"})
	if err := dataClient.Add(restrictedOut); err != nil {
		t.Fatalf("Add(entry outside restrict URI): %v", err)
	}

	relaxed := constraintPersonAdd(
		"uid=relaxed,ou=people,dc=example,dc=com",
		"relaxed",
		"Relaxed",
		"User",
	)
	relaxed.Controls = []ldap.Control{relaxLDAPControl()}
	relaxed.Attribute("mail", []string{"invalid"})
	relaxed.Attribute("description", []string{"one", "two", "three"})
	relaxed.Attribute("jpegPhoto", []string{"far-too-large"})
	if err := dataClient.Add(relaxed); err != nil {
		t.Fatalf("Add(with Relax): %v", err)
	}

	janeDN := "cn=Jane Roe,ou=people,dc=example,dc=com"
	jane := constraintPersonAdd(janeDN, "jane", "Jane", "Roe")
	jane.Attribute("mail", []string{"jane@example.com"})
	if err := dataClient.Add(jane); err != nil {
		t.Fatalf("Add(rename source): %v", err)
	}
	rename := ldap.NewModifyDNRequest(
		janeDN,
		"cn=Jane Wrong",
		true,
		"",
	)
	assertLDAPResultCode(
		t,
		dataClient.ModifyDN(rename),
		ldap.LDAPResultConstraintViolation,
	)
	_ = readStoredEntry(t, store, janeDN)
	relaxedRename := ldap.NewModifyDNRequest(
		janeDN,
		"cn=Jane Wrong",
		true,
		"",
	)
	relaxedRename.Controls = []ldap.Control{relaxLDAPControl()}
	if err := dataClient.ModifyDN(relaxedRename); err != nil {
		t.Fatalf("ModifyDN(with Relax): %v", err)
	}

	updatedRules := constraintTestRules(true)
	updateOverlay := ldap.NewModifyRequest(testConstraintOverlayDN, nil)
	updateOverlay.Replace("olcConstraintAttribute", updatedRules)
	if err := configClient.Modify(updateOverlay); err != nil {
		t.Fatalf("Modify(constraint overlay): %v", err)
	}
	otherDomain := ldap.NewModifyRequest(validDN, nil)
	otherDomain.Add("mail", []string{"john@other.test"})
	if err := dataClient.Modify(otherDomain); err != nil {
		t.Fatalf("Modify(after online constraint update): %v", err)
	}

	invalidConfig := ldap.NewModifyRequest(testConstraintOverlayDN, nil)
	invalidConfig.Replace("olcConstraintAttribute", []string{
		"undefinedConstraintAttribute count 1",
	})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalidConfig),
		ldap.LDAPResultConstraintViolation,
	)
	configured := readStoredEntry(t, store, testConstraintOverlayDN).
		Values("olcConstraintAttribute")
	if len(configured) != len(updatedRules) {
		t.Fatalf("constraint config rollback values = %q", configured)
	}
	assertLDAPResultCode(
		t,
		dataClient.Modify(blockedMail),
		ldap.LDAPResultConstraintViolation,
	)

	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	restartBlocked := ldap.NewModifyRequest(validDN, nil)
	restartBlocked.Add("mail", []string{"blocked@example.com"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(restartBlocked),
		ldap.LDAPResultConstraintViolation,
	)
}

func constraintTestRules(looseMail bool) []string {
	restrict := " restrict=\"ldap:///ou=people,dc=example,dc=com??one?" +
		"(objectClass=inetOrgPerson)\""
	mailPattern := "^[[:alnum:]._-]+@example[.]com$"
	if looseMail {
		mailPattern = ".*"
	}
	return []string{
		"{0}mail regex \"" + mailPattern + "\"" + restrict,
		"{1}mail negregex \"^blocked@\"" + restrict,
		"{2}jpegPhoto size 4" + restrict,
		"{3}description count 2" + restrict,
		"{4}uid uri \"ldap:///ou=archive,dc=example,dc=com?uid?one?" +
			"(objectClass=inetOrgPerson)\"" + restrict,
		"{5}cn,sn,givenName set " +
			"\"(this/givenName + [ ] + this/sn) & this/cn\"" + restrict,
	}
}

func constraintCatalogAdd(uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(
		"uid="+uid+",ou=archive,dc=example,dc=com",
		nil,
	)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{uid})
	return request
}

func constraintPersonAdd(
	dn,
	uid,
	givenName,
	surname string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("givenName", []string{givenName})
	request.Attribute("sn", []string{surname})
	request.Attribute("cn", []string{givenName + " " + surname})
	return request
}

func bindConstraintClient(
	t *testing.T,
	address,
	dn,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", dn, err)
	}
	return client
}
