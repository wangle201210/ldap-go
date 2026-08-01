package server

import (
	"errors"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceConstraintOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{constraintReferenceOverlayConfiguration()},
		"",
		"",
		constraintReferenceCatalogLDIF(),
	)
	defer stopOpenLDAP()
	openLDAP, err := ldap.DialURL(openLDAPURI)
	if err != nil {
		t.Fatalf("DialURL(OpenLDAP): %v", err)
	}
	defer openLDAP.Close()
	if err := openLDAP.Bind(
		"cn=admin,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("Bind(OpenLDAP): %v", err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	for _, uid := range []string{
		"constraint-valid",
		"constraint-mail",
		"constraint-jane",
	} {
		if err := ldapGo.Add(constraintCatalogAdd(uid)); err != nil {
			t.Fatalf("Add(ldap-go catalog %s): %v", uid, err)
		}
	}
	configClient := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=config",
		"config-secret",
	)
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testConstraintOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}constraint"})
	overlay.Attribute("olcConstraintAttribute", constraintTestRules(false))
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go constraint overlay): %v", err)
	}

	openLDAPResults := runConstraintReferenceScenario(t, openLDAP)
	ldapGoResults := runConstraintReferenceScenario(t, ldapGo)
	want := []uint16{
		ldap.LDAPResultSuccess,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultConstraintViolation,
		ldap.LDAPResultSuccess,
	}
	labels := []string{
		"valid add",
		"regex add",
		"negative regex modify",
		"size modify",
		"count modify",
		"set modify",
		"URI add",
		"set rename",
		"Relax add",
	}
	for index := range want {
		if openLDAPResults[index] != want[index] ||
			ldapGoResults[index] != openLDAPResults[index] {
			t.Fatalf(
				"%s result: OpenLDAP=%d ldap-go=%d want=%d",
				labels[index],
				openLDAPResults[index],
				ldapGoResults[index],
				want[index],
			)
		}
	}
}

func runConstraintReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) []uint16 {
	t.Helper()

	validDN := "uid=constraint-valid,ou=people,dc=example,dc=com"
	valid := constraintPersonAdd(
		validDN,
		"constraint-valid",
		"Valid",
		"User",
	)
	valid.Attribute("mail", []string{"valid@example.com"})
	valid.Attribute("description", []string{"one", "two"})
	valid.Attribute("jpegPhoto", []string{"1234"})
	results := []uint16{constraintLDAPResultCode(t, client.Add(valid))}

	badMail := constraintPersonAdd(
		"uid=constraint-mail,ou=people,dc=example,dc=com",
		"constraint-mail",
		"Mail",
		"User",
	)
	badMail.Attribute("mail", []string{"invalid.test"})
	results = append(results, constraintLDAPResultCode(t, client.Add(badMail)))

	blocked := ldap.NewModifyRequest(validDN, nil)
	blocked.Add("mail", []string{"blocked@example.com"})
	results = append(results, constraintLDAPResultCode(t, client.Modify(blocked)))

	oversized := ldap.NewModifyRequest(validDN, nil)
	oversized.Replace("jpegPhoto", []string{"12345"})
	results = append(results, constraintLDAPResultCode(t, client.Modify(oversized)))

	tooMany := ldap.NewModifyRequest(validDN, nil)
	tooMany.Add("description", []string{"three"})
	results = append(results, constraintLDAPResultCode(t, client.Modify(tooMany)))

	wrongName := ldap.NewModifyRequest(validDN, nil)
	wrongName.Replace("cn", []string{"Wrong Name"})
	results = append(results, constraintLDAPResultCode(t, client.Modify(wrongName)))

	missingCatalog := constraintPersonAdd(
		"uid=constraint-missing,ou=people,dc=example,dc=com",
		"constraint-missing",
		"Missing",
		"User",
	)
	missingCatalog.Attribute("mail", []string{"missing@example.com"})
	results = append(
		results,
		constraintLDAPResultCode(t, client.Add(missingCatalog)),
	)

	janeDN := "cn=Constraint Jane,ou=people,dc=example,dc=com"
	jane := constraintPersonAdd(
		janeDN,
		"constraint-jane",
		"Constraint",
		"Jane",
	)
	jane.Attribute("mail", []string{"jane@example.com"})
	if err := client.Add(jane); err != nil {
		t.Fatalf("Add(reference rename source): %v", err)
	}
	rename := ldap.NewModifyDNRequest(
		janeDN,
		"cn=Constraint Wrong",
		true,
		"",
	)
	results = append(results, constraintLDAPResultCode(t, client.ModifyDN(rename)))

	relaxed := constraintPersonAdd(
		"uid=constraint-relaxed,ou=people,dc=example,dc=com",
		"constraint-relaxed",
		"Relaxed",
		"User",
	)
	relaxed.Controls = []ldap.Control{relaxLDAPControl()}
	relaxed.Attribute("mail", []string{"invalid"})
	relaxed.Attribute("description", []string{"one", "two", "three"})
	relaxed.Attribute("jpegPhoto", []string{"12345"})
	results = append(results, constraintLDAPResultCode(t, client.Add(relaxed)))
	return results
}

func constraintLDAPResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("LDAP operation returned non-LDAP error: %v", err)
	}
	return ldapErr.ResultCode
}

func constraintReferenceOverlayConfiguration() string {
	restrict := " restrict=\"ldap:///ou=people,dc=example,dc=com??one?" +
		"(objectClass=inetOrgPerson)\""
	return "constraint\n" +
		"constraint_attribute mail regex " +
		"\"^[[:alnum:]._-]+@example[.]com$\"" + restrict + "\n" +
		"constraint_attribute mail negregex \"^blocked@\"" + restrict + "\n" +
		"constraint_attribute jpegPhoto size 4" + restrict + "\n" +
		"constraint_attribute description count 2" + restrict + "\n" +
		"constraint_attribute uid uri " +
		"\"ldap:///ou=archive,dc=example,dc=com?uid?one?" +
		"(objectClass=inetOrgPerson)\"" + restrict + "\n" +
		"constraint_attribute cn,sn,givenName set " +
		"\"(this/givenName + [ ] + this/sn) & this/cn\"" + restrict
}

func constraintReferenceCatalogLDIF() string {
	result := "\ndn: ou=archive,dc=example,dc=com\n" +
		"objectClass: top\n" +
		"objectClass: organizationalUnit\n" +
		"ou: archive\n"
	for _, uid := range []string{
		"constraint-valid",
		"constraint-mail",
		"constraint-jane",
	} {
		result += "\ndn: uid=" + uid + ",ou=archive,dc=example,dc=com\n" +
			"objectClass: top\n" +
			"objectClass: person\n" +
			"objectClass: organizationalPerson\n" +
			"objectClass: inetOrgPerson\n" +
			"uid: " + uid + "\n" +
			"cn: " + uid + "\n" +
			"sn: " + uid + "\n"
	}
	return result
}
