package server

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceDynamicDirectoryServices(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"overlay dds\n"+
			"dds-max-ttl 1d\n"+
			"dds-min-ttl 30s\n"+
			"dds-default-ttl 1h\n"+
			"dds-interval 1s\n"+
			"dds-max-dynamicObjects 1",
		"",
	)
	defer stop()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("root Bind(): %v", err)
	}

	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension", "dynamicSubtrees"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(root DSE): %v", err)
	}
	if len(root.Entries) != 1 ||
		containsString(
			root.Entries[0].GetAttributeValues("supportedExtension"),
			dynamicRefreshOID,
		) ||
		!containsString(
			root.Entries[0].GetAttributeValues("dynamicSubtrees"),
			"dc=example,dc=com",
		) {
		var extensions, subtrees []string
		if len(root.Entries) == 1 {
			extensions = root.Entries[0].GetAttributeValues(
				"supportedExtension",
			)
			subtrees = root.Entries[0].GetAttributeValues("dynamicSubtrees")
		}
		t.Fatalf(
			"OpenLDAP DDS root DSE extensions = %q, dynamicSubtrees = %q",
			extensions,
			subtrees,
		)
	}

	dynamicDN := "cn=reference-lease,ou=people,dc=example,dc=com"
	if err := client.Add(
		newDynamicRoleAddRequest(dynamicDN, "reference-lease"),
	); err != nil {
		t.Fatalf("OpenLDAP Add(dynamicObject): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		dynamicDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=dynamicObject)",
		[]string{"entryTtl"},
		nil,
	))
	if err != nil {
		t.Fatalf("OpenLDAP Search(dynamicObject): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("OpenLDAP dynamic entries = %d, want 1", len(result.Entries))
	}
	ttl, err := strconv.ParseInt(
		result.Entries[0].GetAttributeValue("entryTtl"),
		10,
		64,
	)
	if err != nil || ttl < 3598 || ttl > 3600 {
		t.Fatalf("OpenLDAP entryTtl = %d, error = %v", ttl, err)
	}

	responseTTL, err := requestDynamicRefresh(client, dynamicDN, 10)
	if err != nil {
		t.Fatalf("OpenLDAP Refresh(dynamicObject): %v", err)
	}
	if responseTTL != 30 {
		t.Fatalf("OpenLDAP Refresh response TTL = %d, want 30", responseTTL)
	}
	_, err = requestDynamicRefresh(client, dynamicDN, 86401)
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	_, err = requestDynamicRefresh(
		client,
		"ou=people,dc=example,dc=com",
		30,
	)
	assertLDAPResultCode(t, err, ldap.LDAPResultObjectClassViolation)

	staticChild := ldap.NewAddRequest("cn=static,"+dynamicDN, nil)
	staticChild.Attribute("objectClass", []string{"organizationalRole"})
	staticChild.Attribute("cn", []string{"static"})
	assertLDAPResultCode(
		t,
		client.Add(staticChild),
		ldap.LDAPResultConstraintViolation,
	)

	modifyTTL := ldap.NewModifyRequest(dynamicDN, nil)
	modifyTTL.Replace("entryTtl", []string{"60"})
	assertLDAPResultCode(
		t,
		client.Modify(modifyTTL),
		ldap.LDAPResultConstraintViolation,
	)
	removeDynamicClass := ldap.NewModifyRequest(dynamicDN, nil)
	removeDynamicClass.Delete("objectClass", []string{"dynamicObject"})
	assertLDAPResultCode(
		t,
		client.Modify(removeDynamicClass),
		ldap.LDAPResultObjectClassViolation,
	)

	staticDN := "cn=static-move,ou=people,dc=example,dc=com"
	static := ldap.NewAddRequest(staticDN, nil)
	static.Attribute("objectClass", []string{"organizationalRole"})
	static.Attribute("cn", []string{"static-move"})
	if err := client.Add(static); err != nil {
		t.Fatalf("OpenLDAP Add(static entry): %v", err)
	}
	makeDynamic := ldap.NewModifyRequest(staticDN, nil)
	makeDynamic.Add("objectClass", []string{"dynamicObject"})
	assertLDAPResultCode(
		t,
		client.Modify(makeDynamic),
		ldap.LDAPResultObjectClassViolation,
	)
	moveStatic := ldap.NewModifyDNRequest(
		staticDN,
		"cn=static-move",
		true,
		dynamicDN,
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(moveStatic),
		ldap.LDAPResultConstraintViolation,
	)

	alias := ldap.NewAddRequest(
		"cn=dynamic-alias,ou=people,dc=example,dc=com",
		nil,
	)
	alias.Attribute(
		"objectClass",
		[]string{"alias", "extensibleObject", "dynamicObject"},
	)
	alias.Attribute("cn", []string{"dynamic-alias"})
	alias.Attribute("aliasedObjectName", []string{dynamicDN})
	assertLDAPResultCode(
		t,
		client.Add(alias),
		ldap.LDAPResultObjectClassViolation,
	)

	second := newDynamicRoleAddRequest(
		"cn=second,ou=people,dc=example,dc=com",
		"second",
	)
	assertLDAPResultCode(
		t,
		client.Add(second),
		ldap.LDAPResultUnwillingToPerform,
	)

	malformed := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		"",
		"requestValue",
	)
	_, err = client.Extended(
		ldap.NewExtendedRequest(dynamicRefreshOID, malformed),
	)
	assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
}

func TestOpenLDAPLDAPExopDynamicRefreshInterop(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP ldapexop interoperability test",
			openLDAPReferenceTestsEnv,
		)
	}
	ldapexop := findOpenLDAPLDAPExop(t)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDSdefaultTtl",
			Values:      stringValues("1h"),
		},
	)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	client := bindDDSRootClient(t, address)
	dn := "cn=ldapexop,ou=people,dc=example,dc=com"
	if err := client.Add(newDynamicRoleAddRequest(dn, "ldapexop")); err != nil {
		client.Close()
		t.Fatalf("Add(dynamicObject): %v", err)
	}
	client.Close()

	command := exec.Command(
		ldapexop,
		"-x",
		"-H",
		"ldap://"+address,
		"-D",
		"cn=admin,dc=example,dc=com",
		"-w",
		"admin-secret",
		"refresh",
		dn,
		"45",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapexop refresh: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "newttl=45") &&
		!strings.Contains(string(output), "responseTTL: 45") {
		t.Fatalf("ldapexop output has no response TTL:\n%s", output)
	}
	assertStoredDDSTTL(t, readStoredEntry(t, store, dn), 45)
}

func TestOpenLDAPReferenceDisabledDDS(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"overlay dds\ndds-state FALSE",
		"",
	)
	defer stop()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("root Bind(): %v", err)
	}
	dn := "cn=inert,ou=people,dc=example,dc=com"
	if err := client.Add(newDynamicRoleAddRequest(dn, "inert")); err != nil {
		t.Fatalf("OpenLDAP Add(inert dynamicObject): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=dynamicObject)",
		[]string{"entryTtl", "entryExpireTimestamp"},
		nil,
	))
	if err != nil {
		t.Fatalf("OpenLDAP Search(inert dynamicObject): %v", err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue("entryTtl") != "" ||
		result.Entries[0].GetAttributeValue("entryExpireTimestamp") != "" {
		t.Fatalf("OpenLDAP inert dynamicObject = %#v", result.Entries)
	}
	_, err = requestDynamicRefresh(client, dn, 60)
	assertLDAPResultCode(
		t,
		err,
		ldap.LDAPResultUnwillingToPerform,
	)
}

func TestOpenLDAPReferenceDDSExpirationHierarchy(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"overlay dds\n"+
			"dds-default-ttl 3s\n"+
			"dds-interval 1s",
		"",
	)
	defer stop()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("root Bind(): %v", err)
	}
	parentDN := "cn=expiring-parent,ou=people,dc=example,dc=com"
	childDN := "cn=expiring-child," + parentDN
	if err := client.Add(
		newDynamicRoleAddRequest(parentDN, "expiring-parent"),
	); err != nil {
		t.Fatalf("OpenLDAP Add(dynamic parent): %v", err)
	}
	if err := client.Add(
		newDynamicRoleAddRequest(childDN, "expiring-child"),
	); err != nil {
		t.Fatalf("OpenLDAP Add(dynamic child): %v", err)
	}
	if _, err := requestDynamicRefresh(client, childDN, 8); err != nil {
		t.Fatalf("OpenLDAP Refresh(dynamic child): %v", err)
	}

	time.Sleep(4 * time.Second)
	if !ldapEntryExists(t, client, parentDN) ||
		!ldapEntryExists(t, client, childDN) {
		t.Fatal("OpenLDAP removed an expired parent with a live dynamic child")
	}

	deadline := time.Now().Add(10 * time.Second)
	for ldapEntryExists(t, client, parentDN) {
		if time.Now().After(deadline) {
			t.Fatal("OpenLDAP did not remove expired dynamic hierarchy")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ldapEntryExists(t, client, childDN) {
		t.Fatal("OpenLDAP removed dynamic parent before its child")
	}
}

func findOpenLDAPLDAPExop(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("ldapexop"); err == nil {
		return path
	}
	for _, candidate := range []string{
		"/opt/homebrew/opt/openldap/bin/ldapexop",
		"/usr/bin/ldapexop",
		"/usr/local/bin/ldapexop",
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("OpenLDAP ldapexop is not installed")
	return ""
}

func ldapEntryExists(t *testing.T, client *ldap.Conn, dn string) bool {
	t.Helper()
	_, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	if err == nil {
		return true
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) &&
		ldapErr.ResultCode == ldap.LDAPResultNoSuchObject {
		return false
	}
	t.Fatalf("Search(%s): %v", dn, err)
	return false
}
