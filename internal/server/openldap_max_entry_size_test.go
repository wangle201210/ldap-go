package server

import (
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceMaxEntrySizeGrammar(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	version, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13 ") {
		t.Fatalf("requires OpenLDAP 2.6.13: %v: %s", err, version)
	}
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil,
		"database config\nrootdn cn=config\nrootpw config-secret", "", "")
	defer stop()
	reference := observeMaxEntrySizeGrammar(t, uri)
	store := storage.NewMemory()
	defer store.Close()
	seedEntryLimit(t, store, "0", true)
	_, address, stopGo := startConfigurationCapabilityServer(t, store)
	defer stopGo()
	implementation := observeMaxEntrySizeGrammar(t, "ldap://"+address)
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf("OpenLDAP: %v\nldap-go: %v", reference, implementation)
	}
}

func TestMaxEntrySizeOnlineGrammar(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	seedEntryLimit(t, store, "0", true)
	_, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	observeMaxEntrySizeGrammar(t, "ldap://"+address)
}

func observeMaxEntrySizeGrammar(t *testing.T, uri string) []string {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	dn := "olcDatabase={1}mdb,cn=config"
	read := func() string {
		r, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"olcDbMaxEntrySize"}, nil))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(r.Entries[0].GetAttributeValues("olcDbMaxEntrySize"), ",")
	}
	observations := []string{read()}
	last := "0"
	for _, test := range []struct {
		value string
		code  uint16
	}{{"0", 0}, {"1", 0}, {"010", 21}, {"08", 21}, {"0x10", 21}, {"+1", 21}, {"-1", 19}, {"-0", 21}, {" 1", 21}, {"1 ", 21}, {"1k", 21}, {"18446744073709551615", 0}, {"18446744073709551616", 19}, {"001", 21}, {"", 21}} {
		m := ldap.NewModifyRequest(dn, nil)
		m.Replace("olcDbMaxEntrySize", []string{test.value})
		err := client.Modify(m)
		if test.code == 0 {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertLDAPResultCode(t, err, test.code)
		}
		if test.code == 0 {
			last = test.value
		}
		if got := read(); got != last {
			t.Fatalf("after %q read=%q, want %q", test.value, got, last)
		}
		observations = append(observations, strconv.Itoa(int(test.code))+":"+read())
	}
	m := ldap.NewModifyRequest(dn, nil)
	m.Delete("olcDbMaxEntrySize", nil)
	if err := client.Modify(m); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "" {
		t.Fatalf("deleted limit still emitted: %q", got)
	}
	observations = append(observations, read())
	return observations
}

func TestOpenLDAPReferenceMaxEntrySizeAccounting(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	for _, lastmod := range []bool{false, true} {
		t.Run("lastmod="+strconv.FormatBool(lastmod), func(t *testing.T) {
			directive := ""
			if !lastmod {
				directive = "lastmod off"
			}
			uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, "database config\nrootdn cn=config\nrootpw config-secret", directive, "")
			defer stop()
			store := storage.NewMemory()
			defer store.Close()
			seedEntryLimit(t, store, "0", lastmod)
			_, address, stopGo := startConfigurationCapabilityServer(t, store)
			defer stopGo()
			for _, test := range []struct {
				attribute string
				values    []string
			}{
				{"", nil}, {"description", []string{"  A  mixed Case  value  "}},
				{"description", []string{"one", "TWO"}}, {"description;lang-en", []string{"options"}},
				{"jpegPhoto", []string{string([]byte{0, 255, 10, 128, 0})}},
				{"postalAddress", []string{" A $ B  C $ D\\24 "}},
				{"telephoneNumber", []string{"+1 234-567"}},
				{"seeAlso", []string{"CN=Someone, OU=people, DC=example, DC=com"}},
				{"description", []string{"\u00c9cole \u212a \ufb03 \uff21"}},
			} {
				t.Run(test.attribute+strings.Join(test.values, ","), func(t *testing.T) {
					a := entryLimitPerson("cn=limit,ou=people,dc=example,dc=com", "")
					if test.attribute == "postalAddress" {
						a.Attributes[0].Vals = append(a.Attributes[0].Vals, "extensibleObject")
					}
					if test.attribute != "" {
						a.Attribute(test.attribute, test.values)
					}
					reference := findMaxEntrySizeBoundary(t, uri, a)
					implementation := findMaxEntrySizeBoundary(t, "ldap://"+address, a)
					if reference != implementation {
						t.Fatalf("minimum accepted bytes: OpenLDAP=%d ldap-go=%d", reference, implementation)
					}
					t.Logf("minimum accepted bytes: %d", reference)
				})
			}
		})
	}
}

func findMaxEntrySizeBoundary(t *testing.T, uri string, add *ldap.AddRequest) uint64 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	config, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	low, high := uint64(1), uint64(8192)
	for low < high {
		mid := low + (high-low)/2
		replaceEntryLimit(t, config, mid)
		err := client.Add(add)
		if err == nil {
			if err := client.Del(ldap.NewDelRequest(add.DN, nil)); err != nil {
				t.Fatal(err)
			}
			high = mid
		} else {
			assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
			low = mid + 1
		}
	}
	replaceEntryLimit(t, config, 0)
	return low
}

func TestOpenLDAPReferenceMaxEntrySizeLoweringAndOrder(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, "database config\nrootdn cn=config\nrootpw config-secret", "lastmod off", "")
	defer stop()
	store := storage.NewMemory()
	defer store.Close()
	seedEntryLimit(t, store, "0", false)
	_, address, stopGo := startConfigurationCapabilityServer(t, store)
	defer stopGo()
	for _, uri := range []string{uri, "ldap://" + address} {
		t.Run(uri, func(t *testing.T) { checkEntryLimitLowering(t, uri) })
	}
}

func TestMaxEntrySizeOversizedDescendant(t *testing.T) {
	for _, bolt := range []bool{false, true} {
		t.Run(strconv.FormatBool(bolt), func(t *testing.T) {
			store := entryLimitStore(t, bolt)
			defer store.Close()
			seedEntryLimit(t, store, "0", false)
			_, address, stop := startConfigurationCapabilityServer(t, store)
			defer stop()
			checkEntryLimitLowering(t, "ldap://"+address)
		})
	}
}

func checkEntryLimitLowering(t *testing.T, uri string) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	config, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	parent := "ou=branch,dc=example,dc=com"
	a := ldap.NewAddRequest(parent, nil)
	a.Attribute("objectClass", []string{"organizationalUnit"})
	a.Attribute("ou", []string{"branch"})
	if err := client.Add(a); err != nil {
		t.Fatal(err)
	}
	child := "cn=limit," + parent
	if err := client.Add(entryLimitPerson(child, strings.Repeat("x", 500))); err != nil {
		t.Fatal(err)
	}
	replaceEntryLimit(t, config, 128)
	assertLDAPResultCode(t, client.Add(entryLimitPerson(child, strings.Repeat("x", 500))), ldap.LDAPResultEntryAlreadyExists)
	assertLDAPResultCode(t, client.Add(entryLimitPerson("cn=limit,ou=missing,dc=example,dc=com", strings.Repeat("x", 500))), ldap.LDAPResultNoSuchObject)
	invalid := ldap.NewModifyRequest(child, nil)
	invalid.Delete("sn", nil)
	assertLDAPResultCode(t, client.Modify(invalid), ldap.LDAPResultObjectClassViolation)
	if err := client.ModifyDN(ldap.NewModifyDNRequest(parent, "ou=moved", true, "")); err != nil {
		t.Fatalf("rename with oversized descendant: %v", err)
	}
	child = "cn=limit,ou=moved,dc=example,dc=com"
	m := ldap.NewModifyRequest(child, nil)
	m.Replace("description", []string{strings.Repeat("x", 400)})
	assertLDAPResultCode(t, client.Modify(m), ldap.LDAPResultAdminLimitExceeded)
	assertLDAPResultCode(t, client.ModifyDN(ldap.NewModifyDNRequest(child, "cn=other", true, "")), ldap.LDAPResultAdminLimitExceeded)
	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(child, "", ""))
	assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
	m = ldap.NewModifyRequest(child, nil)
	m.Delete("description", nil)
	if err := client.Modify(m); err != nil {
		t.Fatalf("shrink to exact 128 byte boundary: %v", err)
	}
	replaceEntryLimit(t, config, 1)
	if err := client.Del(ldap.NewDelRequest(child, nil)); err != nil {
		t.Fatalf("delete oversized: %v", err)
	}
}

func TestOpenLDAPReferenceMaxEntrySizeTransaction(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, "database config\nrootdn cn=config\nrootpw config-secret", "", "")
	defer stop()
	config, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	replaceEntryLimit(t, config, 1024)
	connection := dialAndBindRawLDAP(t, strings.TrimPrefix(uri, "ldap://"), "cn=admin,dc=example,dc=com", "secret")
	defer connection.Close()
	id := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("limit-txn")
	assertRawLDAPResult(t, sendRawLDAPOperation(t, connection, 3, rawAddRequest(entry), rawTransactionSpecificationControl(id, true, true)), 0)
	assertRawLDAPResult(t, sendRawLDAPOperation(t, connection, 4, rawModifyReplaceRequest(entry.DN, "description", strings.Repeat("x", 2048)), rawTransactionSpecificationControl(id, true, true)), 0)
	response := endRawLDAPTransaction(t, connection, 5, true, id)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultAdminLimitExceeded))
	value, _ := rawExtendedResponseValue(response)
	decoded, err := ldapwire.DecodeTransactionEndResponseValue(value)
	if err != nil || !decoded.HasFailedMessageID || decoded.FailedMessageID != 4 {
		t.Fatalf("transaction response=%+v %v", decoded, err)
	}
}
