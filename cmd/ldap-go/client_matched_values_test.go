package main

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchMatchedValuesExtension(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	common := []string{
		"ldapsearch", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
		"-b", clientToolPeopleDN, "-s", "one", "-LLL",
	}
	stdout, stderr, exitCode := runLDAPClientCommand(
		append(append([]string(nil), common...),
			"-E", "!mv=(uid=alice)", "(uid=*)", "uid"),
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("matched-values search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if strings.Count(stdout, "dn: uid=") != 2 ||
		!strings.Contains(stdout, "dn: uid=alice,"+clientToolPeopleDN+"\nuid: alice\n") ||
		strings.Contains(stdout, "dn: uid=bob,"+clientToolPeopleDN+"\nuid:") {
		t.Fatalf("matched-values UID projection = %q", stdout)
	}

	stdout, stderr, exitCode = runLDAPClientCommand(
		append(append([]string(nil), common...),
			"-E", "mv=((uid=alice)(uid=bob))", "(uid=*)", "uid"),
		"",
	)
	if exitCode != 0 || stderr != "" || strings.Count(stdout, "uid: ") != 2 {
		t.Fatalf("matched-values list exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestParseLDAPSearchMatchedValuesExtension(t *testing.T) {
	control, err := parseLDAPSearchMatchedValuesExtension("!mv=((mail=*@example.com)(cn=Alice))")
	if err != nil {
		t.Fatalf("parse matched-values extension: %v", err)
	}
	raw, ok := control.(*ldapRawControl)
	if !ok || !raw.critical || raw.oid != ldapwire.MatchedValuesControlOID || !raw.hasValue {
		t.Fatalf("matched-values control = %#v", control)
	}
	filters, err := ldapwire.DecodeValuesReturnFilter(raw.value)
	if err != nil || len(filters) != 2 {
		t.Fatalf("matched-values filters = %#v, %v", filters, err)
	}
	raw.clear()

	for _, value := range []string{
		"mv",
		"mv=",
		"mv=(&(uid=alice)(cn=Alice))",
		"mv=((uid=alice)",
	} {
		if _, err := parseLDAPSearchMatchedValuesExtension(value); err == nil {
			t.Errorf("parseLDAPSearchMatchedValuesExtension(%q) succeeded", value)
		}
	}
}
