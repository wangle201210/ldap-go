package main

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPSearchDomainScopeExtension(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	stdout, stderr, exitCode := runLDAPClientCommand([]string{
		"ldapsearch", "-H", uri, "-x",
		"-D", clientToolRootDN, "-w", clientToolRootPassword,
		"-b", clientToolPeopleDN, "-s", "sub", "-LLL",
		"-E", "!domainScope", "(objectClass=*)", "1.1",
	}, "")
	if exitCode != 0 || stderr != "" || !strings.Contains(stdout, "dn: ") {
		t.Fatalf("domainScope search exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestParseLDAPSearchDomainScopeExtension(t *testing.T) {
	for _, value := range []string{"domainScope", "!domainScope", "DoMaInScOpE"} {
		control, err := parseLDAPSearchDomainScopeExtension(value)
		if err != nil {
			t.Fatalf("parseLDAPSearchDomainScopeExtension(%q): %v", value, err)
		}
		raw, ok := control.(*ldapRawControl)
		if !ok || raw.oid != ldapwire.DomainScopeControlOID || raw.hasValue ||
			raw.critical != strings.HasPrefix(value, "!") {
			t.Fatalf("domainScope control %q = %#v", value, control)
		}
	}
	for _, value := range []string{"domainScope=", "domainScope=true", "domain", "!!domainScope"} {
		if _, err := parseLDAPSearchDomainScopeExtension(value); err == nil {
			t.Errorf("parseLDAPSearchDomainScopeExtension(%q) succeeded", value)
		}
	}
}
