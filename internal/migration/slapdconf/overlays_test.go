package slapdconf

import (
	"fmt"
	"strings"
	"testing"
)

func TestCommonOverlays(t *testing.T) {
	for _, test := range []struct{ name, config, attribute, value string }{
		{"syncprov", "syncprov-checkpoint 100 10\nsyncprov-sessionlog 100\nsyncprov-nopresent TRUE\nsyncprov-reloadhint FALSE", "olcSpCheckpoint", "100 10"},
		{"memberof", "memberof-group-oc groupOfNames\nmemberof-member-ad member\nmemberof-memberof-ad memberOf\nmemberof-refint TRUE\nmemberof-addcheck TRUE", "olcMemberOfRefInt", "TRUE"},
		{"refint", "refint_attributes member uniqueMember\nrefint_nothing cn=nobody,dc=example", "olcRefintNothing", "cn=nobody,dc=example"},
		{"ppolicy", "ppolicy_default cn=default,dc=example\nppolicy_hash_cleartext\nppolicy_use_lockout", "olcPPolicyHashCleartext", "TRUE"},
		{"unique", "unique_uri ldap:///dc=example?uid?sub", "olcUniqueURI", "ldap:///dc=example?uid?sub"},
		{"auditlog", "auditlog /unused/audit.log", "olcAuditlogFile", "/unused/audit.log"},
		{"constraint", "constraint_attribute cn count 1", "olcConstraintAttribute", "cn count 1"},
		{"sssvlv", "sssvlv-max 10\nsssvlv-maxkeys 3\nsssvlv-maxperconn 2", "olcSssVlvMax", "10"},
		{"rwm", "rwm-map attribute description displayName", "olcRwmMap", "{0}attribute description displayName"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := configFile(t, fmt.Sprintf("database mdb\nsuffix dc=example\ndirectory /unused\noverlay %s\n%s\n", test.name, test.config))
			document, err := ConvertFile(path, ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			dn := "olcOverlay={0}" + test.name + ",olcDatabase={1}mdb,cn=config"
			if got := values(t, document, dn, test.attribute)[0]; got != test.value {
				t.Fatalf("%s = %q", test.attribute, got)
			}
		})
	}
}

func TestDatabaseSelection(t *testing.T) {
	path := configFile(t, `database frontend
access to * by * read
database config
rootdn cn=config
rootpw secret
database mdb
suffix dc=example
directory /unused
database ldap
suffix dc=remote
uri "ldap://localhost:1389 ldap://localhost:2389"
rebind-as-user
chase-referrals no
database null
suffix dc=empty
bind on
do-search off
database monitor
`)
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for index, backend := range []string{"config", "mdb", "ldap", "null", "monitor"} {
		dn := fmt.Sprintf("olcDatabase={%d}%s,cn=config", index, backend)
		if got := values(t, document, dn, "olcDatabase")[0]; got != fmt.Sprintf("{%d}%s", index, backend) {
			t.Fatalf("database = %q", got)
		}
	}
}

func TestAccesslogDynlistAndRelay(t *testing.T) {
	path := configFile(t, `database mdb
suffix dc=example
directory /unused/main
overlay accesslog
logdb cn=log
logops writes
logbase reads dc=example
logsuccess TRUE
logpurge 7+00:00 1+00:00
overlay dynlist
dynlist-attrpair member memberURL
database mdb
suffix cn=log
directory /unused/log
database relay
suffix dc=alias
relay dc=example
`)
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := values(t, document, "olcOverlay={1}dynlist,olcDatabase={1}mdb,cn=config", "olcDynListAttrSet")[0]; got != "{0}groupOfURLs memberURL member" {
		t.Fatalf("dynlist = %q", got)
	}
}

func TestRWMCommonRewriteBackendSelection(t *testing.T) {
	directives := `overlay rwm
rwm-rewriteEngine on
rwm-rewriteContext default
rwm-rewriteRule "^(.*)$" "$1" ":"
`
	for _, test := range []struct {
		name, configuration, dn string
	}{
		{
			name:          "ldap",
			configuration: "database ldap\nsuffix dc=proxy\nuri ldap://127.0.0.1:389\n" + directives,
			dn:            "olcOverlay={0}rwm,olcDatabase={1}ldap,cn=config",
		},
		{
			name: "relay",
			configuration: "database mdb\nsuffix dc=target\ndirectory /unused\n" +
				"database relay\nsuffix dc=proxy\nrelay dc=target\n" + directives,
			dn: "olcOverlay={0}rwm,olcDatabase={2}relay,cn=config",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, err := ConvertFile(configFile(t, test.configuration), ParseOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got := values(t, document, test.dn, "olcRwmRewrite")
			if len(got) != 3 || got[0] != "{0}rwm-rewriteEngine on" {
				t.Fatalf("rewrite = %q", got)
			}
		})
	}
}

func TestRWMCommonRewriteRejectsLocalBackendAtDirective(t *testing.T) {
	path := configFile(t, `database mdb
suffix dc=example
directory /unused
overlay rwm
rwm-rewriteEngine on
`)
	if _, err := ConvertFile(path, ParseOptions{}); err == nil ||
		!strings.Contains(err.Error(), path+":5:") ||
		!strings.Contains(err.Error(), "local backend mdb") {
		t.Fatalf("error = %v", err)
	}
}

func TestRWMSuffixAndMapRemainSupportedOnLocalBackend(t *testing.T) {
	path := configFile(t, `database mdb
suffix dc=example
directory /unused
overlay rwm
rwm-suffixmassage dc=remote
rwm-map attribute description displayName
`)
	if _, err := ConvertFile(path, ParseOptions{}); err != nil {
		t.Fatal(err)
	}
}
