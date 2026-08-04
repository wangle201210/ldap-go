package aci

import (
	"strings"
	"testing"
)

func TestParseOpenLDAPACI(t *testing.T) {
	t.Parallel()

	raw := "0#subtree#grant;d,c,s,r;[all]$deny;w;userPassword#" +
		"group/groupOfUniqueNames/uniqueMember#" +
		"cn=ITD Staff,ou=Groups,dc=example,dc=com"
	value, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	if value.OID != "0" || value.Scope != ScopeSubtree ||
		value.SubjectKind != SubjectGroup ||
		value.ObjectClass != "groupOfUniqueNames" ||
		value.GroupAttribute != "uniqueMember" ||
		len(value.Permissions) != 2 ||
		!value.Permissions[0].Grant || value.Permissions[1].Grant ||
		value.Permissions[0].Rights != RightDisclose|RightCompare|RightSearch|RightRead ||
		!value.Permissions[0].Attributes[0].All {
		t.Fatalf("Parse() = %#v", value)
	}
}

func TestNormalizeOpenLDAPACI(t *testing.T) {
	t.Parallel()

	left := []byte("1#SUBTREE#GRANT;r;CN;r;MAIL=Allowed*#ACCESS-ID#" +
		"UID=Alice,DC=Example,DC=COM")
	right := []byte("1#subtree#grant;r;cn;r;mail=Allowed*#access-id#" +
		"uid=alice,dc=example,dc=com")
	comparison, err := Compare(left, right)
	if err != nil {
		t.Fatalf("Compare(): %v", err)
	}
	if comparison != 0 {
		t.Fatalf("Compare() = %d, want 0", comparison)
	}
	normalized, err := Normalize(left)
	if err != nil {
		t.Fatalf("Normalize(): %v", err)
	}
	if got := string(normalized); !strings.Contains(got, "#grant;r;cn;r;mail=Allowed*#") {
		t.Fatalf("Normalize() = %q", got)
	}
}

func TestParseOpenLDAPACIRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	values := []string{
		"",
		"0#entry#grant;r;cn#public",
		"not-an-oid#entry#grant;r;cn#public#",
		"0#one#grant;r;cn#public#",
		"0#entry#allow;r;cn#public#",
		"0#entry#grant;q;cn#public#",
		"0#entry#grant;r#public#",
		"0#entry#grant;r;cn#unknown#",
		"0#entry#grant;r;cn#access-id#not a DN",
		"0#entry#grant;r;cn#group//member#cn=group,dc=example,dc=com",
	}
	for _, value := range values {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(value); err == nil {
				t.Fatalf("Parse(%q) succeeded", value)
			}
		})
	}
}
