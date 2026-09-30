package schema

import (
	"fmt"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func dnPrefixNamesTestRegistry(t testing.TB) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	member, ok := registry.AttributeType("member")
	if !ok {
		t.Fatal("missing builtin member")
	}
	member.Names = append(member.Names, "prefixMemberAlias", "prefix-member.7", "kMember", "\u00c9Member")
	if err := registry.UpsertAttributeType(member); err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.871", Names: []string{"prefixNameChild", "prefixChildAlias"}, Superior: "2.5.4.31"},
		{OID: "1.2.3.872", Names: []string{"prefixNameGrandchild"}, Superior: "prefixChildAlias"},
		// The option-free alias resolves, but Name() is not an equivalent request.
		{OID: "1.2.3.873", Names: []string{"prefixPrimary;lang-en", "prefixPlainAlias"}, Superior: "member"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, length := range []int{127, 128, 129} {
		attribute := AttributeType{
			OID: fmt.Sprintf("1.2.3.874.%d", length), Names: []string{strings.Repeat("N", length)}, Superior: "member",
		}
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	// Distinct descriptors with the same OID must retain subtype identity.
	duplicate := member
	duplicate.Names = []string{"prefixDuplicateMember"}
	registry.mu.Lock()
	registry.attributes[schemaKey(duplicate.Name())] = &duplicate
	registry.mu.Unlock()
	return registry
}

func TestDNPrefixAttributeSelectedLockedNamesParity(t *testing.T) {
	registry := dnPrefixNamesTestRegistry(t)
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	check := func(t *testing.T, candidate, description string) {
		t.Helper()
		requested := registry.attributes[schemaKey(description)]
		if requested == nil || len(description) > 128 || strings.Contains(description, ";") {
			t.Fatalf("invalid option-free request fixture %q", description)
		}
		want := registry.attributeDescriptionSubtype(candidate, description)
		if got := registry.dnPrefixAttributeSelectedLocked(candidate, description, requested); got != want {
			t.Fatalf("selected(%q, %q) = %v, attributeDescriptionSubtype = %v", candidate, description, got, want)
		}
	}

	candidates := []string{
		"member", "MEMBER", "MeMbEr", "2.5.4.31", "prefixMemberAlias", "PREFIXMEMBERALIAS",
		"prefix-member.7", "PREFIX-MEMBER.7", "prefixDuplicateMember", "PREFIXDUPLICATEMEMBER",
		"prefixNameChild", "PREFIXNAMECHILD", "prefixChildAlias", "1.2.3.871",
		"prefixNameGrandchild", "PREFIXNAMEGRANDCHILD", "1.2.3.872",
		"prefixPlainAlias", "PREFIXPLAINALIAS", "1.2.3.873", "prefixPrimary;lang-en",
		"cn", "manager", "uniqueMember", "memberOf", "objectClass", "creatorsName", "modifiersName",
		"createTimestamp", "modifyTimestamp", "entryUUID", "entryCSN", "structuralObjectClass",
		"", " ", "\t\r\n", ";", ";;", " ; ", "unknown", "UNKNOWN", "unknown;lang-en",
		" member ", "\tMEMBER\r\n", "\u00a0member\u2003", "\u202fMEMBER\u3000",
		"member;lang-en", "MEMBER;LANG-en;binary", "member;lang-", "member;lang-en;lang-en",
		" member ; LANG-en ; binary ", "member;", "member;;", "member;=", "member;\xff",
		"2.5.4.31;binary", "prefixMemberAlias;lang-en", "prefixChildAlias;binary",
		"prefixNameGrandchild;lang-en", "prefixDuplicateMember;binary", "prefixPlainAlias;binary",
		" prefixPlainAlias ", "\u00a0prefixPlainAlias\u2003", "1.2.3.873;binary",
		"\u212aMember", "KMEMBER", "\u00c9Member", "\u00e9MEMBER", "\u00e9Member;binary",
		"m\u00e9mber", "mem\u200bber", "member\x00", "\x00member", "\xffmember", "member\xff",
		"\xc0\xafmember", "\xff;\xfe", "mem ber", "mem;ber", ";member", "member=", "member_",
		"member/", "member.", "member-", "2..5.4.31", ".", "-", "0",
	}
	for _, length := range []int{127, 128, 129} {
		name := strings.Repeat("N", length)
		candidates = append(candidates, name, strings.ToLower(name), name+";binary", " "+name+" ", strings.Repeat("Z", length))
		candidates = append(candidates, "member;"+strings.Repeat("x", length-len("member;")), strings.Repeat(" ", length-len("member"))+"member")
	}
	for _, description := range []string{
		"member", "MEMBER", "2.5.4.31", "prefixMemberAlias", "prefixDuplicateMember",
		" prefixMemberAlias ", "\u00a0member\u2003", "\u00c9Member",
		"prefixNameChild", "prefixChildAlias", "1.2.3.871", "prefixNameGrandchild",
		"prefixPlainAlias", "1.2.3.873", strings.Repeat("N", 127), strings.Repeat("N", 128),
	} {
		t.Run(description, func(t *testing.T) {
			for _, candidate := range candidates {
				check(t, candidate, description)
			}
		})
	}

	t.Run("all byte insertions and replacements", func(t *testing.T) {
		for _, description := range []string{"member", "2.5.4.31", "prefixChildAlias", "prefixPlainAlias"} {
			for _, seed := range []string{"MeMbEr", "2.5.4.31", "prefixChildAlias", "prefixPlainAlias"} {
				for value := range 256 {
					variation := string([]byte{byte(value)})
					for offset := range len(seed) + 1 {
						check(t, seed[:offset]+variation+seed[offset:], description)
						if offset < len(seed) {
							check(t, seed[:offset]+variation+seed[offset+1:], description)
						}
					}
				}
			}
		}
	})
}

func TestCompareEntryAttributeWithDNPrefixNamesOracle(t *testing.T) {
	registry := dnPrefixNamesTestRegistry(t)
	base := dnPrefixTestEntry(32, false)
	member := base.Attributes[0]
	base.Attributes = []directory.Attribute{
		{Description: "objectClass", Values: byteValues("top", "groupOfNames")},
		{Description: "cn", Values: byteValues("group")},
		{Description: "creatorsName", Values: byteValues("cn=creator,dc=example")},
		{Description: "createTimestamp", Values: byteValues("20260930000000Z")},
		member,
		{Description: "modifiersName", Values: byteValues("cn=modifier,dc=example")},
		{Description: "modifyTimestamp", Values: byteValues("20260930010000Z")},
		{Description: "entryUUID", Values: byteValues("11111111-1111-4111-8111-111111111111")},
		{Description: "entryCSN", Values: byteValues("20260930010000.000000Z#000000#000#000000")},
		{Description: "structuralObjectClass", Values: byteValues("groupOfNames")},
	}
	first := member.Values[0]
	last := member.Values[len(member.Values)-1]
	missing := []byte("cn=missing,dc=example")
	warm := checkCompareEntryAttributeWithDNPrefix(t, registry, base, "member", first, nil)
	if warm == nil {
		t.Fatal("unselected camel-case operational attributes prevented prefix qualification")
	}
	t.Run("operational attributes remain unselected", func(t *testing.T) {
		for _, previous := range []*DNComparisonPrefix{nil, warm} {
			for _, assertion := range [][]byte{first, last, missing} {
				if next := checkCompareEntryAttributeWithDNPrefix(t, registry, base, "member", assertion, previous); next == nil {
					t.Fatal("single exact member did not return a prefix")
				}
			}
			checkCompareEntryAttributeWithDNPrefix(t, registry, base, "member", []byte("bad-dn"), previous)
		}
	})

	for _, description := range []string{
		"member", "MEMBER", "2.5.4.31", "prefixMemberAlias", "prefixDuplicateMember",
		"member;lang-en", "member;;", " member ", "\u00a0member\u2003", "\u212aMember",
		"prefixNameChild", "prefixChildAlias", "1.2.3.871", "prefixNameGrandchild;binary",
		strings.Repeat("N", 129),
	} {
		t.Run("later selected/"+description, func(t *testing.T) {
			if !registry.AttributeDescriptionSubtype(description, "member") {
				t.Fatalf("later attribute %q must be selected by the oracle", description)
			}
			for _, fixture := range []struct {
				name   string
				values [][]byte
			}{
				{"empty", nil},
				{"match before error", byteValues("cn=added,dc=example", "bad-dn")},
				{"error before match", byteValues("bad-dn", "cn=added,dc=example")},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					entry := base.Clone()
					entry.Attributes = append(entry.Attributes, directory.Attribute{Description: description, Values: fixture.values})
					for _, previous := range []*DNComparisonPrefix{nil, warm} {
						// Qualification must scan past the first matching member even
						// though comparison still stops before later invalid values.
						for _, assertion := range [][]byte{first, last, []byte("cn=added,dc=example"), missing, []byte("bad-dn")} {
							if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "member", assertion, previous); next != nil {
								t.Fatal("later selected attribute failed to discard the prefix and use the full comparator")
							}
						}
					}
				})
			}
		})
	}

	t.Run("fallback preserves original requested alias", func(t *testing.T) {
		entry := base.Clone()
		entry.Attributes[4].Description = "prefixPlainAlias"
		warm := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "prefixPlainAlias", first, nil)
		if warm == nil {
			t.Fatal("option-free alias did not qualify for a prefix")
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "prefixPlainAlias;binary", Values: byteValues("bad-dn")})
		for _, previous := range []*DNComparisonPrefix{nil, warm} {
			for _, assertion := range [][]byte{first, missing} {
				if next := checkCompareEntryAttributeWithDNPrefix(t, registry, entry, "prefixPlainAlias", assertion, previous); next != nil {
					t.Fatal("fallback substituted the primary name for the original requested alias")
				}
			}
		}
	})
}
