package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func preparedEqualityRegistry(t testing.TB) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	attribute, _ := registry.AttributeType("objectClass")
	attribute.Names = append(attribute.Names, "classAlias")
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.10", Names: []string{"childClass", "childAlias"}, Superior: "objectClass"},
		{OID: "1.2.3.11", Names: []string{"grandchildClass"}, Superior: "childAlias", Equality: "caseExactMatch"},
		{OID: "1.2.3.12", Names: []string{"orderedClass"}, Superior: "objectClass", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, class := range []ObjectClass{
		{OID: "1.2.3.20", Names: []string{"customPerson", "personAlias"}, Superiors: []string{"inetOrgPerson"}},
		{OID: "1.2.3.21", Names: []string{"customChild"}, Superiors: []string{"personAlias"}},
		{OID: "1.2.3.22", Names: []string{"multipleParents"}, Superiors: []string{"alias", "customChild"}},
		{OID: "1.2.3.23", Names: []string{"orphanClass"}, Superiors: []string{"unknownParent"}},
		{OID: "1.2.3.24", Names: []string{"cycleA"}, Superiors: []string{"cycleB"}},
		{OID: "1.2.3.25", Names: []string{"cycleB"}, Superiors: []string{"cycleA", "person"}},
	} {
		if err := registry.RegisterObjectClass(class); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func checkPreparedEquality(t testing.TB, registry *Registry, matcher *PreparedEqualityMatcher, filter directory.Filter, entry directory.Entry) {
	t.Helper()
	want, wantErr := filter.MatchWith(entry, registry)
	got, gotErr := matcher.Match(entry)
	if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("(%s=%q), attributes=%+v: prepared=(%v, %v), general=(%v, %v)",
			filter.Attribute, filter.Assertion, entry.Attributes, got, gotErr, want, wantErr)
	}
}

func TestPreparedEqualityMatcherValues(t *testing.T) {
	t.Parallel()
	registry := preparedEqualityRegistry(t)
	values := byteValues(
		"top", "person", "2.5.6.6", "organizationalPerson", "inetOrgPerson",
		"INETORGPERSON", "2.16.840.1.113730.3.2.2", "alias", "2.5.6.1",
		"customPerson", "personAlias", "1.2.3.20", "customChild", "multipleParents",
		"orphanClass", "cycleA", "cycleB", "unknownClass", "UNKNOWNCLASS", "1.2.3.999",
		" inetOrgPerson ", "\t2.16.840.1.113730.3.2.2\n", "\u00a0person\u2003",
		" unknownClass ", " 1.2.3.999 ", "inet OrgPerson", "", " ", "\t\n",
		"{0}inetOrgPerson", "{bad}person", "\x00", "\xff", "\xfe", "x\xff", "X\xff",
		"x\ufffd", "\ufffd", "\u212a", "k", "\u017f", "s",
	)
	values = append(values, nil)
	for _, description := range []string{"objectClass", "2.5.4.0", "CLASSALIAS", " objectClass ; lang- "} {
		for index, assertion := range values {
			t.Run(fmt.Sprintf("%s/assertion%d", description, index), func(t *testing.T) {
				matcher, err := registry.PrepareEqualityMatcher(description, assertion)
				if err != nil {
					t.Fatal(err)
				}
				filter := directory.Filter{Kind: directory.FilterEquality, Attribute: description, Assertion: assertion}
				for _, candidate := range []string{"objectClass;lang-en", "childAlias;lang-en", "grandchildClass;lang-en", "orderedClass;lang-en"} {
					for _, value := range values {
						entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: [][]byte{value}}}}
						checkPreparedEquality(t, registry, matcher, filter, entry)
					}
				}
			})
		}
	}
}

func TestPreparedEqualityMatcherDescriptions(t *testing.T) {
	t.Parallel()
	registry := preparedEqualityRegistry(t)
	descriptions := []string{
		"objectClass", "OBJECTCLASS", "2.5.4.0", "classAlias", " objectClass ",
		"objectClass;lang-en", "objectClass;LANG-EN", "objectClass;lang-",
		"objectClass;lang-en-us", "objectClass;lang", "objectClass;binary",
		"objectClass;binary;lang-en", "objectClass;lang-en;binary", "objectClass;lang-en;lang-en",
		"objectClass;", "objectClass;;", " objectClass ; lang-en ; ",
		"objectClass;unknown", "objectClass;x=y", "objectClass;\xff", "objectClass;\x00",
	}
	candidates := append(append([]string(nil), descriptions...),
		"childClass", "childAlias;lang-en", "1.2.3.10;binary;lang-en-us",
		"grandchildClass;lang-en", "orderedClass;lang-en", "cn", "structuralObjectClass",
		"unknown", "1.2.3.999", "", ";objectClass", "objectClass\xff", "object Class")
	for _, description := range descriptions {
		t.Run(description, func(t *testing.T) {
			for _, assertion := range []string{"person", "unknownClass", "", "\xff"} {
				matcher, err := registry.PrepareEqualityMatcher(description, []byte(assertion))
				if err != nil {
					t.Fatal(err)
				}
				filter := directory.Filter{Kind: directory.FilterEquality, Attribute: description, Assertion: []byte(assertion)}
				checkPreparedEquality(t, registry, matcher, filter, directory.Entry{})
				for _, candidate := range candidates {
					for _, values := range [][][]byte{nil, {}, {nil}, byteValues("inetOrgPerson"), byteValues(assertion), byteValues("alias", "\xff", "inetOrgPerson")} {
						entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: values}}}
						checkPreparedEquality(t, registry, matcher, filter, entry)
					}
				}
				entry := directory.Entry{Attributes: []directory.Attribute{
					{Description: "cn", Values: byteValues(assertion)},
					{Description: "objectClass", Values: byteValues("alias")},
					{Description: "classAlias;lang-en", Values: byteValues("\xff", "inetOrgPerson")},
					{Description: "objectClass;lang-en", Values: byteValues(assertion)},
				}}
				checkPreparedEquality(t, registry, matcher, filter, entry)
			}
		})
	}
}

func TestPreparedEqualityMatcherSemantics(t *testing.T) {
	t.Parallel()
	registry := preparedEqualityRegistry(t)
	for _, test := range []struct {
		name, description, candidate, value, assertion string
		want                                           bool
	}{
		{"descendant", "objectClass", "objectClass", "customChild", "person", true},
		{"known OID", "2.5.4.0", "classAlias", "1.2.3.20", "inetOrgPerson", true},
		{"known spaces", "objectClass", "objectClass", " inetOrgPerson ", " person ", true},
		{"unknown raw", "objectClass", "objectClass", "UNKNOWNCLASS", "unknownClass", true},
		{"unknown spaces preserved", "objectClass", "objectClass", " unknownClass ", "unknownClass", false},
		{"unknown OID spaces preserved", "objectClass", "objectClass", "1.2.3.999", " 1.2.3.999 ", false},
		{"unknown raw spaces equal", "objectClass", "objectClass", " UNKNOWNCLASS ", " unknownClass ", true},
		{"empty value", "objectClass", "objectClass", "", "", true},
		{"invalid UTF8", "objectClass", "objectClass", "\xff", "\xff", true},
		{"lowercase not EqualFold", "objectClass", "objectClass", "\u017f", "s", false},
		{"malformed request with values", " objectClass ; ", "classAlias;", "person", "person", true},
		{"option wildcard", "objectClass;lang-", "childAlias;lang-en-us", "inetOrgPerson", "person", true},
		{"exact language", "objectClass;lang-en", "objectClass;lang-en-us", "person", "person", false},
		{"subtype rule not used", "objectClass", "grandchildClass", "INETORGPERSON", "person", true},
		{"subtype ordered flag not used", "objectClass", "orderedClass", "{0}inetOrgPerson", "person", false},
		{"subtype raw ordered value", "objectClass", "orderedClass", "{0}inetOrgPerson", "{0}INETORGPERSON", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			matcher, err := registry.PrepareEqualityMatcher(test.description, []byte(test.assertion))
			if err != nil {
				t.Fatal(err)
			}
			filter := directory.Filter{Kind: directory.FilterEquality, Attribute: test.description, Assertion: []byte(test.assertion)}
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: test.candidate, Values: byteValues(test.value)}}}
			checkPreparedEquality(t, registry, matcher, filter, entry)
			if got, err := matcher.Match(entry); err != nil || got != test.want {
				t.Fatalf("Match = %v, %v; want %v, nil", got, err, test.want)
			}
			if got, err := matcher.Match(directory.Entry{}); err != nil || got {
				t.Fatalf("absent Match = %v, %v; want false, nil", got, err)
			}
		})
	}
}

func TestPreparedEqualityMatcherFallback(t *testing.T) {
	t.Parallel()
	registry := preparedEqualityRegistry(t)
	for _, description := range []string{"", "missing", "1.2.3.999", "cn", "structuralObjectClass", "childClass", "orderedClass", "authzTo", "objectClass\xff"} {
		if matcher, err := registry.PrepareEqualityMatcher(description, []byte("person")); err == nil || matcher != nil {
			t.Fatalf("PrepareEqualityMatcher(%q) = %v, %v; want nil, error", description, matcher, err)
		}
	}
	for _, test := range []struct {
		name, rule, superior string
		ordered              bool
	}{
		{name: "ordered", rule: "objectIdentifierMatch", ordered: true},
		{name: "other rule", rule: "caseIgnoreMatch"},
		{name: "unsupported rule", rule: "unknownRule"},
		{name: "no rule"},
		{name: "unknown superior", rule: "objectIdentifierMatch", superior: "missing"},
		{name: "inheritance cycle", rule: "objectIdentifierMatch", superior: "objectClass"},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistry()
			attribute := AttributeType{OID: "2.5.4.0", Names: []string{"objectClass"}, Equality: test.rule, Superior: test.superior}
			if test.ordered {
				attribute.Extensions = map[string][]string{"X-ORDERED": {"VALUES"}}
			}
			if err := registry.RegisterAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			if matcher, err := registry.PrepareEqualityMatcher("objectClass", []byte("person")); err == nil || matcher != nil {
				t.Fatalf("PrepareEqualityMatcher = %v, %v; want nil, error", matcher, err)
			}
		})
	}
	var matcher *PreparedEqualityMatcher
	if matched, err := matcher.Match(directory.Entry{}); matched || err == nil {
		t.Fatalf("nil Match = %v, %v", matched, err)
	}
}

func TestPreparedEqualityMatcherRuleOIDAndOwnership(t *testing.T) {
	t.Parallel()
	for _, rule := range []string{"objectIdentifierMatch", "OBJECTIDENTIFIERMATCH", "2.5.13.0"} {
		t.Run(rule, func(t *testing.T) {
			registry := preparedEqualityRegistry(t)
			attribute, _ := registry.AttributeType("objectClass")
			attribute.Equality = rule
			if err := registry.UpsertAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			// As with PreparedSubstringMatcher, schema setup ends before preparing.
			for _, assertion := range byteValues("person", "unknownClass", "\xff") {
				original := bytes.Clone(assertion)
				matcher, err := registry.PrepareEqualityMatcher("objectClass", assertion)
				if err != nil {
					t.Fatal(err)
				}
				assertion[0] = '!'
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: "objectClass", Values: [][]byte{original}}}}
				before := entry.Clone()
				filter := directory.Filter{Kind: directory.FilterEquality, Attribute: "objectClass", Assertion: original}
				checkPreparedEquality(t, registry, matcher, filter, entry)
				if !reflect.DeepEqual(entry, before) {
					t.Fatal("Match changed entry values")
				}
				entry.Attributes[0].Values[0] = []byte("unrelatedClass")
				checkPreparedEquality(t, registry, matcher, filter, entry)
			}
		})
	}
}

func FuzzPreparedEqualityMatcher(f *testing.F) {
	registry := preparedEqualityRegistry(f)
	for _, seed := range [][4]string{
		{"objectClass", "objectClass", "inetOrgPerson", "person"},
		{"2.5.4.0", "childAlias;lang-en", "1.2.3.20", "inetOrgPerson"},
		{" objectClass ; lang- ", "classAlias;LANG-EN", " PERSON ", " person "},
		{"objectClass;", "objectClass;;", "\xff", "\xff"},
		{"objectClass", "objectClass", "X\xff", "x\ufffd"},
		{"objectClass", "objectClass", " UNKNOWN ", "unknown"},
		{"objectClass", "orderedClass", "{0}person", "person"},
		{"objectClass", "", "", ""},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, description, candidate, value, assertion string) {
		matcher, err := registry.PrepareEqualityMatcher(description, []byte(assertion))
		if err != nil {
			return
		}
		filter := directory.Filter{Kind: directory.FilterEquality, Attribute: description, Assertion: []byte(assertion)}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: byteValues(value)}}}
		checkPreparedEquality(t, registry, matcher, filter, entry)
		checkPreparedEquality(t, registry, matcher, filter, directory.Entry{})
	})
}
