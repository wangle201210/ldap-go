package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Embed only the legacy interfaces so the oracle runs the complete existing
// EvaluateWith path, including absent assertions and non-equality children.
type legacyEqualityMatcher struct {
	directory.ValueMatcher
	directory.AttributeResolver
	directory.FilterAssertionValidator
	directory.OrderingMatcher
	directory.ApproximateMatcher
	directory.DNAttributesResolver
}

func legacyEquality(registry *Registry) legacyEqualityMatcher {
	return legacyEqualityMatcher{registry, registry, registry, registry, registry, registry}
}

func equalityEvaluationRegistry(t testing.TB) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.801", Names: []string{"eqChild", "eqAlias"}, Superior: "uid"},
		{OID: "1.2.3.802", Names: []string{"eqExact"}, Superior: "eqChild", Equality: "caseExactMatch"},
		{OID: "1.2.3.803", Names: []string{"eqOrdered"}, Superior: "uid", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
		{OID: "1.2.3.804", Names: []string{"eqBits"}, Syntax: SyntaxBitString, Equality: "2.5.13.16"},
		{OID: "1.2.3.805", Names: []string{"eqUnknownRule"}, Syntax: SyntaxDirectoryString, Equality: "unregisteredMatch"},
		{OID: "1.2.3.806", Names: []string{"eqNoRule"}, Syntax: SyntaxDirectoryString},
		{OID: "1.2.3.807", Names: []string{"eqOrphan"}, Superior: "unknownParent"},
		{OID: "1.2.3.808", Names: []string{"eqCycleA"}, Superior: "eqCycleB"},
		{OID: "1.2.3.809", Names: []string{"eqCycleB"}, Superior: "eqCycleA"},
		{OID: "1.2.3.810", Names: []string{"eqClassChild"}, Superior: "objectClass", Equality: "caseExactMatch"},
		{OID: "1.2.3.811", Names: []string{"eqOrderedInteger"}, Syntax: SyntaxInteger, Equality: "integerMatch", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
		{OID: "1.2.3.812", Names: []string{"eqOIDRule"}, Syntax: SyntaxDirectoryString, Equality: "2.5.13.2"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, class := range []ObjectClass{
		{OID: "1.2.3.820", Names: []string{"eqPerson", "eqPersonAlias"}, Superiors: []string{"inetOrgPerson"}},
		{OID: "1.2.3.821", Names: []string{"eqMultiParent"}, Superiors: []string{"alias", "eqPerson"}},
		{OID: "1.2.3.822", Names: []string{"eqClassCycleA"}, Superiors: []string{"eqClassCycleB"}},
		{OID: "1.2.3.823", Names: []string{"eqClassCycleB"}, Superiors: []string{"eqClassCycleA", "person"}},
		{OID: "1.2.3.824", Names: []string{"eqClassOrphan"}, Superiors: []string{"missingClass"}},
	} {
		if err := registry.RegisterObjectClass(class); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func equalityLeaf(description, assertion string) directory.Filter {
	return directory.Filter{Kind: directory.FilterEquality, Attribute: description, Assertion: []byte(assertion)}
}

func equalityNode(kind directory.FilterKind, children ...directory.Filter) directory.Filter {
	return directory.Filter{Kind: kind, Children: children}
}

func checkEqualityEvaluation(t testing.TB, registry *Registry, entry directory.Entry, leaf directory.Filter) {
	t.Helper()
	before := entry
	before.Attributes = slices.Clone(entry.Attributes)
	for index := range before.Attributes {
		before.Attributes[index].Values = slices.Clone(entry.Attributes[index].Values)
		for valueIndex, value := range before.Attributes[index].Values {
			before.Attributes[index].Values[valueIndex] = bytes.Clone(value)
		}
	}
	assertionBefore := bytes.Clone(leaf.Assertion)
	trueFilter := equalityNode(directory.FilterAnd)
	falseFilter := equalityNode(directory.FilterOr)
	undefined := equalityLeaf("unknownEqualityAttribute", "x")
	not := equalityNode(directory.FilterNot, leaf)
	for index, filter := range []directory.Filter{
		leaf, not, equalityNode(directory.FilterNot, not),
		equalityNode(directory.FilterAnd, leaf, undefined),
		equalityNode(directory.FilterAnd, undefined, leaf, falseFilter),
		equalityNode(directory.FilterOr, leaf, undefined),
		equalityNode(directory.FilterOr, undefined, leaf, trueFilter),
		equalityNode(directory.FilterNot, equalityNode(directory.FilterOr, not, undefined)),
		equalityNode(directory.FilterNot, equalityNode(directory.FilterAnd, not, undefined)),
		equalityNode(directory.FilterOr,
			equalityNode(directory.FilterAnd, trueFilter, not),
			equalityNode(directory.FilterNot, equalityNode(directory.FilterOr, leaf, falseFilter))),
	} {
		want, wantErr := filter.EvaluateWith(entry, legacyEquality(registry))
		got, gotErr := filter.EvaluateWith(entry, registry)
		if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
			t.Fatalf("tree %d, (%s=%q), entry=%+v: fast=(%v, %v), legacy=(%v, %v)",
				index, leaf.Attribute, leaf.Assertion, entry.Attributes, got, gotErr, want, wantErr)
		}
	}
	if !reflect.DeepEqual(entry, before) || !bytes.Equal(leaf.Assertion, assertionBefore) {
		t.Fatalf("evaluation mutated inputs: (%s=%q)", leaf.Attribute, assertionBefore)
	}
}

func TestEqualityEvaluationValues(t *testing.T) {
	t.Parallel()
	registry := equalityEvaluationRegistry(t)
	for _, fixture := range []struct {
		description string
		values      []string
	}{
		{"uid", []string{"Alice", " alice ", "ALICE", "a\u00a0b", "\u212a", "\u017f"}},
		{"eqExact", []string{"Alice", "ALICE", " alice "}},
		{"eqOIDRule", []string{"Alice", "ALICE", " alice "}},
		{"mail", []string{"USER@example.com", "user@example.com"}},
		{"postalAddress", []string{" One $ Two ", "one$two", "one\\24two"}},
		{"telephoneNumber", []string{"+1 212-555-0123", "+12125550123"}},
		{"internationalISDNNumber", []string{"12 34", "1234", "abc"}},
		{"userPassword", []string{"Secret", "secret", "\x00\xff"}},
		{"eqBits", []string{"'01'B", "'001'B", "''B", "'2'B", "'01'b"}},
		{"uidNumber", []string{"42", "0042", "+42", "-42", "999999999999999999999999999999999"}},
		{"hasSubordinates", []string{"TRUE", "true", "FALSE", "not-a-boolean"}},
		{"member", []string{"CN=Alice,DC=example", "2.5.4.3=alice,dc=example", "cn=Alice+uid=A,dc=example", "cn=\\ff", "not-a-dn"}},
		{"uniqueMember", []string{"cn=Alice,dc=example#'01'B", "CN=alice,DC=example#'01'B", "cn=alice,dc=example", "not-a-dn#'01'B"}},
		{"entryUUID", []string{"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "not-a-uuid"}},
		{"createTimestamp", []string{"20260920000000Z", "20260920010000+0100", "20260920000000.1Z", "not-a-time"}},
		{"entryCSN", []string{"20260920000000.000001Z#000001#001#000000", "20260920000000.000002Z#000001#001#000000", "bad-csn"}},
		{"authzTo", []string{"dn:cn=Alice,dc=example", "dn.exact:cn=Alice,dc=example", "u:alice", "bad-authz"}},
		{"OpenLDAPaci", []string{"1#entry#grant;r;cn#public#", "1#entry#deny;r;cn#public#", "bad-aci"}},
		{"objectClass", []string{"inetOrgPerson", "person", "2.5.6.6", " eqPersonAlias ", "eqMultiParent", "eqClassCycleA", "eqClassOrphan", "UNKNOWN", "unknown", " unknown "}},
		{"eqClassChild", []string{"inetOrgPerson", "person", "PERSON"}},
		{"attributeTypes", []string{"( 2.5.4.3 NAME 'cn' SUP name )", "cn", "CN", "2.5.4.3", "unknownDefinition", "bad identifier"}},
		{"objectClasses", []string{"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )", "person", "2.5.6.6", "unknownClass"}},
		{"matchingRules", []string{"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", "caseIgnoreMatch", "2.5.13.2", "unknownRule"}},
		{"matchingRuleUse", []string{"( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES cn )", "caseIgnoreMatch", "2.5.13.2"}},
		{"ldapSyntaxes", []string{"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )", "1.3.6.1.4.1.1466.115.121.1.15", "Directory String", "1..2"}},
		{"dITStructureRules", []string{"( 42 NAME 'test' FORM 1.2.3 )", "42", "( bad )", "-42"}},
		{"eqOrdered", []string{"{0}Alice", "{1}Bob", "{1}", "{0}ALICE", "Alice", "{bad}Alice", "{}Alice", "{99999999999999999999999999}Alice"}},
		{"eqOrderedInteger", []string{"{0}42", "{1}bad", "{1}", "42", "{bad}42"}},
		{"eqUnknownRule", []string{"Alice"}},
		{"eqNoRule", []string{"Alice"}},
		{"jpegPhoto", []string{"photo"}},
		{"eqOrphan", []string{"Alice"}},
		{"eqCycleA", []string{"Alice"}},
		{"unknownEqualityAttribute", []string{"Alice"}},
	} {
		t.Run(fixture.description, func(t *testing.T) {
			values := byteValues(append(slices.Clone(fixture.values), "", " ", "invalid", "\x00", "\xff", "x\xff", "x\ufffd")...)
			values = append(values, nil)
			for _, assertion := range values {
				filter := directory.Filter{Kind: directory.FilterEquality, Attribute: fixture.description, Assertion: assertion}
				checkEqualityEvaluation(t, registry, directory.Entry{}, filter)
				for _, stored := range append([][][]byte{nil, {}, values, {[]byte("invalid"), assertion}, {assertion, []byte("invalid")}}, singleEqualityValues(values)...) {
					entry := directory.Entry{Attributes: []directory.Attribute{{Description: fixture.description, Values: stored}}}
					checkEqualityEvaluation(t, registry, entry, filter)
				}
			}
		})
	}
}

func singleEqualityValues(values [][]byte) [][][]byte {
	result := make([][][]byte, len(values))
	for index, value := range values {
		result[index] = [][]byte{value}
	}
	return result
}

func TestEqualityEvaluationDescriptions(t *testing.T) {
	t.Parallel()
	registry := equalityEvaluationRegistry(t)
	descriptions := []string{
		"uid", "USERID", "0.9.2342.19200300.100.1.1", " uid ",
		"uid;lang-en", "uid;LANG-EN", "uid;lang-en-us", "uid;lang-", "uid;lang",
		"uid;binary", "uid;binary;lang-en", "uid;lang-en;binary", "uid;lang-en;lang-en",
		"uid;", "uid;;", " uid ; lang-en ; ", "uid;unknown", "uid;x=y", "uid;\xff", "uid;\x00",
		"eqChild", "eqAlias;lang-en", "eqExact;lang-en", "eqOrdered;lang-en", "1.2.3.801;lang-en-us",
		"eqCycleA", "eqOrphan", "unknownEqualityAttribute", "", ";uid", "uid\xff", "u id",
	}
	for _, description := range descriptions {
		t.Run(description, func(t *testing.T) {
			for _, assertion := range []string{"alice", "{0}alice", "\xff", ""} {
				filter := equalityLeaf(description, assertion)
				for _, candidate := range descriptions {
					for _, values := range [][][]byte{nil, {nil}, byteValues("ALICE"), byteValues("invalid", "alice")} {
						entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: values}}}
						checkEqualityEvaluation(t, registry, entry, filter)
					}
				}
				entry := directory.Entry{Attributes: []directory.Attribute{
					{Description: "cn", Values: byteValues(assertion)},
					{Description: "uid", Values: byteValues("different")},
					{Description: "eqAlias;lang-en", Values: byteValues("ALICE")},
					{Description: "eqExact;lang-en", Values: byteValues("alice")},
					{Description: "uid;lang-en", Values: byteValues(assertion)},
				}}
				checkEqualityEvaluation(t, registry, entry, filter)
			}
		})
	}
}

func TestEqualityEvaluationThreeValues(t *testing.T) {
	t.Parallel()
	registry := equalityEvaluationRegistry(t)
	for _, test := range []struct {
		name, requested, candidate, assertion string
		values                                []string
		want                                  directory.FilterResult
	}{
		{"missing known", "uid", "cn", "alice", []string{"alice"}, directory.FilterFalseResult},
		{"missing unknown", "unknown", "uid", "alice", []string{"alice"}, directory.FilterUndefinedResult},
		{"present unknown", "unknown", "unknown", "alice", []string{"alice"}, directory.FilterUndefinedResult},
		{"no equality", "jpegPhoto", "jpegPhoto", "photo", []string{"photo"}, directory.FilterUndefinedResult},
		{"empty selected values", "createTimestamp", "createTimestamp", "bad-time", nil, directory.FilterUndefinedResult},
		{"invalid then match", "createTimestamp", "createTimestamp", "20260920000000Z", []string{"bad-time", "20260920000000Z"}, directory.FilterTrueResult},
		{"match then invalid", "createTimestamp", "createTimestamp", "20260920000000Z", []string{"20260920000000Z", "bad-time"}, directory.FilterTrueResult},
		{"invalid then miss", "createTimestamp", "createTimestamp", "20260920000000Z", []string{"bad-time", "20260921000000Z"}, directory.FilterUndefinedResult},
		{"all misses", "uid", "uid", "alice", []string{"bob", "carol"}, directory.FilterFalseResult},
		{"invalid assertion", "eqBits", "eqBits", "'2'B", []string{"'2'B"}, directory.FilterUndefinedResult},
		{"parent rule selects subtype", "uid", "eqExact", "alice", []string{"ALICE"}, directory.FilterTrueResult},
		{"subtype own rule", "eqExact", "eqExact", "alice", []string{"ALICE"}, directory.FilterFalseResult},
		{"class ancestry through subtype", "objectClass", "eqClassChild", "person", []string{"eqMultiParent"}, directory.FilterTrueResult},
		{"ordered successful index after invalid", "eqOrderedInteger", "eqOrderedInteger", "{1}", []string{"{bad}42", "{1}bad"}, directory.FilterTrueResult},
		{"option mismatch absent", "uid;lang-en", "uid;lang-en-us", "alice", []string{"alice"}, directory.FilterFalseResult},
		{"option prefix", "uid;lang-", "eqAlias;lang-en-us", "alice", []string{"ALICE"}, directory.FilterTrueResult},
		{"unknown option with values", "uid;unknown", "uid;unknown", "alice", []string{"alice"}, directory.FilterTrueResult},
		{"unknown option absent", "uid;unknown", "uid", "alice", []string{"alice"}, directory.FilterUndefinedResult},
		{"raw invalid boolean with values", "hasSubordinates", "hasSubordinates", "invalid", []string{"invalid"}, directory.FilterTrueResult},
		{"invalid boolean absent", "hasSubordinates", "hasSubordinates", "invalid", nil, directory.FilterUndefinedResult},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: test.candidate, Values: byteValues(test.values...)}}}
			filter := equalityLeaf(test.requested, test.assertion)
			checkEqualityEvaluation(t, registry, entry, filter)
			if got, err := filter.EvaluateWith(entry, registry); err != nil || got != test.want {
				t.Fatalf("EvaluateWith = %v, %v; want %v, nil", got, err, test.want)
			}
		})
	}
}

func TestEqualityEvaluationMixedFilters(t *testing.T) {
	t.Parallel()
	registry := equalityEvaluationRegistry(t)
	entry := directory.Entry{DN: "uid=alice,dc=example", Attributes: []directory.Attribute{
		{Description: "uid", Values: byteValues("ALICE")},
		{Description: "uidNumber", Values: byteValues("42")},
	}}
	for _, child := range []directory.Filter{
		{Kind: directory.FilterPresent, Attribute: "uid"},
		{Kind: directory.FilterApprox, Attribute: "uid", Assertion: []byte("alice")},
		{Kind: directory.FilterSubstrings, Attribute: "uid", Substring: directory.Substring{Initial: []byte("al")}},
		{Kind: directory.FilterGreaterOrEqual, Attribute: "uidNumber", Assertion: []byte("40")},
		{Kind: directory.FilterLessOrEqual, Attribute: "uidNumber", Assertion: []byte("bad")},
		{Kind: directory.FilterExtensible, Attribute: "uid", MatchingRule: "caseExactMatch", Assertion: []byte("ALICE")},
		{Kind: directory.FilterExtensible, Attribute: "dc", DNAttributes: true, Assertion: []byte("example")},
		{Kind: directory.FilterExtensible, MatchingRule: "caseIgnoreMatch", Assertion: []byte("alice")},
		{Kind: directory.FilterNot},
		{Kind: directory.FilterNot, Children: []directory.Filter{equalityLeaf("uid", "alice"), equalityLeaf("uid", "bob")}},
	} {
		filter := equalityNode(directory.FilterAnd, equalityLeaf("uid", "alice"), child)
		checkEqualityEvaluation(t, registry, entry, filter)
	}
}

type overriddenEqualityRegistry struct {
	*Registry
	hideValues   bool
	valueCalls   int
	compareCalls int
}

func (wrapper *overriddenEqualityRegistry) AttributeValues(entry directory.Entry, description string) [][]byte {
	wrapper.valueCalls++
	if wrapper.hideValues {
		return nil
	}
	return wrapper.Registry.AttributeValues(entry, description)
}

func (wrapper *overriddenEqualityRegistry) Compare(_, _ string, _, _ []byte) (int, error) {
	wrapper.compareCalls++
	return 1, nil
}

func TestEqualityEvaluationWrappedLegacyOverrides(t *testing.T) {
	t.Parallel()
	registry := equalityEvaluationRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "uid", Values: byteValues("alice")}}}
	filter := equalityLeaf("uid", "alice")
	for _, hideValues := range []bool{false, true} {
		t.Run(fmt.Sprintf("hideValues=%t", hideValues), func(t *testing.T) {
			wrapper := &overriddenEqualityRegistry{Registry: registry, hideValues: hideValues}
			// The adapter hides the promoted evaluator while preserving the
			// dynamic dispatch of the wrapper's visibility and comparison rules.
			matcher := legacyEqualityMatcher{wrapper, wrapper, wrapper, wrapper, wrapper, wrapper}
			if _, exposed := any(matcher).(interface {
				EvaluateEquality(directory.Entry, string, []byte) (directory.FilterResult, bool)
			}); exposed {
				t.Fatal("legacy adapter exposes equality evaluator")
			}
			if got, err := filter.EvaluateWith(entry, matcher); err != nil || got != directory.FilterFalseResult {
				t.Fatalf("wrapped evaluation = %v, %v; want false, nil", got, err)
			}
			wantComparisons := 1
			if hideValues {
				wantComparisons = 0
			}
			if wrapper.valueCalls != 1 || wrapper.compareCalls != wantComparisons {
				t.Fatalf("override calls = values %d, comparisons %d; want 1, %d", wrapper.valueCalls, wrapper.compareCalls, wantComparisons)
			}
		})
	}
}

func FuzzEqualityEvaluation(f *testing.F) {
	registry := equalityEvaluationRegistry(f)
	for _, seed := range [][5]string{
		{"uid", "USERID;lang-en", "ALICE", "bob", "alice"},
		{"createTimestamp", "createTimestamp", "bad", "20260920000000Z", "20260920000000Z"},
		{"eqBits", "eqBits", "'01'B", "'2'B", "'2'B"},
		{"uid;lang-", "eqAlias;lang-en", "\xff", "ALICE", "alice"},
		{"objectClass", "eqClassChild", "eqMultiParent", "\xff", "person"},
		{"attributeTypes", "attributeTypes", "bad", "( 2.5.4.3 NAME 'cn' SUP name )", "cn"},
		{"eqOrderedInteger", "eqOrderedInteger", "{bad}42", "{1}bad", "{1}"},
		{"member", "member", "not-a-dn", "CN=Alice,DC=example", "cn=alice,dc=example"},
		{"eqUnknownRule", "eqUnknownRule", "value", "", "value"},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4])
	}
	f.Fuzz(func(t *testing.T, description, candidate, first, second, assertion string) {
		filter := equalityLeaf(description, assertion)
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: byteValues(first, second)}}}
		checkEqualityEvaluation(t, registry, entry, filter)
		checkEqualityEvaluation(t, registry, directory.Entry{}, filter)
	})
}
