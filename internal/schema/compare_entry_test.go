package schema

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Keep the former public-method sequence as an oracle for a stable registry.
func originalCompareEntryAttribute(registry *Registry, entry directory.Entry, description string, assertion []byte) (bool, bool, error) {
	if !registry.HasAttributeDescription(entry, description) {
		return false, false, nil
	}
	for _, value := range registry.AttributeValues(entry, description) {
		comparison, err := registry.Compare(description, "", value, assertion)
		if err != nil {
			return true, false, err
		}
		if comparison == 0 {
			return true, true, nil
		}
	}
	return true, false, nil
}

func checkCompareEntryAttribute(t testing.TB, registry *Registry, entry directory.Entry, description string, assertion []byte) (bool, bool, error) {
	t.Helper()
	before := entry
	before.Attributes = slices.Clone(entry.Attributes)
	for i := range before.Attributes {
		before.Attributes[i].Values = slices.Clone(entry.Attributes[i].Values)
		for j, value := range before.Attributes[i].Values {
			before.Attributes[i].Values[j] = bytes.Clone(value)
		}
	}
	assertionBefore := bytes.Clone(assertion)
	wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, description, assertion)
	present, matched, err := registry.CompareEntryAttribute(entry, description, assertion)
	if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
		t.Fatalf("%s=%q: got (%v, %v, %T: %v), want (%v, %v, %T: %v)", description, assertion,
			present, matched, err, err, wantPresent, wantMatched, wantErr, wantErr)
	}
	if !reflect.DeepEqual(entry, before) || !reflect.DeepEqual(assertion, assertionBefore) {
		t.Fatal("comparison mutated entry or assertion")
	}
	return present, matched, err
}

func TestCompareEntryAttribute(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, test := range []struct {
		name, requested, candidate, assertion string
		values                                [][]byte
		present, matched, wantErr             bool
	}{
		{"absent", "uid", "cn", "alice", byteValues("alice"), false, false, false},
		{"absent invalid assertion", "eqBits", "cn", "bad", nil, false, false, false},
		{"empty nil", "uid", "uid", "alice", nil, true, false, false},
		{"empty slice", "uid", "uid", "alice", [][]byte{}, true, false, false},
		{"empty invalid assertion", "eqBits", "eqBits", "bad", nil, true, false, false},
		{"nil value", "userPassword", "userPassword", "", [][]byte{nil}, true, true, false},
		{"nil value error", "member", "member", "bad-dn", [][]byte{nil}, true, false, true},
		{"alias OID", "USERID", "0.9.2342.19200300.100.1.1", "alice", byteValues("ALICE"), true, true, false},
		{"subtype options", "uid;lang-", "1.2.3.801;LANG-EN;binary", "alice", byteValues("ALICE"), true, true, false},
		{"alias options", "1.2.3.801;lang-en", "eqAlias;lang-en", "alice", byteValues("ALICE"), true, true, false},
		{"option mismatch", "uid;lang-en", "uid;lang-en-us", "alice", byteValues("alice"), false, false, false},
		{"requested parent rule", "uid", "eqExact", "alice", byteValues("ALICE"), true, true, false},
		{"requested child rule", "eqExact", "eqExact", "alice", byteValues("ALICE"), true, false, false},
		{"binary", "userPassword;binary", "userPassword;binary", "\x00\xff", byteValues("\x00\xff"), true, true, false},
		{"binary case sensitive", "userPassword", "userPassword", "secret", byteValues("Secret"), true, false, false},
		{"ordered index", "eqOrderedInteger", "eqOrderedInteger", "{1}", byteValues("{1}bad"), true, true, false},
		{"ordered content", "eqOrdered", "eqOrdered", "alice", byteValues("{0}ALICE"), true, true, false},
		{"ordered invalid", "eqOrderedInteger", "eqOrderedInteger", "{1}", byteValues("{bad}42", "{1}bad"), true, false, true},
		{"DN aliases", "member", "member", "cn=alice,dc=example", byteValues("2.5.4.3=ALICE,DC=example"), true, true, false},
		{"DN invalid", "member", "member", "cn=alice", byteValues("bad-dn", "cn=alice"), true, false, true},
		{"objectClass ancestry", "objectClass", "objectClass", "person", byteValues("eqMultiParent"), true, true, false},
		{"objectClass alias", "objectClass", "objectClass", "1.2.3.820", byteValues("eqPersonAlias"), true, true, false},
		{"schema description", "attributeTypes", "attributeTypes", "cn", byteValues("( 2.5.4.3 NAME 'cn' SUP name )"), true, true, false},
		{"bit assertion", "eqBits", "eqBits", "'2'B", byteValues("'2'B"), true, false, true},
		{"unknown attribute", "unknownCompare", "unknownCompare", "x", byteValues("x"), true, false, true},
		{"no rule", "eqNoRule", "eqNoRule", "x", byteValues("x"), true, false, true},
		{"unknown rule", "eqUnknownRule", "eqUnknownRule", "x", byteValues("x"), true, false, true},
		{"orphan", "eqOrphan", "eqOrphan", "x", byteValues("x"), true, false, true},
		{"cycle", "eqCycleA", "eqCycleA", "x", byteValues("x"), true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{DN: "uid=alice,dc=example", Attributes: []directory.Attribute{{Description: test.candidate, Values: test.values, RawNormalized: true}}}
			present, matched, err := checkCompareEntryAttribute(t, registry, entry, test.requested, []byte(test.assertion))
			if present != test.present || matched != test.matched || (err != nil) != test.wantErr {
				t.Fatalf("got (%v, %v, %v), want (%v, %v, error=%v)", present, matched, err, test.present, test.matched, test.wantErr)
			}
		})
	}
	checkCompareEntryAttribute(t, registry, directory.Entry{}, "uid", nil)
	shared := []byte(" ALICE ")
	checkCompareEntryAttribute(t, registry, directory.Entry{Attributes: []directory.Attribute{{Description: "uid", Values: [][]byte{shared}}}}, "uid", shared)
}

func TestCompareEntryAttributeStopsInOrder(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, matchFirst := range []bool{false, true} {
		for _, split := range []bool{false, true} {
			t.Run(fmt.Sprintf("matchFirst=%t/split=%t", matchFirst, split), func(t *testing.T) {
				values := byteValues("bad-time", "20260920000000Z")
				if matchFirst {
					slices.Reverse(values)
				}
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: "createTimestamp", Values: values}}}
				if split {
					entry.Attributes[0].Values = values[:1]
					entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "createTimestamp;lang-en", Values: values[1:]})
				}
				present, matched, err := checkCompareEntryAttribute(t, registry, entry, "createTimestamp", []byte("20260920000000Z"))
				if !present || matched != matchFirst || (err != nil) == matchFirst {
					t.Fatalf("got (%v, %v, %v), matchFirst=%v", present, matched, err, matchFirst)
				}
			})
		}
	}
}

func TestCompareEntryAttributeSchemaErrors(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, description := range []string{"attributeTypes", "objectClasses", "matchingRules", "matchingRuleUse"} {
		for _, assertion := range []string{"unknownCompareIdentifier", "bad identifier"} {
			t.Run(description+"/"+assertion, func(t *testing.T) {
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: description, Values: byteValues("( 2.5.4.3 NAME 'cn' )")}}}
				present, matched, err := checkCompareEntryAttribute(t, registry, entry, description, []byte(assertion))
				typed, ok := errors.AsType[*SchemaDescriptionAssertionError](err)
				if !present || matched || !ok || typed.Unknown != (assertion == "unknownCompareIdentifier") {
					t.Fatalf("lost schema error classification: (%v, %v, %#v)", present, matched, err)
				}
			})
		}
	}
}

func TestCompareEntryAttributeSchemaChange(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "eqExact", Values: byteValues("ALICE")}}}
	attribute, _ := registry.AttributeType("eqExact")
	for _, rule := range []string{"caseExactMatch", "caseIgnoreMatch", "caseExactMatch"} {
		attribute.Equality = rule
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		present, matched, err := checkCompareEntryAttribute(t, registry, entry, "eqExact", []byte("alice"))
		if !present || err != nil || matched != (rule == "caseIgnoreMatch") {
			t.Fatalf("after %s: (%v, %v, %v)", rule, present, matched, err)
		}
	}
}

func TestCompareEntryAttributeDNAssertionReuse(t *testing.T) {
	registry := equalityEvaluationRegistry(t)
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.850", Names: []string{"compareDNChild"}, Superior: "member"},
		{OID: "1.2.3.851", Names: []string{"compareDNOID"}, Equality: "2.5.13.1", Syntax: SyntaxDistinguishedName, SyntaxLength: 1},
		{OID: "1.2.3.852", Names: []string{"compareDNOrdered"}, Equality: "distinguishedNameMatch", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, description := range []string{"member", "compareDNChild", "compareDNOID", "compareDNOrdered"} {
		for _, values := range [][]string{
			{"cn=other", "cn=Alice"}, {"cn=other", "bad-dn", "cn=Alice"},
			{"cn=Alice", "bad-dn"}, {"{0}cn=other", "{1}cn=Alice"},
		} {
			entry := directory.Entry{Attributes: []directory.Attribute{
				{Description: description},
				{Description: description + ";lang-en", Values: byteValues(values[0])},
				{Description: description, Values: byteValues(values[1:]...)},
			}}
			for _, assertion := range []string{"cn=alice", "cn=absent", "bad-dn", "", "{1}"} {
				checkCompareEntryAttribute(t, registry, entry, description, []byte(assertion))
			}
		}
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "member", Values: byteValues("eqExact=bob", "eqExact=ALICE")}}}
	attribute, _ := registry.AttributeType("eqExact")
	for _, rule := range []string{"caseExactMatch", "caseIgnoreMatch", "caseExactMatch"} {
		attribute.Equality = rule
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		present, matched, err := checkCompareEntryAttribute(t, registry, entry, "member", []byte("eqExact=alice"))
		if !present || err != nil || matched != (rule == "caseIgnoreMatch") {
			t.Fatalf("DN assertion reused across schema change: (%v, %v, %v)", present, matched, err)
		}
	}
}

func FuzzCompareEntryAttribute(f *testing.F) {
	registry := equalityEvaluationRegistry(f)
	for _, seed := range [][5]string{
		{"uid;lang-", "eqAlias;lang-en", "ALICE", "bob", "alice"},
		{"member", "member", "bad-dn", "cn=alice", "cn=alice"},
		{"objectClasses", "objectClasses", "( 2.5.6.6 NAME 'person' )", "", "unknownClass"},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4])
	}
	f.Fuzz(func(t *testing.T, description, candidate, first, second, assertion string) {
		if len(description)+len(candidate)+len(first)+len(second)+len(assertion) > 4096 {
			t.Skip()
		}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: byteValues(first, second)}}}
		checkCompareEntryAttribute(t, registry, entry, description, []byte(assertion))
	})
}

func benchmarkCompareEntryAttribute(b *testing.B, description string, values [][]byte, assertion []byte) {
	registry := equalityEvaluationRegistry(b)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: description, Values: values}}}
	wantPresent, wantMatched, wantErr := originalCompareEntryAttribute(registry, entry, description, assertion)
	for _, implementation := range []string{"original", "new"} {
		b.Run(implementation, func(b *testing.B) {
			compare := registry.CompareEntryAttribute
			if implementation == "original" {
				compare = func(entry directory.Entry, description string, assertion []byte) (bool, bool, error) {
					return originalCompareEntryAttribute(registry, entry, description, assertion)
				}
			}
			present, matched, err := compare(entry, description, assertion)
			if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
				b.Fatalf("fixture mismatch: (%v, %v, %v)", present, matched, err)
			}
			b.ReportAllocs()
			for b.Loop() {
				present, matched, err = compare(entry, description, assertion)
			}
			if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
				b.Fatalf("comparison mismatch: (%v, %v, %v)", present, matched, err)
			}
		})
	}
}

func BenchmarkCompareEntryAttributeUIDSingle(b *testing.B) {
	benchmarkCompareEntryAttribute(b, "uid", byteValues("Alice"), []byte("alice"))
}

func BenchmarkCompareEntryAttributeGroup1000(b *testing.B) {
	values := make([][]byte, 1000)
	for i := range values {
		values[i] = fmt.Appendf(nil, "cn=user%d,ou=people,dc=example", i)
	}
	for _, test := range []struct{ name, assertion string }{
		{"first", string(values[0])}, {"last", string(values[999])}, {"absent", "cn=absent,ou=people,dc=example"},
	} {
		b.Run(test.name, func(b *testing.B) {
			benchmarkCompareEntryAttribute(b, "member", values, []byte(test.assertion))
		})
	}
}

func BenchmarkCompareEntryAttributeError(b *testing.B) {
	benchmarkCompareEntryAttribute(b, "createTimestamp", byteValues("bad-time", "20260920000000Z"), []byte("20260920000000Z"))
}
