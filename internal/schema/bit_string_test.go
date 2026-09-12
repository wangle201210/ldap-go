package schema

import (
	"bytes"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestBitStringSyntaxAndMatching(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ParseAndRegisterAttributeType("( 1.2.3.4 NAME 'bits' EQUALITY 2.5.13.16 SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"''B", "'0'B", "'1'B", "'00101'B"} {
		if err := registry.ValidateAttributeValue("bits", []byte(value)); err != nil {
			t.Fatal(err)
		}
		normalized, err := registry.NormalizeEqualityValue("bits", []byte(value))
		if err != nil || !bytes.Equal(normalized, []byte(value)) {
			t.Fatalf("bit representation changed: %q %v", normalized, err)
		}
		for _, rule := range []string{"", "bitStringMatch", "2.5.13.16"} {
			if cmp, err := registry.Compare("bits", rule, []byte(value), []byte(value)); err != nil || cmp != 0 {
				t.Fatalf("matching failed: %d %v", cmp, err)
			}
		}
	}
	for _, value := range []string{"", "0", "'2'B", "'01'b", " '01'B", "'01'B ", "'0 1'B", "'\x00'B", "'\xff'B"} {
		if err := registry.ValidateAttributeValue("bits", []byte(value)); err == nil {
			t.Fatalf("invalid bit string accepted: %q", value)
		}
		if _, err := registry.Compare("bits", "", []byte("'01'B"), []byte(value)); err == nil {
			t.Fatalf("invalid bit assertion accepted: %q", value)
		}
	}
	if cmp, err := registry.Compare("bits", "", []byte("'01'B"), []byte("'001'B")); err != nil || cmp == 0 {
		t.Fatal("significant leading bit lost")
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "cn", Values: [][]byte{[]byte("'01'B")}}}}
	filter := directory.Filter{Kind: directory.FilterExtensible, Attribute: "cn", MatchingRule: "bitStringMatch", Assertion: []byte("'01'B")}
	if result, err := filter.EvaluateWith(entry, registry); err != nil || result != directory.FilterUndefinedResult {
		t.Fatalf("incompatible bit matching: %v %v", result, err)
	}
}
