package schema

import (
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestNormalizeOrderedEntryValues(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{Attributes: []directory.Attribute{
		{Description: "authzTo", Values: byteValues(
			"{2}dn:uid=third,dc=example,dc=com",
			"{0}dn:uid=first,dc=example,dc=com",
			"{1}dn:uid=second,dc=example,dc=com",
		)},
		{Description: "description", Values: byteValues("unchanged")},
	}}
	if err := registry.NormalizeOrderedEntryValues(&entry); err != nil {
		t.Fatal(err)
	}
	if got, want := stringsFromValues(entry.Attributes[0].Values), []string{
		"{0}dn:uid=first,dc=example,dc=com",
		"{1}dn:uid=second,dc=example,dc=com",
		"{2}dn:uid=third,dc=example,dc=com",
	}; !slices.Equal(got, want) {
		t.Fatalf("ordered values = %q, want %q", got, want)
	}
	if got := stringsFromValues(entry.Attributes[1].Values); !slices.Equal(got, []string{"unchanged"}) {
		t.Fatalf("ordinary values = %q", got)
	}

	for _, values := range [][][]byte{
		byteValues("{0}first", "second"),
		byteValues("{0}first", "{0}duplicate"),
		byteValues("{bad}first"),
	} {
		if _, err := NormalizeOrderedValues(values); err == nil {
			t.Fatalf("NormalizeOrderedValues(%q) succeeded", stringsFromValues(values))
		}
	}
}

func TestOrderedValueMatchingIgnoresOrSelectsIndex(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		assertion string
		wantEqual bool
	}{
		{assertion: "dn:uid=alice,dc=example,dc=com", wantEqual: true},
		{assertion: "{2}", wantEqual: true},
		{assertion: "{2}dn:uid=alice,dc=example,dc=com", wantEqual: true},
		{assertion: "{1}dn:uid=alice,dc=example,dc=com"},
		{assertion: "{2}dn:uid=bob,dc=example,dc=com"},
	} {
		comparison, err := registry.Compare(
			"authzTo",
			"",
			[]byte("{2}dn:uid=alice,dc=example,dc=com"),
			[]byte(test.assertion),
		)
		if err != nil || (comparison == 0) != test.wantEqual {
			t.Fatalf("Compare(%q) = %d, %v; equal=%v", test.assertion, comparison, err, test.wantEqual)
		}
	}
	if err := registry.ValidateAttributeValue(
		"authzTo",
		[]byte("{0}dn:uid=alice,dc=example,dc=com"),
	); err != nil {
		t.Fatalf("ValidateAttributeValue(ordered authzTo): %v", err)
	}
}

func stringsFromValues(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}
