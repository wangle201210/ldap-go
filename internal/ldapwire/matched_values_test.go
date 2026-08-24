package ldapwire

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestDecodeValuesReturnFilter(t *testing.T) {
	value := encodeValuesReturnFilterForTest(
		t,
		"(mail=*@example.com)",
		"(member=uid=alice,dc=example,dc=com)",
		"(uidNumber>=1000)",
		"(description=*)",
		"(cn:caseIgnoreMatch:=alice)",
	)
	filters, err := DecodeValuesReturnFilter(value)
	if err != nil {
		t.Fatalf("DecodeValuesReturnFilter(): %v", err)
	}
	want := []directory.FilterKind{
		directory.FilterSubstrings,
		directory.FilterEquality,
		directory.FilterGreaterOrEqual,
		directory.FilterPresent,
		directory.FilterExtensible,
	}
	if len(filters) != len(want) {
		t.Fatalf("decoded filter count = %d, want %d", len(filters), len(want))
	}
	for index := range want {
		if filters[index].Kind != want[index] {
			t.Fatalf("filter %d kind = %d, want %d", index, filters[index].Kind, want[index])
		}
	}
}

func TestDecodeValuesReturnFilterRejectsInvalidEncoding(t *testing.T) {
	for _, test := range []struct {
		name  string
		value []byte
	}{
		{name: "empty", value: nil},
		{name: "wrong outer tag", value: []byte{0x31, 0x00}},
		{name: "trailing data", value: []byte{0x30, 0x00, 0x05, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeValuesReturnFilter(test.value); err == nil {
				t.Fatal("invalid values return filter was accepted")
			}
		})
	}
	if filters, err := DecodeValuesReturnFilter([]byte{0x30, 0x00}); err != nil || len(filters) != 0 {
		t.Fatalf("empty sequence = %#v, %v", filters, err)
	}
	ignored := encodeValuesReturnFilterForTest(t, "(&(uid=alice)(cn=Alice))")
	if filters, err := DecodeValuesReturnFilter(ignored); err != nil ||
		len(filters) != 1 || filters[0].Kind != directory.FilterComputed {
		t.Fatalf("unknown complex item = %#v, %v", filters, err)
	}
	dnAttributes := encodeValuesReturnFilterForTest(t, "(:dn:caseIgnoreMatch:=alice)")
	if filters, err := DecodeValuesReturnFilter(dnAttributes); err != nil ||
		len(filters) != 1 || !filters[0].DNAttributes {
		t.Fatalf("OpenLDAP-compatible dnAttributes = %#v, %v", filters, err)
	}
}

func encodeValuesReturnFilterForTest(t *testing.T, values ...string) []byte {
	t.Helper()
	sequence := ber.NewSequence("values return filter")
	for _, value := range values {
		filter, err := ldap.CompileFilter(value)
		if err != nil {
			t.Fatalf("CompileFilter(%q): %v", value, err)
		}
		sequence.AppendChild(filter)
	}
	return sequence.Bytes()
}
