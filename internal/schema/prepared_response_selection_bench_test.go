package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkPreparedAttributeSelectionResponse(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	selection, ok := registry.PrepareExplicitAttributeSelection([]string{"cn", "member"})
	if !ok {
		b.Fatal("could not prepare attribute selection")
	}
	mixed := responseSelectionTestValues(1000)
	mixed[0], mixed[1] = nil, []byte{}
	mixed[2] = make([]byte, 4096)
	mixed[3] = make([]byte, 4097)
	mixed[500] = make([]byte, 64<<10)
	mixed[999] = make([]byte, 128<<10)
	emptyValues := make([][]byte, 1000)
	for index := range emptyValues {
		emptyValues[index] = []byte{}
	}
	for _, test := range []struct {
		name      string
		values    [][]byte
		typesOnly bool
	}{
		{"values1", responseSelectionTestValues(1), false},
		{"values7", responseSelectionTestValues(7), false},
		{"values8", responseSelectionTestValues(8), false},
		{"values10", responseSelectionTestValues(10), false},
		{"values1000", responseSelectionTestValues(1000), false},
		{"mixedHuge", mixed, false},
		{"nil", nil, false},
		{"empty", [][]byte{}, false},
		{"nilValues", make([][]byte, 1000), false},
		{"emptyValues", emptyValues, false},
		{"typesOnly", mixed, true},
	} {
		b.Run(test.name, func(b *testing.B) {
			entry := directory.Entry{DN: "cn=group,dc=example,dc=com", Attributes: []directory.Attribute{
				{Description: "objectClass", Values: byteValues("groupOfNames")},
				{Description: "cn", Values: byteValues("group")},
				{Description: "member;lang-en", Values: test.values, RawNormalized: true},
				{Description: "unselected", Values: [][]byte{make([]byte, 128<<10)}},
			}}
			b.Run("Select", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					selection.Select(entry, test.typesOnly)
				}
			})
			b.Run("SelectForResponse", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					selection.SelectForResponse(entry, test.typesOnly)
				}
			})
		})
	}
}
