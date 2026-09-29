package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"weak"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestPreparedAttributeSelectionResponseParity(t *testing.T) {
	t.Parallel()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{0, 1, 7, 8, 10, 1000} {
		values := responseSelectionTestValues(count)
		if count >= 8 {
			values[1] = nil
			values[2] = []byte{}
			values[3] = make([]byte, 4096)
			values[4] = make([]byte, 4097)
		}
		entry := directory.Entry{
			DN: "cn=group,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: byteValues("groupOfNames")},
				{Description: "SN", Values: [][]byte{nil, {}, {0, 255}}, RawNormalized: true},
				{Description: "member;lang-en", Values: values, RawNormalized: true},
				{Description: "2.5.4.3", Values: byteValues("Group")},
				{Description: "cn;lang-fr", Values: byteValues("Groupe")},
				{Description: "description", Values: nil},
				{Description: "jpegPhoto", Values: [][]byte{}},
				{Description: "x-custom;binary", Values: values, RawNormalized: true},
				{Description: "member", Values: values},
				{Description: "userPassword", Values: [][]byte{make([]byte, 128<<10)}},
			},
		}.WithDNIdentityKey("transient identity")
		for _, test := range []struct {
			name      string
			requested []string
		}{
			{"nilSelection", nil},
			{"noAttributes", []string{"1.1"}},
			{"noMatch", []string{"not-present"}},
			{"subtype", []string{"name"}},
			{"mixed", []string{"X-CUSTOM", "name", "MEMBER", "description", "jpegPhoto", "member"}},
		} {
			var selection *PreparedAttributeSelection
			if test.requested != nil {
				var ok bool
				selection, ok = registry.PrepareExplicitAttributeSelection(test.requested)
				if !ok {
					t.Fatalf("could not prepare %v", test.requested)
				}
			}
			for _, typesOnly := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/typesOnly=%t", count, test.name, typesOnly), func(t *testing.T) {
					got := selection.SelectForResponse(entry, typesOnly)
					want := selection.Select(entry, typesOnly)
					assertResponseSelectionParity(t, got, want)
					for index, attribute := range got.Attributes {
						for valueIndex, value := range attribute.Values {
							wantCap := cap(want.Attributes[index].Values[valueIndex])
							if len(attribute.Values) >= 8 && len(value) > 0 && len(value) <= 4096 {
								wantCap = len(value)
							}
							if cap(value) != wantCap {
								t.Fatalf("attribute %d value %d: cap = %d, want %d", index, valueIndex, cap(value), wantCap)
							}
						}
					}
				})
			}
		}
	}
	selection, ok := registry.PrepareExplicitAttributeSelection([]string{"member"})
	if !ok {
		t.Fatal("could not prepare member selection")
	}
	for _, attributes := range [][]directory.Attribute{nil, {}} {
		entry := directory.Entry{DN: "cn=empty", Attributes: attributes}
		for _, typesOnly := range []bool{false, true} {
			assertResponseSelectionParity(t, selection.SelectForResponse(entry, typesOnly), selection.Select(entry, typesOnly))
		}
	}
}

func assertResponseSelectionParity(t *testing.T, got, want directory.Entry) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatal("response selection differs from Select (including order, metadata or nil/empty values)")
	}
	if cap(got.Attributes) != cap(want.Attributes) {
		t.Fatalf("attribute capacity = %d, want %d", cap(got.Attributes), cap(want.Attributes))
	}
	for index, attribute := range got.Attributes {
		if cap(attribute.Values) != cap(want.Attributes[index].Values) {
			t.Fatalf("attribute %d value capacity = %d, want %d", index, cap(attribute.Values), cap(want.Attributes[index].Values))
		}
	}
}

func TestPreparedAttributeSelectionResponseOwnership(t *testing.T) {
	t.Parallel()
	selection := &PreparedAttributeSelection{attributes: map[string]struct{}{"member": {}}}
	for _, count := range []int{1, 7, 8, 10, 1000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			backing := bytes.Repeat([]byte("abcdef"), 1024)
			values := make([][]byte, count)
			for index := range values {
				values[index] = backing[index%8 : index%8+80]
			}
			if count >= 8 {
				values[3], values[4] = nil, backing[:0]
				values[5], values[6] = backing[:4096], backing[:4097]
			}
			entry := directory.Entry{Attributes: []directory.Attribute{
				{Description: "member", Values: values},
				{Description: "MEMBER;binary", Values: values},
				{Description: "unselected", Values: [][]byte{backing}},
			}}
			got := selection.SelectForResponse(entry, false)
			second := selection.SelectForResponse(entry, false)
			want := selection.Select(entry, false)
			clear(backing)
			assertResponseSelectionParity(t, got, want)
			assertResponseSelectionParity(t, second, want)
			sourceAfterClear := entry.Clone()

			for attributeIndex, attribute := range got.Attributes {
				for _, index := range []int{0, min(1, count-1), min(5, count-1), min(6, count-1), count / 2, count - 1} {
					value := attribute.Values[index]
					if len(value) != 0 {
						value[0] ^= 0xff
						assertResponseSelectionParity(t, second, want)
						want.Attributes[attributeIndex].Values[index][0] ^= 0xff
						assertResponseSelectionParity(t, got, want)
						value[0] ^= 0xff
						want.Attributes[attributeIndex].Values[index][0] ^= 0xff
					}
					appended := append(value, 0xff)
					if appended[len(value)] != 0xff {
						t.Fatal("append did not preserve the added byte")
					}
					assertResponseSelectionParity(t, got, want)
				}
			}
			got.Attributes[0].Description = "changed"
			got.Attributes[0].Values[0] = []byte("changed")
			assertResponseSelectionParity(t, second, want)
			if !reflect.DeepEqual(entry, sourceAfterClear) {
				t.Fatal("response mutation changed source values or slice headers")
			}
		})
	}
}

func TestPreparedAttributeSelectionResponseBoundedRetention(t *testing.T) {
	for _, keep := range []int{0, 511, 999} {
		t.Run(fmt.Sprint(keep), func(t *testing.T) {
			retained, references, source := responseSelectionRetentionFixture(keep)
			runtime.GC()
			live := 0
			for _, reference := range references {
				if reference.Value() != nil {
					live++
				}
			}
			sourceRetained := source.Value() != nil
			runtime.KeepAlive(retained)
			if sourceRetained {
				t.Fatal("retained source backing storage containing unselected data")
			}
			if live == 0 || live*80 > 4096 {
				t.Fatalf("one 80-byte value retained %d values (%d bytes), want at most 4096 bytes", live, live*80)
			}
		})
	}
}

func responseSelectionRetentionFixture(keep int) ([]byte, []weak.Pointer[byte], weak.Pointer[byte]) {
	backing := bytes.Repeat([]byte{'x'}, 128<<10)
	values := make([][]byte, 1000)
	for index := range values {
		values[index] = backing[index : index+80]
	}
	selection := &PreparedAttributeSelection{attributes: map[string]struct{}{"member": {}}}
	selected := selection.SelectForResponse(directory.Entry{Attributes: []directory.Attribute{
		{Description: "unselected", Values: [][]byte{backing}},
		{Description: "member", Values: values},
	}}, false)
	// Weak references distinguish separate blocks from capped views of one 80 KB
	// allocation. The 80-byte values also exceed the GC's tiny allocation size.
	references := make([]weak.Pointer[byte], len(values))
	for index, value := range selected.Attributes[0].Values {
		references[index] = weak.Make(&value[0])
	}
	return selected.Attributes[0].Values[keep], references, weak.Make(&backing[0])
}

func TestPreparedAttributeSelectionResponseAllocations(t *testing.T) {
	selection := &PreparedAttributeSelection{attributes: map[string]struct{}{"member": {}}}
	for _, count := range []int{1, 7, 1000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			entry := directory.Entry{Attributes: []directory.Attribute{
				{Description: "member", Values: responseSelectionTestValues(count)},
			}}
			var retained directory.Entry
			baseline := testing.AllocsPerRun(10, func() { retained = selection.Select(entry, false) })
			compact := testing.AllocsPerRun(10, func() { retained = selection.SelectForResponse(entry, false) })
			runtime.KeepAlive(retained)
			if count < 8 && compact != baseline {
				t.Fatalf("small response allocations = %g, want %g", compact, baseline)
			}
			if count == 1000 && compact >= baseline/4 {
				t.Fatalf("compact allocations = %g, want less than a quarter of baseline %g", compact, baseline)
			}
		})
	}
}

func responseSelectionTestValues(count int) [][]byte {
	values := make([][]byte, count, count+3)
	for index := range values {
		values[index] = fmt.Appendf(nil, "uid=user%04d,ou=people,dc=example,dc=com", index)
	}
	return values
}
