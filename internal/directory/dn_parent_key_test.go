package directory

import (
	"reflect"
	"strings"
	"testing"
)

func TestDNParentKeyReference(t *testing.T) {
	if key, ok := (DN{}).ParentKey(); key != "" || ok {
		t.Fatal("zero DN has a parent")
	}
	for _, raw := range []string{"", "DC=COM", "uid=Alice,DC=EXAMPLE,dc=COM", `cn=\ leading\ +uid=Alice,dc=COM`, "exactAlias=Root,dc=COM", strings.Repeat("ou=people,", 130) + "dc=com"} {
		original := mustDN(t, raw)
		normalized, err := original.NormalizeWith(scopeIdentityNormalizer{})
		if err != nil {
			t.Fatal(err)
		}
		physical, err := ParseDNWithIdentityKey(raw, normalized.Key())
		if err != nil {
			t.Fatal(err)
		}
		for _, dn := range []DN{original, normalized, physical} {
			parent, wantOK := dn.Parent()
			got, ok := dn.ParentKey()
			if ok != wantOK || ok && got != parent.Key() {
				t.Fatalf("%q: parent key=%q/%v, want %q/%v", raw, got, ok, parent.Key(), wantOK)
			}
			before := dn
			if dn.Depth() != 0 {
				values := dn.RDNValues()
				values[0].Type = "changed"
				clear(values[0].Value)
			}
			for range 10 {
				other, otherOK := dn.ParentKey()
				if other != got || otherOK != ok || !reflect.DeepEqual(dn, before) {
					t.Fatal("parent key ownership changed")
				}
			}
		}
	}
}

func BenchmarkDNParentKey(b *testing.B) {
	dn, err := ParseDNWithNormalizer("uid=alice,ou=people,dc=example,dc=com", scopeIdentityNormalizer{})
	if err != nil {
		b.Fatal(err)
	}
	parent, _ := dn.Parent()
	for _, direct := range []bool{false, true} {
		name := "Parent"
		if direct {
			name = "ParentKey"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var key string
				if direct {
					key, _ = dn.ParentKey()
				} else {
					parent, _ := dn.Parent()
					key = parent.Key()
				}
				if key != parent.Key() {
					b.Fatal("parent key differs")
				}
			}
		})
	}
}
