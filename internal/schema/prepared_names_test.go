package schema

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestPreparedAttributeNamesMatchResolver(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.910", Names: []string{"k", "mixedAlias"}, Superior: "objectClass"}); err != nil {
		t.Fatal(err)
	}
	descriptions := []string{"", " unknown ", "\u212a", "u\u0130d", "\xff", "cn;", ";cn"}
	for key, attribute := range registry.attributes {
		descriptions = append(descriptions, key)
		for _, name := range attribute.Names {
			descriptions = append(descriptions, name, strings.ToUpper(name), strings.ToLower(name), " \t"+name+"\u00a0", name+";lang-EN", name+" ;binary")
		}
	}
	for _, target := range []string{"uid", "objectClass", "name", "k"} {
		registry.mu.RLock()
		prepared := registry.prepareAttributeNames(registry.attributes[schemaKey(target)])
		registry.mu.RUnlock()
		for _, candidate := range descriptions {
			if got, want := prepared.match(candidate), registry.AttributeDescriptionSubtype(candidate, target); got != want {
				t.Fatalf("%q <: %q: got %v, want %v", candidate, target, got, want)
			}
		}
	}
}

func objectClassFoldReference(matcher *PreparedObjectClassMatcher, entry directory.Entry) uint64 {
	var result uint64
	for _, attribute := range entry.Attributes {
		description, _, _ := strings.Cut(attribute.Description, ";")
		if !matcher.attributes[schemaKey(description)] {
			continue
		}
		for _, value := range attribute.Values {
			result |= matcher.flags[schemaKey(string(value))]
		}
	}
	return result
}

func TestPreparedObjectClassExactSpellings(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := registry.PrepareObjectClassMatcher("top", "person", "alias", "subentry")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"missingClass", "", "\xff", "\u212a", "\u00a0INETORGPERSON\t"}
	for key, class := range registry.objectClasses {
		names = append(names, key)
		for _, name := range class.Names {
			names = append(names, name, strings.ToUpper(name), strings.ToLower(name), " "+name+" ")
		}
	}
	for _, description := range []string{"objectClass", "OBJECTCLASS", " objectClass ;binary", "2.5.4.0", "description", "bogus", "\xff"} {
		for _, name := range names {
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: description, Values: [][]byte{[]byte(name), []byte("organizationalPerson")}}}}
			if got, want := matcher.Match(entry), objectClassFoldReference(matcher, entry); got != want {
				t.Fatalf("%q/%q: flags=%x, want %x", description, name, got, want)
			}
		}
	}
}

func FuzzPreparedKnownNames(f *testing.F) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		f.Fatal(err)
	}
	if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.910", Names: []string{"k", "mixedAlias"}, Superior: "objectClass"}); err != nil {
		f.Fatal(err)
	}
	matcher, err := registry.PrepareObjectClassMatcher("top", "person", "alias", "subentry")
	if err != nil {
		f.Fatal(err)
	}
	registry.mu.RLock()
	names := registry.prepareAttributeNames(registry.attributes["uid"])
	registry.mu.RUnlock()
	for _, seed := range [][2]string{{"objectClass", "inetOrgPerson"}, {" OBJECTCLASS ;lang-en", " \tPERSON "}, {"uid", "\xff"}, {"\u212a", "alias"}, {"createTimestamp", "top"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, description, value string) {
		if got, want := names.match(description), registry.AttributeDescriptionSubtype(description, "uid"); got != want {
			t.Fatalf("attribute %q: got %v, want %v", description, got, want)
		}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: description, Values: [][]byte{[]byte(value)}}}}
		if got, want := matcher.Match(entry), objectClassFoldReference(matcher, entry); got != want {
			t.Fatalf("object class %q/%q: got %x, want %x", description, value, got, want)
		}
	})
}

func preparedNameBenchmarkEntry() directory.Entry {
	entry := directory.Entry{DN: "uid=sample,dc=example"}
	for _, name := range []string{"objectClass", "uid", "cn", "sn", "description", "createTimestamp", "modifyTimestamp", "entryCSN", "entryUUID", "creatorsName", "modifiersName", "structuralObjectClass"} {
		value := "sample"
		if name == "objectClass" {
			value = "inetOrgPerson"
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{Description: name, Values: [][]byte{[]byte(value)}})
	}
	return entry
}

func BenchmarkPreparedObjectClassNames(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	matcher, err := registry.PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		b.Fatal(err)
	}
	entry := preparedNameBenchmarkEntry()
	for _, direct := range []bool{false, true} {
		name := "fold"
		if direct {
			name = "known-spellings"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var got uint64
				if direct {
					got = matcher.Match(entry)
				} else {
					got = objectClassFoldReference(matcher, entry)
				}
				if got != 0 {
					b.Fatal("unexpected class flags")
				}
			}
		})
	}
}
