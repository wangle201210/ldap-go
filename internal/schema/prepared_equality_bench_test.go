package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkPreparedEqualityMatcher(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name, description, assertion string
		values                       []string
		want                         bool
	}{
		{"inetOrgPerson", "objectClass", "inetOrgPerson", []string{"top", "person", "organizationalPerson", "inetOrgPerson"}, true},
		{"ancestor", "objectClass", "person", []string{"inetOrgPerson"}, true},
		{"miss", "objectClass", "inetOrgPerson", []string{"top", "alias"}, false},
		{"unknown", "objectClass", "unknownClass", []string{"UNKNOWNCLASS"}, true},
		{"options", "objectClass;lang-", "person", []string{"inetOrgPerson"}, true},
	} {
		b.Run(test.name, func(b *testing.B) {
			entry := directory.Entry{Attributes: []directory.Attribute{
				{Description: "uid", Values: byteValues("user001")},
				{Description: "cn", Values: byteValues("User 001")},
				{Description: "sn", Values: byteValues("001")},
				{Description: "objectClass;lang-en", Values: byteValues(test.values...)},
				{Description: "mail", Values: byteValues("user001@example.com")},
				{Description: "description", Values: byteValues("benchmark entry")},
			}}
			filter := directory.Filter{Kind: directory.FilterEquality, Attribute: test.description, Assertion: []byte(test.assertion)}
			prepared, err := registry.PrepareEqualityMatcher(filter.Attribute, filter.Assertion)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("general", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if got, err := filter.MatchWith(entry, registry); err != nil || got != test.want {
						b.Fatalf("MatchWith = %v, %v", got, err)
					}
				}
			})
			b.Run("prepared", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if got, err := prepared.Match(entry); err != nil || got != test.want {
						b.Fatalf("Match = %v, %v", got, err)
					}
				}
			})
		})
	}
}

func BenchmarkPrepareEqualityMatcher(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	assertion := []byte("inetOrgPerson")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := registry.PrepareEqualityMatcher("objectClass", assertion); err != nil {
			b.Fatal(err)
		}
	}
}
