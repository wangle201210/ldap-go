package schema

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkPreparedSubstringMatcher(b *testing.B) {
	for _, test := range []struct {
		name, rule string
		ordered    bool
		values     []string
		assertion  directory.Substring
		want       bool
	}{
		{"caseIgnore", "caseIgnoreSubstringsMatch", false, []string{"Other", "Alpha Beta Gamma"}, directory.Substring{Initial: []byte("alpha"), Any: byteValues("beta"), Final: []byte("gamma")}, true},
		{"caseExactMiss", "caseExactSubstringsMatch", false, []string{"Other", "Alpha Beta Gamma"}, directory.Substring{Initial: []byte("alpha")}, false},
		{"octets", "octetStringSubstringsMatch", false, []string{"\x00\xffAlpha"}, directory.Substring{Initial: []byte("\x00\xff")}, true},
		{"numeric", "numericStringSubstringsMatch", false, []string{"12 34 56"}, directory.Substring{Initial: []byte("1 2"), Final: []byte("56")}, true},
		{"telephone", "telephoneNumberSubstringsMatch", false, []string{"+1 234-567"}, directory.Substring{Initial: []byte("+1-2"), Final: []byte("67")}, true},
		{"ordered", "caseIgnoreSubstringsMatch", true, []string{"{0}Other", "{1}Alpha Beta Gamma"}, directory.Substring{Initial: []byte("alpha"), Any: byteValues("beta"), Final: []byte("gamma")}, true},
		{"orderedInvalidThenMatch", "caseIgnoreSubstringsMatch", true, []string{"{bad}Alpha", "{1}Alpha"}, directory.Substring{Initial: []byte("alpha")}, true},
		{"listInvalidThenMatch", "caseIgnoreListSubstringsMatch", false, []string{"Alpha$", "Alpha$Beta"}, directory.Substring{Initial: []byte("alpha"), Final: []byte("beta")}, true},
		{"listUndefined", "caseIgnoreListSubstringsMatch", false, []string{"Alpha$", "Other"}, directory.Substring{Initial: []byte("alpha")}, false},
		{"orderedList", "caseIgnoreListSubstringsMatch", true, []string{"{0}Alpha$", "{1}Alpha$Beta"}, directory.Substring{Initial: []byte("alpha"), Final: []byte("beta")}, true},
		{"absent", "caseIgnoreListSubstringsMatch", false, nil, directory.Substring{Initial: []byte("alpha")}, false},
	} {
		b.Run(test.name, func(b *testing.B) {
			registry := preparedSubstringRegistry(b, test.rule, test.ordered)
			filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: "sample", Substring: test.assertion}
			matcher, err := registry.PrepareSubstringMatcher(filter.Attribute, filter.Substring)
			if err != nil {
				b.Fatal(err)
			}
			entry := directory.Entry{Attributes: []directory.Attribute{
				{Description: "uid", Values: byteValues("user001")},
				{Description: "unrelated", Values: byteValues("Alpha Beta Gamma")},
				{Description: "childAlias;lang-en", Values: byteValues(test.values...)},
				{Description: "description", Values: byteValues("benchmark entry")},
			}}
			checkPreparedSubstring(b, registry, matcher, filter, entry)
			b.Run("general", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if got, err := filter.MatchWith(entry, registry); err != nil || got != test.want {
						b.Fatalf("MatchWith = %v, %v; want %v, nil", got, err, test.want)
					}
				}
			})
			b.Run("prepared", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if got, err := matcher.Match(entry); err != nil || got != test.want {
						b.Fatalf("Match = %v, %v; want %v, nil", got, err, test.want)
					}
				}
			})
		})
	}
}

func BenchmarkPrepareSubstringMatcher(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	assertion := directory.Substring{Initial: []byte(" alpha "), Any: byteValues(" beta "), Final: []byte(" gamma ")}
	for _, description := range []string{"cn", "postalAddress"} {
		b.Run(description, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := registry.PrepareSubstringMatcher(description, assertion); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
