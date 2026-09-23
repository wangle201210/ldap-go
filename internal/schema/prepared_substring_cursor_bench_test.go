package schema

import (
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkPreparedSubstringQueryCursor(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	classes, err := registry.PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		b.Fatal(err)
	}
	entry := preparedNameBenchmarkEntry()
	entry.Attributes = entry.Attributes[:11]
	reordered := entry.Clone()
	slices.Reverse(reordered.Attributes)
	for _, fixture := range []struct {
		name    string
		entries [2]directory.Entry
	}{
		{"stable11", [2]directory.Entry{entry, entry}},
		{"alternating11", [2]directory.Entry{entry, reordered}},
	} {
		for _, assertion := range []struct {
			name, prefix string
			want         bool
		}{
			{"hit", "sam", true},
			{"miss", "missing", false},
		} {
			matcher, err := registry.PrepareSubstringMatcher("uid", directory.Substring{Initial: []byte(assertion.prefix)})
			if err != nil {
				b.Fatal(err)
			}
			plan := matcher.WithObjectClasses(classes)
			b.Run(fixture.name+"/"+assertion.name+"/plan", func(b *testing.B) {
				b.ReportAllocs()
				row := 0
				for b.Loop() {
					entry := fixture.entries[row]
					row ^= 1
					flags, selected := plan.Classify(entry)
					if matched, err := plan.Match(entry, selected); flags != 0 || matched != assertion.want || err != nil {
						b.Fatalf("flags=%x Match=%v/%v, want 0/%v/nil", flags, matched, err, assertion.want)
					}
				}
			})
			b.Run(fixture.name+"/"+assertion.name+"/cursor", func(b *testing.B) {
				cursor := plan.NewCursor()
				// Warm stable layouts and exhaust admissions for alternating layouts.
				for row := range maxPreparedSubstringCursorCopies {
					entry := fixture.entries[row%2]
					flags, selected := cursor.Classify(entry)
					if matched, err := cursor.Match(entry, selected); flags != 0 || matched != assertion.want || err != nil {
						b.Fatalf("flags=%x Match=%v/%v, want 0/%v/nil", flags, matched, err, assertion.want)
					}
				}
				b.ReportAllocs()
				row := 0
				for b.Loop() {
					entry := fixture.entries[row]
					row ^= 1
					flags, selected := cursor.Classify(entry)
					if matched, err := cursor.Match(entry, selected); flags != 0 || matched != assertion.want || err != nil {
						b.Fatalf("flags=%x Match=%v/%v, want 0/%v/nil", flags, matched, err, assertion.want)
					}
				}
			})
		}
	}
}
