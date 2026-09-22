package schema

import (
	"fmt"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func BenchmarkPreparedSubstringQueryPlan(b *testing.B) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		b.Fatal(err)
	}
	classes, err := registry.PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		b.Fatal(err)
	}
	for _, fixture := range []struct {
		name  string
		count int
	}{
		{"ordinary11", 11},
		{"fallback65", 65},
	} {
		entry := preparedNameBenchmarkEntry()
		entry.Attributes = entry.Attributes[:11]
		for len(entry.Attributes) < fixture.count {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description: fmt.Sprintf("description;lang-x%d", len(entry.Attributes)),
				Values:      byteValues("sample"),
			})
		}
		if fixture.count > 64 {
			// Exercise a target beyond the bitmap boundary in the fallback path.
			entry.Attributes[1], entry.Attributes[64] = entry.Attributes[64], entry.Attributes[1]
		}
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
			b.Run(fixture.name+"/"+assertion.name+"/sequential", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if flags := classes.Match(entry); flags != 0 {
						b.Fatalf("unexpected special entry: flags=%x", flags)
					}
					if matched, err := matcher.Match(entry); err != nil || matched != assertion.want {
						b.Fatalf("Match = %v/%v, want %v/nil", matched, err, assertion.want)
					}
				}
			})
			b.Run(fixture.name+"/"+assertion.name+"/plan", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					flags, selected := plan.Classify(entry)
					if flags != 0 {
						b.Fatalf("unexpected special entry: flags=%x", flags)
					}
					if matched, err := plan.Match(entry, selected); err != nil || matched != assertion.want {
						b.Fatalf("Match = %v/%v, want %v/nil", matched, err, assertion.want)
					}
				}
			})
		}
	}
}
