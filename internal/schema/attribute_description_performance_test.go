package schema

import (
	"maps"
	"strings"
	"testing"
)

func referenceSplitAttributeDescription(description string) (string, map[string]struct{}) {
	parts := strings.Split(strings.TrimSpace(description), ";")
	options := make(map[string]struct{}, len(parts)-1)
	for _, option := range parts[1:] {
		options[schemaKey(option)] = struct{}{}
	}
	return parts[0], options
}

func FuzzSplitAttributeDescription(f *testing.F) {
	for _, description := range []string{
		"", "uid", " CN ", "2.5.4.3", "cn;lang-en", "cn;LANG-en;lang-en",
		"userCertificate;binary", "cn;", "cn;;", " ; ", " cn ; LANG-en ; binary ",
		"cn;lang-", "cn;lang-en-US", "cn\x00", "\xff;\xfe",
	} {
		f.Add(description)
	}
	f.Fuzz(func(t *testing.T, description string) {
		name, options := splitAttributeDescription(description)
		wantName, wantOptions := referenceSplitAttributeDescription(description)
		if name != wantName || !maps.Equal(options, wantOptions) {
			t.Fatalf("split(%q) = (%q, %v), want (%q, %v)", description, name, options, wantName, wantOptions)
		}
	})
}

var benchmarkAttributeName string
var benchmarkAttributeOptions map[string]struct{}

func BenchmarkSplitAttributeDescription(b *testing.B) {
	for _, description := range []string{"uid", " CN ", "cn;lang-en", "userCertificate;binary;lang-en"} {
		b.Run(description, func(b *testing.B) {
			for _, implementation := range []struct {
				name  string
				split func(string) (string, map[string]struct{})
			}{
				{"reference", referenceSplitAttributeDescription},
				{"current", splitAttributeDescription},
			} {
				b.Run(implementation.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						benchmarkAttributeName, benchmarkAttributeOptions = implementation.split(description)
					}
				})
			}
		})
	}
}
