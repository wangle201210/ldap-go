package schema

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func checkSubstringASCIIValue(t testing.TB, value []byte, caseIgnore bool) {
	t.Helper()
	before := bytes.Clone(value)
	normalize := normalizeSpace
	if caseIgnore {
		normalize = normalizeCaseIgnore
	}
	want := normalize(value)
	got := normalizeSubstringASCIIValue(value, caseIgnore)
	if !bytes.Equal(got, want) {
		t.Fatalf("normalize(%x, caseIgnore=%v) = %x, want %x", value, caseIgnore, got, want)
	}
	if !bytes.Equal(value, before) {
		t.Fatalf("normalization modified input: %x, want %x", value, before)
	}
	identity := substringASCIIIdentity(value, caseIgnore)
	if identity {
		if !bytes.Equal(value, want) {
			t.Fatalf("false identity for %x, caseIgnore=%v", value, caseIgnore)
		}
		if (got == nil) != (value == nil) || cap(got) != cap(value) {
			t.Fatal("identity did not preserve the input slice")
		}
	}
	if len(value) > 0 && len(got) > 0 && (&got[0] == &value[0]) != identity {
		t.Fatalf("unexpected borrowing for %x, caseIgnore=%v, identity=%v", value, caseIgnore, identity)
	}
}

func TestSubstringASCIIIdentity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		value         []byte
		ignore, exact bool
	}{
		{"nil", nil, true, true},
		{"empty", []byte{}, true, true},
		{"empty with capacity", make([]byte, 0, 8), true, true},
		{"lowercase", []byte("alpha-123_beta@example.org"), true, true},
		{"uppercase", []byte("ALPHA"), false, true},
		{"late uppercase", []byte("alphaZ"), false, true},
		{"nonspace controls", []byte("\x00\x01\x08\x0e\x1c\x1f\x7f"), true, true},
		{"space", []byte(" "), false, false},
		{"already normalized space", []byte("alpha beta"), false, false},
		{"leading space", []byte(" alpha"), false, false},
		{"trailing space", []byte("alpha "), false, false},
		{"tab", []byte("a\tb"), false, false},
		{"newline", []byte("a\nb"), false, false},
		{"vertical tab", []byte("a\vb"), false, false},
		{"form feed", []byte("a\fb"), false, false},
		{"carriage return", []byte("a\rb"), false, false},
		{"all whitespace", []byte(" \t\n\v\f\r"), false, false},
		{"unicode lowercase", []byte("caf\u00e9"), false, false},
		{"unicode case fold", []byte("\u212a\u00c9"), false, false},
		{"unicode whitespace", []byte("\u00a0alpha\u2003beta\u0085"), false, false},
		{"invalid utf8", []byte("a\xff\xc0\x80z"), false, false},
		{"truncated utf8", []byte("alpha\xe2\x80"), false, false},
		{"literal braces", []byte("{12}alpha"), true, true},
		{"literal invalid prefix", []byte("{bad}alpha"), true, true},
		{"maximum short value", bytes.Repeat([]byte("a"), maxSubstringASCIIIdentityBytes), true, true},
		{"long value", bytes.Repeat([]byte("a"), maxSubstringASCIIIdentityBytes+1), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, caseIgnore := range []bool{false, true} {
				want := test.exact
				if caseIgnore {
					want = test.ignore
				}
				if got := substringASCIIIdentity(test.value, caseIgnore); got != want {
					t.Fatalf("identity(%x, caseIgnore=%v) = %v, want %v", test.value, caseIgnore, got, want)
				}
				checkSubstringASCIIValue(t, test.value, caseIgnore)
			}
		})
	}
}

func TestSubstringASCIIAllBytes(t *testing.T) {
	t.Parallel()
	for _, caseIgnore := range []bool{false, true} {
		for first := 0; first < 256; first++ {
			checkSubstringASCIIValue(t, []byte{byte(first)}, caseIgnore)
			checkSubstringASCIIValue(t, []byte{'a', byte(first), 'z'}, caseIgnore)
			for second := 0; second < 256; second++ {
				checkSubstringASCIIValue(t, []byte{byte(first), byte(second)}, caseIgnore)
			}
		}
	}
}

func TestSubstringASCIIOrderedContent(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"{12}alpha", "{0}Alpha", "{1} alpha  beta ", "{2}\x00\x7f", "{3}\u212a", "{4}\xff", "{5}"} {
		entryValue := []byte(raw)
		_, parsed, indexed, err := ParseOrderedValue(entryValue)
		if err != nil || !indexed {
			t.Fatalf("ParseOrderedValue(%q) = indexed %v, error %v", raw, indexed, err)
		}
		// Also exercise a content view backed by the original entry value.
		content := entryValue[bytes.IndexByte(entryValue, '}')+1:]
		if !bytes.Equal(content, parsed) {
			t.Fatal("content differs from the ordered parser")
		}
		for _, caseIgnore := range []bool{false, true} {
			checkSubstringASCIIValue(t, parsed, caseIgnore)
			checkSubstringASCIIValue(t, content, caseIgnore)
		}
		if string(entryValue) != raw {
			t.Fatal("normalization modified the ordered entry value")
		}
	}
}

func TestSubstringASCIIAssertionOwnership(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		rule, value string
		caseIgnore  bool
	}{
		{"caseIgnoreSubstringsMatch", "alphabetaomega", true},
		{"caseIgnoreIA5SubstringsMatch", "alphabetaomega", true},
		{"caseExactSubstringsMatch", "AlphaBetaOmega", false},
		{"caseExactIA5SubstringsMatch", "AlphaBetaOmega", false},
	} {
		t.Run(test.rule, func(t *testing.T) {
			registry := preparedSubstringRegistry(t, test.rule, false)
			assertion := directory.Substring{
				Initial: []byte(test.value[:5]),
				Any:     [][]byte{[]byte(test.value[5:9])},
				Final:   []byte(test.value[9:]),
			}
			matcher, err := registry.PrepareSubstringMatcher("sample", assertion)
			if err != nil {
				t.Fatal(err)
			}
			assertion.Initial[0] = '!'
			assertion.Any[0][0] = '!'
			assertion.Final[0] = '!'
			value := []byte(test.value)
			candidate := normalizeSubstringASCIIValue(value, test.caseIgnore)
			if &candidate[0] != &value[0] {
				t.Fatal("identity candidate was not borrowed")
			}
			if !matchNormalizedSubstring(candidate, matcher.substring) {
				t.Fatal("prepared assertion aliases the caller's assertion")
			}
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: "sample", Values: [][]byte{value}}}}
			if got, err := matcher.Match(entry); err != nil || !got {
				t.Fatalf("owned assertion match = %v, %v; want true, nil", got, err)
			}
			if string(value) != test.value {
				t.Fatal("matching modified the entry value")
			}
			value[0] = '!'
			if got, err := matcher.Match(entry); err != nil || got {
				t.Fatalf("match after entry mutation = %v, %v; want false, nil", got, err)
			}
		})
	}
}

func FuzzSubstringASCIIValue(f *testing.F) {
	for _, value := range [][]byte{nil, {}, []byte("alpha"), []byte("ALPHA"), []byte(" a\tb "), []byte("\x00\x1f\x7f"), []byte("\xff\xc0\x80"), []byte("\u212a\u00e9\u00a0\u2003"), []byte("{1}alpha"), []byte(strings.Repeat("alpha", 64))} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		checkSubstringASCIIValue(t, value, false)
		checkSubstringASCIIValue(t, value, true)
	})
}

func BenchmarkSubstringASCIIValue(b *testing.B) {
	for _, mode := range []struct {
		name       string
		caseIgnore bool
		normalize  func([]byte) []byte
	}{
		{"caseIgnore", true, normalizeCaseIgnore},
		{"caseExact", false, normalizeSpace},
	} {
		for _, test := range []struct {
			name, value string
		}{
			{"empty", ""},
			{"lowercase", "alpha-123_beta@example.org"},
			{"uppercase", "Alpha-123_Beta@example.org"},
			{"controls", "alpha\x00\x1f\x7f"},
			{"whitespace", " alpha  beta\tgamma "},
			{"unicode", "caf\u00e9\u212a"},
			{"invalidUTF8", "alpha\xffbeta"},
			{"longASCII", strings.Repeat("alpha", 256)},
			{"lateFallback", strings.Repeat("alpha", 256) + " "},
		} {
			b.Run(mode.name+"/"+test.name, func(b *testing.B) {
				value := []byte(test.value)
				checkSubstringASCIIValue(b, value, mode.caseIgnore)
				b.Run("original", func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(value)))
					for b.Loop() {
						mode.normalize(value)
					}
				})
				b.Run("wrapper", func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(value)))
					for b.Loop() {
						normalizeSubstringASCIIValue(value, mode.caseIgnore)
					}
				})
			})
		}
	}
}
