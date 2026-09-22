package schema

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

var preparedSubstringRules = []struct {
	name, oid string
}{
	{"caseIgnoreSubstringsMatch", "2.5.13.4"},
	{"caseExactSubstringsMatch", "2.5.13.7"},
	{"caseIgnoreIA5SubstringsMatch", "1.3.6.1.4.1.1466.109.114.3"},
	{"caseExactIA5SubstringsMatch", "1.3.6.1.4.1.4203.1.2.1"},
	{"numericStringSubstringsMatch", "2.5.13.10"},
	{"caseIgnoreListSubstringsMatch", "2.5.13.12"},
	{"telephoneNumberSubstringsMatch", "2.5.13.21"},
	{"octetStringSubstringsMatch", "2.5.13.19"},
}

func preparedSubstringRegistry(t testing.TB, rule string, ordered bool) *Registry {
	t.Helper()
	syntax := SyntaxDirectoryString
	switch canonicalMatchingRule(rule) {
	case "caseignoreia5substringsmatch", "caseexactia5substringsmatch":
		syntax = SyntaxIA5String
	case "numericstringsubstringsmatch":
		syntax = SyntaxNumericString
	case "caseignorelistsubstringsmatch":
		syntax = SyntaxPostalAddress
	case "telephonenumbersubstringsmatch":
		syntax = SyntaxTelephoneNumber
	case "octetstringsubstringsmatch":
		syntax = SyntaxOctetString
	}
	attribute := AttributeType{OID: "1.2.3.1", Names: []string{"sample", "sampleAlias"}, Syntax: syntax, Substring: rule}
	if ordered {
		attribute.Extensions = map[string][]string{"X-ORDERED": {"VALUES"}}
	}
	registry := NewRegistry()
	for _, candidate := range []AttributeType{
		attribute,
		{OID: "1.2.3.2", Names: []string{"child", "childAlias"}, Superior: "sampleAlias"},
		{OID: "1.2.3.3", Names: []string{"grandchild"}, Superior: "childAlias", Substring: "octetStringSubstringsMatch"},
		{OID: "1.2.3.4", Names: []string{"orderedChild"}, Superior: "sample", Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
		{OID: "1.2.3.5", Names: []string{"siblingsChild"}, Superior: "sample", Extensions: map[string][]string{"X-ORDERED": {"SIBLINGS"}}},
		{OID: "1.2.3.6", Names: []string{"unrelated"}, Syntax: syntax, Substring: rule},
	} {
		if err := registry.RegisterAttributeType(candidate); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func checkPreparedSubstring(t testing.TB, registry *Registry, matcher *PreparedSubstringMatcher, filter directory.Filter, entry directory.Entry) {
	t.Helper()
	want, wantErr := filter.MatchWith(entry, registry)
	got, gotErr := matcher.Match(entry)
	if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("attribute=%q substring=%+v entry=%+v: prepared=(%v, %v), general=(%v, %v)",
			filter.Attribute, filter.Substring, entry.Attributes, got, gotErr, want, wantErr)
	}
}

func TestPreparedSubstringMatcherRootSemantics(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, rule           string
		ordered              bool
		requested, candidate string
		values               []string
		assertion            directory.Substring
		want                 directory.FilterResult
	}{
		{"ordered initial", "caseIgnoreSubstringsMatch", true, "sample", "sample", []string{"{12}Alpha Beta"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"ordered prefix is not content", "caseIgnoreSubstringsMatch", true, "sample", "sample", []string{"{12}Alpha"}, directory.Substring{Any: byteValues("{12}")}, directory.FilterFalseResult},
		{"ordered assertion stays literal", "caseIgnoreSubstringsMatch", true, "sample", "sample", []string{"{12}Alpha"}, directory.Substring{Initial: []byte("{12}")}, directory.FilterFalseResult},
		{"ordered invalid then match", "caseIgnoreSubstringsMatch", true, "sample", "sample", []string{"{bad}Alpha", "{2}Alpha"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"ordered invalid only", "caseIgnoreSubstringsMatch", true, "sample", "sample", []string{"{bad}Alpha"}, directory.Substring{Any: byteValues("alpha")}, directory.FilterUndefinedResult},
		{"ordered overflow", "caseIgnoreSubstringsMatch", true, "sample", "sample", []string{"{999999999999999999999999999999}Alpha"}, directory.Substring{}, directory.FilterUndefinedResult},
		{"ordered parent strips child", "caseIgnoreSubstringsMatch", true, "sample", "childAlias;lang-en", []string{"{2}Alpha"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"child does not inherit ordered flag", "caseIgnoreSubstringsMatch", true, "child", "child", []string{"{2}Alpha"}, directory.Substring{Initial: []byte("{2}")}, directory.FilterTrueResult},
		{"candidate ordered flag not used", "caseIgnoreSubstringsMatch", false, "sample", "orderedChild", []string{"{2}Alpha"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterFalseResult},
		{"candidate ordered prefix stays literal", "caseIgnoreSubstringsMatch", false, "sample", "orderedChild", []string{"{2}Alpha"}, directory.Substring{Initial: []byte("{2}")}, directory.FilterTrueResult},
		{"inherited rule", "caseIgnoreSubstringsMatch", false, "childAlias", "child;lang-en", []string{"ALPHA"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"candidate rule not used", "caseIgnoreSubstringsMatch", false, "sample", "grandchild", []string{"ALPHA"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"requested rule override", "caseIgnoreSubstringsMatch", false, "grandchild", "grandchild", []string{"ALPHA"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterFalseResult},
		{"ordered siblings stays literal", "caseIgnoreSubstringsMatch", false, "siblingsChild", "siblingsChild", []string{"{2}Alpha"}, directory.Substring{Initial: []byte("{2}")}, directory.FilterTrueResult},
		{"list invalid then match", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{"Alpha$", "Alpha$Beta"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"list match then invalid", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{"Alpha$Beta", "Alpha$"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"list invalid and miss", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{"Alpha$", "Other"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterUndefinedResult},
		{"list invalid only", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{"Alpha$"}, directory.Substring{}, directory.FilterUndefinedResult},
		{"list absent", "caseIgnoreListSubstringsMatch", false, "sample", "sample", nil, directory.Substring{Initial: []byte("alpha")}, directory.FilterUndefinedResult},
		{"ordinary absent", "caseIgnoreSubstringsMatch", false, "sample", "sample", nil, directory.Substring{Initial: []byte("alpha")}, directory.FilterFalseResult},
		{"ordered list skips both errors", "caseIgnoreListSubstringsMatch", true, "sample", "sample", []string{"{bad}Alpha", "{1}Alpha$", "{2}Alpha$Beta"}, directory.Substring{Initial: []byte("alpha")}, directory.FilterTrueResult},
		{"list line boundary", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{"Alpha$Beta"}, directory.Substring{Any: byteValues("hab")}, directory.FilterFalseResult},
		{"list separate parts", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{"Alpha$Beta"}, directory.Substring{Initial: []byte("alpha"), Final: []byte("beta")}, directory.FilterTrueResult},
		{"list escaped dollar", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{`Alpha\24Beta$Gamma`}, directory.Substring{Any: byteValues("a$b")}, directory.FilterTrueResult},
		{"list escaped backslash", "caseIgnoreListSubstringsMatch", false, "sample", "sample", []string{`Alpha\5cBeta$Gamma`}, directory.Substring{Any: byteValues(`a\b`)}, directory.FilterTrueResult},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := preparedSubstringRegistry(t, test.rule, test.ordered)
			filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: test.requested, Substring: test.assertion}
			matcher, err := registry.PrepareSubstringMatcher(filter.Attribute, filter.Substring)
			if err != nil {
				t.Fatal(err)
			}
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: test.candidate, Values: byteValues(test.values...)}}}
			if got, err := filter.EvaluateWith(entry, registry); err != nil || got != test.want {
				t.Fatalf("EvaluateWith = %v, %v; want %v, nil", got, err, test.want)
			}
			checkPreparedSubstring(t, registry, matcher, filter, entry)
			// Only the root boolean collapses undefined; NOT must preserve it.
			negated := directory.Filter{Kind: directory.FilterNot, Children: []directory.Filter{filter}}
			wantNot := directory.FilterUndefinedResult
			switch test.want {
			case directory.FilterTrueResult:
				wantNot = directory.FilterFalseResult
			case directory.FilterFalseResult:
				wantNot = directory.FilterTrueResult
			}
			if got, err := negated.EvaluateWith(entry, registry); err != nil || got != wantNot {
				t.Fatalf("NOT = %v, %v; want %v, nil", got, err, wantNot)
			}
		})
	}
}

func TestPreparedSubstringMatcherReference(t *testing.T) {
	t.Parallel()
	assertions := []directory.Substring{
		{}, {Initial: []byte{}}, {Final: []byte{}}, {Any: [][]byte{nil, {}}},
		{Initial: []byte("Alpha")}, {Initial: []byte("alpha")},
		{Any: byteValues("beta")}, {Final: []byte("Gamma")},
		{Initial: []byte(" alpha "), Any: byteValues(" beta "), Final: []byte(" gamma ")},
		{Any: byteValues("alpha", "alpha")}, {Initial: []byte("alpha"), Final: []byte("alpha")},
		{Any: byteValues("gamma", "beta")}, {Any: byteValues("ha", "be")}, {Any: byteValues("hab")},
		{Initial: []byte(" \t "), Any: [][]byte{nil, {}, []byte(" ")}, Final: []byte{}},
		{Any: byteValues("1 2", "3")}, {Initial: []byte("+1-2"), Final: []byte("45")},
		{Any: byteValues("{1}")}, {Any: byteValues("a$b")}, {Any: byteValues(`a\b`)},
		{Initial: []byte("\x00\xff")}, {Any: byteValues("\xff")}, {Final: []byte("\ufffd")},
		{Any: byteValues("\u212a", "\u00e9")},
	}
	values := append(byteValues(
		"", " ", "\t\n", "Alpha", "Alpha Beta Gamma", "ALPHA  BETA\tGAMMA", "alphaalpha",
		"Alpha$Beta$Gamma", "Alpha$", "$Alpha", "Alpha$$Beta", `Alpha\24Beta$Gamma`,
		`Alpha\5CBeta$Gamma`, `Alpha\20Beta`, `Alpha\`, "Alpha$ $Gamma", "1 2 3 45", "+1 23-45",
		"{1}Alpha Beta Gamma", "{1}Alpha$Beta$Gamma", "{0002}Alpha", "{bad}Alpha", "{}Alpha", "{-1}Alpha",
		"{1", "{999999999999999999999999}Alpha", "{0}", "\x00\xffAlpha", "\xff", "\u212a\u00c9", "\u00a0Alpha\u2003Beta",
	), nil)
	for _, rule := range preparedSubstringRules {
		for _, spelling := range []string{rule.name, strings.ToUpper(rule.name), rule.oid} {
			for _, ordered := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/ordered=%v", spelling, ordered), func(t *testing.T) {
					registry := preparedSubstringRegistry(t, spelling, ordered)
					for _, assertion := range assertions {
						filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: "sample", Substring: assertion}
						matcher, err := registry.PrepareSubstringMatcher(filter.Attribute, assertion)
						if err != nil {
							t.Fatal(err)
						}
						checkPreparedSubstring(t, registry, matcher, filter, directory.Entry{})
						for _, value := range values {
							entry := directory.Entry{Attributes: []directory.Attribute{{Description: "sampleAlias;lang-en", Values: [][]byte{value}}}}
							checkPreparedSubstring(t, registry, matcher, filter, entry)
							entry.Attributes[0].Values = append(entry.Attributes[0].Values, []byte("Alpha Beta Gamma"))
							checkPreparedSubstring(t, registry, matcher, filter, entry)
						}
					}
				})
			}
		}
	}
}

func TestPreparedSubstringMatcherDescriptions(t *testing.T) {
	t.Parallel()
	for _, ordered := range []bool{false, true} {
		registry := preparedSubstringRegistry(t, "caseIgnoreListSubstringsMatch", ordered)
		for _, requested := range []string{"sample", " SAMPLE ", "sampleAlias", "1.2.3.1", "child", "childAlias", "1.2.3.2", "grandchild", "orderedChild"} {
			t.Run(fmt.Sprintf("%s/ordered=%v", requested, ordered), func(t *testing.T) {
				filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: requested, Substring: directory.Substring{Initial: []byte("alpha")}}
				matcher, err := registry.PrepareSubstringMatcher(requested, filter.Substring)
				if err != nil {
					t.Fatal(err)
				}
				for _, candidate := range []string{
					"sample", "SAMPLEALIAS", "1.2.3.1", " sample ", "sample;lang-en", "sample;LANG-EN;binary",
					"sample;lang-", "sample;unknown", "sample;", "sample;;", " sample ; lang-en ; ", "sample;\xff",
					"child", "childAlias;lang-en", "1.2.3.2", "grandchild;lang-en", "orderedChild", "siblingsChild",
					"unrelated", "missing", "", "sample\xff",
				} {
					for _, values := range [][][]byte{nil, {}, {nil}, byteValues("Alpha$Beta"), byteValues("{1}Alpha$Beta"), byteValues("Alpha$", "Alpha$Beta")} {
						entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: values}}}
						checkPreparedSubstring(t, registry, matcher, filter, entry)
					}
				}
				entry := directory.Entry{Attributes: []directory.Attribute{
					{Description: "unrelated", Values: byteValues("Alpha$Beta")},
					{Description: "sample", Values: byteValues("Alpha$")},
					{Description: "childAlias;lang-en", Values: byteValues("Other")},
					{Description: "1.2.3.2;lang-en", Values: byteValues("Alpha$Beta")},
					{Description: "sample", Values: byteValues("{1}Alpha$Beta")},
				}}
				checkPreparedSubstring(t, registry, matcher, filter, entry)
			})
		}
	}
}

func TestPreparedSubstringMatcherFallback(t *testing.T) {
	t.Parallel()
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.10", Names: []string{"noRule"}, Syntax: SyntaxDirectoryString},
		{OID: "1.2.3.11", Names: []string{"unsupported"}, Syntax: SyntaxDirectoryString, Substring: "unknownRule"},
		{OID: "1.2.3.12", Names: []string{"orphan"}, Superior: "missing"},
		{OID: "1.2.3.13", Names: []string{"cycle"}, Superior: "cycle"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	assertion := directory.Substring{Initial: []byte("alpha")}
	for _, requested := range []string{"", "missing", "1.2.3.999", "sample\xff", "noRule", "unsupported", "orphan", "cycle", "sample;lang-en", "sample;lang-", "sample;", "sample;unknown"} {
		t.Run(requested, func(t *testing.T) {
			filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: requested, Substring: assertion}
			entry := directory.Entry{Attributes: []directory.Attribute{{Description: requested, Values: byteValues("Alpha")}}}
			want, wantErr := filter.MatchWith(entry, registry)
			_, beforeErr := registry.MatchSubstring(requested, []byte("Alpha"), assertion)
			if matcher, err := registry.PrepareSubstringMatcher(requested, assertion); err == nil || matcher != nil {
				t.Fatalf("PrepareSubstringMatcher(%q) = %v, %v; want nil, error", requested, matcher, err)
			}
			if got, err := filter.MatchWith(entry, registry); got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("fallback changed: got=(%v, %v), want=(%v, %v)", got, err, want, wantErr)
			}
			if _, err := registry.MatchSubstring(requested, []byte("Alpha"), assertion); fmt.Sprint(err) != fmt.Sprint(beforeErr) {
				t.Fatalf("general error changed: got=%v, want=%v", err, beforeErr)
			}
			if strings.Contains(requested, ";") && (!want || wantErr != nil) {
				t.Fatalf("option fallback must still match: %v, %v", want, wantErr)
			}
			if !strings.Contains(requested, ";") && beforeErr == nil {
				t.Fatal("general matcher lost its error")
			}
		})
	}
	var matcher *PreparedSubstringMatcher
	if matched, err := matcher.Match(directory.Entry{}); matched || err == nil {
		t.Fatalf("nil Match = %v, %v; want false, error", matched, err)
	}
}

func TestPreparedSubstringMatcherOwnership(t *testing.T) {
	t.Parallel()
	for _, rule := range preparedSubstringRules {
		for _, ordered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ordered=%v", rule.name, ordered), func(t *testing.T) {
				registry := preparedSubstringRegistry(t, rule.name, ordered)
				assertion := directory.Substring{Initial: []byte("Alpha"), Any: byteValues("Be", "ta"), Final: []byte("Gamma")}
				filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: "sample", Substring: directory.Substring{Initial: []byte("Alpha"), Any: byteValues("Be", "ta"), Final: []byte("Gamma")}}
				matcher, err := registry.PrepareSubstringMatcher(filter.Attribute, assertion)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(assertion, filter.Substring) {
					t.Fatal("PrepareSubstringMatcher changed the assertion")
				}
				assertion.Initial[0] = '!'
				assertion.Any[0][0] = '!'
				assertion.Any[1] = []byte("!")
				assertion.Final[0] = '!'
				value := "Alpha  Be\tta Gamma"
				if ordered {
					value = "{1}" + value
				}
				entry := directory.Entry{Attributes: []directory.Attribute{{Description: "sample", Values: byteValues("{bad}Alpha$", value), RawNormalized: true}}}
				before := entry.Clone()
				for range 2 {
					checkPreparedSubstring(t, registry, matcher, filter, entry)
				}
				if !reflect.DeepEqual(entry, before) {
					t.Fatal("Match changed entry values")
				}
				if got, err := matcher.Match(entry); err != nil || !got {
					t.Fatalf("owned assertion match = %v, %v; want true, nil", got, err)
				}
				copy(entry.Attributes[0].Values[1], "unrelated")
				checkPreparedSubstring(t, registry, matcher, filter, entry)
			})
		}
	}
}

func TestPreparedSubstringMatcherPreservesGeneralErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		rule, value string
		ordered     bool
	}{
		{"caseIgnoreSubstringsMatch", "{bad}Alpha", true},
		{"caseIgnoreListSubstringsMatch", "Alpha$", false},
		{"caseIgnoreListSubstringsMatch", "{1}Alpha$", true},
	} {
		registry := preparedSubstringRegistry(t, test.rule, test.ordered)
		assertion := directory.Substring{Any: byteValues("alpha")}
		_, wantErr := registry.MatchSubstring("sample", []byte(test.value), assertion)
		if wantErr == nil {
			t.Fatal("general MatchSubstring must report invalid values")
		}
		matcher, err := registry.PrepareSubstringMatcher("sample", assertion)
		if err != nil {
			t.Fatal(err)
		}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: "sample", Values: byteValues(test.value)}}}
		filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: "sample", Substring: assertion}
		checkPreparedSubstring(t, registry, matcher, filter, entry)
		if _, err := registry.MatchSubstring("sample", []byte(test.value), assertion); fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("general MatchSubstring error changed: got=%v, want=%v", err, wantErr)
		}
	}
}

func FuzzPreparedSubstringMatcher(f *testing.F) {
	var registries []*Registry
	for _, rule := range preparedSubstringRules {
		registries = append(registries, preparedSubstringRegistry(f, rule.name, false), preparedSubstringRegistry(f, rule.oid, true))
	}
	for index := range registries {
		f.Add(uint8(index), "sample", "sampleAlias;lang-en", "{1}Alpha$Beta", "Alpha", "", "Beta", uint8(7))
		f.Add(uint8(index), "sample", "childAlias", "Alpha$", "alpha", "", "", uint8(1))
		f.Add(uint8(index), "sample", "orderedChild", "{bad}Alpha", "", "alpha", "", uint8(2))
		f.Add(uint8(index), " sample ", " SAMPLE ;lang-en", "\xff", "", "", "", uint8(7))
	}
	f.Fuzz(func(t *testing.T, selection uint8, requested, candidate, value, initial, anyPart, final string, shape uint8) {
		registry := registries[int(selection)%len(registries)]
		assertion := directory.Substring{}
		if shape&1 != 0 {
			assertion.Initial = []byte(initial)
		}
		if shape&2 != 0 {
			assertion.Any = bytes.Split([]byte(anyPart), []byte{0})
		}
		if shape&4 != 0 {
			assertion.Final = []byte(final)
		}
		matcher, err := registry.PrepareSubstringMatcher(requested, assertion)
		if err != nil {
			return
		}
		filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: requested, Substring: assertion}
		entry := directory.Entry{Attributes: []directory.Attribute{{Description: candidate, Values: bytes.Split([]byte(value), []byte{0})}}}
		checkPreparedSubstring(t, registry, matcher, filter, entry)
		checkPreparedSubstring(t, registry, matcher, filter, directory.Entry{})
	})
}
