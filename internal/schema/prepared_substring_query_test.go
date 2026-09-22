package schema

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func preparedQueryClasses(t testing.TB, registry *Registry) *PreparedObjectClassMatcher {
	t.Helper()
	for _, attribute := range []AttributeType{
		{OID: "2.5.4.0", Names: []string{"objectClass"}, Syntax: SyntaxDirectoryString, Substring: "caseIgnoreSubstringsMatch"},
		{OID: "1.2.3.7", Names: []string{"classChild", "classAlias", "k"}, Superior: "objectClass"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for index, name := range []string{"ordinary", "subentry", "alias", "referral", "specialChild"} {
		class := ObjectClass{OID: fmt.Sprintf("1.2.3.%d", index+20), Names: []string{name}}
		if name == "specialChild" {
			class.Superiors = []string{"alias", "referral"}
		}
		if err := registry.RegisterObjectClass(class); err != nil {
			t.Fatal(err)
		}
	}
	classes, err := registry.PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		t.Fatal(err)
	}
	return classes
}

func TestPreparedSubstringQueryPlanReference(t *testing.T) {
	for _, rule := range preparedSubstringRules {
		for _, ordered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ordered=%v", rule.name, ordered), func(t *testing.T) {
				registry := preparedSubstringRegistry(t, rule.name, ordered)
				classes := preparedQueryClasses(t, registry)
				for _, requested := range []string{"sample", "sampleAlias", "child", "grandchild", "orderedChild", "objectClass"} {
					filter := directory.Filter{Kind: directory.FilterSubstrings, Attribute: requested, Substring: directory.Substring{Initial: []byte("alpha")}}
					matcher, err := registry.PrepareSubstringMatcher(requested, filter.Substring)
					if err != nil {
						t.Fatal(err)
					}
					plan := matcher.WithObjectClasses(classes)
					if !plan.fused {
						t.Fatal("same schema did not fuse")
					}
					for _, description := range []string{"sample", " SAMPLEALIAS ;LANG-EN;binary", "1.2.3.1", "child;unknown", "grandchild", "orderedChild", "classAlias;lang-en", "\u212a", "missing", "\xff"} {
						for _, values := range [][][]byte{nil, {nil}, byteValues("Alpha"), byteValues("{bad}Alpha", "{2}Alpha"), byteValues("Alpha$", "Alpha$Beta"), byteValues("Other", "ALPHA", "Alpha$")} {
							entry := directory.Entry{Attributes: []directory.Attribute{
								{Description: "unrelated", Values: byteValues("Alpha")},
								{Description: description, Values: values},
								{Description: " CLASSALIAS ;binary", Values: byteValues(" \tSPECIALCHILD ")},
								{Description: "objectClass", Values: byteValues("subentry")},
							}}
							before := entry.Clone()
							if values == nil {
								before.Attributes[1].Values = nil
							}
							flags, selected := plan.Classify(entry)
							if want := classes.Match(entry); flags != want || flags != 7 {
								t.Fatalf("class flags = %x, want %x (all three classes)", flags, want)
							}
							got, gotErr := plan.Match(entry, selected)
							want, wantErr := filter.MatchWith(entry, registry)
							if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
								t.Fatalf("%s/%s/%q: got %v/%v, want %v/%v", requested, description, values, got, gotErr, want, wantErr)
							}
							if !reflect.DeepEqual(entry, before) {
								t.Fatal("query plan changed borrowed attributes or values")
							}
						}
					}
				}
			})
		}
	}
}

func TestPreparedSubstringQueryPlanDefersValues(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	otherClasses, err := registry.Clone().PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		t.Fatal(err)
	}
	for _, classMatcher := range []*PreparedObjectClassMatcher{classes, otherClasses} {
		for _, count := range []int{2, 64, 65} {
			for _, disposition := range []string{"alias", "referral", "subentry", "invisible", "visible"} {
				matcher, err := registry.PrepareSubstringMatcher("sample", directory.Substring{Initial: []byte("alpha")})
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				normalize := matcher.normalize
				matcher.normalize = func(value []byte) []byte {
					calls++
					return normalize(value)
				}
				plan := matcher.WithObjectClasses(classMatcher)
				entry := directory.Entry{Attributes: make([]directory.Attribute, count)}
				entry.Attributes[0] = directory.Attribute{Description: "sample", Values: byteValues(strings.Repeat(" ALPHA ", 1024))}
				class := disposition
				if disposition == "invisible" || disposition == "visible" {
					class = "ordinary"
				}
				entry.Attributes[count-1] = directory.Attribute{Description: "objectClass", Values: byteValues(class)}
				flags, selected := plan.Classify(entry)
				if calls != 0 {
					t.Fatalf("Classify evaluated substring values for %s/%d", disposition, count)
				}
				if flags != classMatcher.Match(entry) {
					t.Fatal("classification changed")
				}
				if flags == 0 && disposition == "visible" {
					if got, err := plan.Match(entry, selected); err != nil || !got || calls != 1 {
						t.Fatalf("deferred match = %v/%v, normalize calls = %d", got, err, calls)
					}
				}
			}
		}
	}
}

func TestPreparedSubstringQueryPlanPositionBoundary(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	matcher, err := registry.PrepareSubstringMatcher("sample", directory.Substring{Initial: []byte("alpha")})
	if err != nil {
		t.Fatal(err)
	}
	plan := matcher.WithObjectClasses(classes)
	for _, count := range []int{0, 1, 63, 64, 65, 129} {
		entry := directory.Entry{Attributes: make([]directory.Attribute, count)}
		if count != 0 {
			entry.Attributes[count-1] = directory.Attribute{Description: "childAlias;lang-en", Values: byteValues("Alpha")}
		}
		flags, selected := plan.Classify(entry)
		got, err := plan.Match(entry, selected)
		if flags != 0 || err != nil || got != (count != 0) {
			t.Fatalf("%d attributes: flags=%x match=%v/%v", count, flags, got, err)
		}
	}
}

func TestPreparedSubstringQueryPlanSchemaFallback(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	oldMatcher, err := registry.PrepareSubstringMatcher("sample", directory.Substring{Initial: []byte("alpha")})
	if err != nil {
		t.Fatal(err)
	}
	oldPlan := oldMatcher.WithObjectClasses(classes)
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "classAlias", Values: byteValues("alias", "alpha")}}}
	for _, changed := range []*Registry{registry.Clone(), registry} {
		if err := changed.UpsertAttributeType(AttributeType{OID: "1.2.3.7", Names: []string{"classChild", "classAlias", "k"}, Superior: "sample"}); err != nil {
			t.Fatal(err)
		}
		newMatcher, err := changed.PrepareSubstringMatcher("sample", directory.Substring{Initial: []byte("alpha")})
		if err != nil {
			t.Fatal(err)
		}
		newClasses, err := changed.PrepareObjectClassMatcher("subentry", "alias", "referral")
		if err != nil {
			t.Fatal(err)
		}
		newPlan := newMatcher.WithObjectClasses(newClasses)
		flags, selected := newPlan.Classify(entry)
		if matched, err := newPlan.Match(entry, selected); !newPlan.fused || flags != 0 || !matched || err != nil {
			t.Fatal("new query plan did not reflect attribute mutation")
		}
		for _, pair := range []struct {
			substring *PreparedSubstringMatcher
			classes   *PreparedObjectClassMatcher
		}{
			{newMatcher, classes}, {oldMatcher, newClasses},
		} {
			plan := pair.substring.WithObjectClasses(pair.classes)
			if plan.fused {
				t.Fatal("different schema snapshots fused")
			}
			flags, selected := plan.Classify(entry)
			got, gotErr := plan.Match(entry, selected)
			want, wantErr := pair.substring.Match(entry)
			if flags != pair.classes.Match(entry) || got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatalf("fallback changed classification or matching: flags=%x match=%v/%v", flags, got, gotErr)
			}
		}
		flags, selected = oldPlan.Classify(entry)
		if matched, err := oldPlan.Match(entry, selected); flags != 2 || matched || err != nil {
			t.Fatal("schema mutation changed a published query plan")
		}
	}
}

func TestPreparedSubstringQueryPlanCacheEviction(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	for i := 0; i < maxPreparedNamePlans; i++ {
		if err := registry.RegisterAttributeType(AttributeType{OID: fmt.Sprintf("1.2.3.%d", i+100), Names: []string{fmt.Sprintf("eviction%d", i)}, Superior: "sample"}); err != nil {
			t.Fatal(err)
		}
	}
	classes := preparedQueryClasses(t, registry)
	for i := 0; i < maxPreparedNamePlans; i++ {
		cachedNames(t, registry, fmt.Sprintf("eviction%d", i))
	}
	matcher, err := registry.PrepareSubstringMatcher("sample", directory.Substring{Initial: []byte("alpha")})
	if err != nil {
		t.Fatal(err)
	}
	plan := matcher.WithObjectClasses(classes)
	entry := directory.Entry{Attributes: []directory.Attribute{
		{Description: "eviction0;lang-en", Values: byteValues("alpha")},
		{Description: "classAlias", Values: byteValues("specialChild")},
	}}
	flags, selected := plan.Classify(entry)
	if matched, err := plan.Match(entry, selected); !plan.fused || flags != 6 || !matched || err != nil {
		t.Fatal("cache eviction invalidated the schema generation or a published plan")
	}
}

func TestPreparedSubstringQueryPlanNilMatchers(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	matcher, err := registry.PrepareSubstringMatcher("sample", directory.Substring{})
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{Attributes: []directory.Attribute{
		{Description: "sample", Values: byteValues("alpha")},
		{Description: "objectClass", Values: byteValues("alias")},
	}}
	for _, substring := range []*PreparedSubstringMatcher{nil, matcher} {
		for _, classMatcher := range []*PreparedObjectClassMatcher{nil, classes} {
			plan := substring.WithObjectClasses(classMatcher)
			flags, selected := plan.Classify(entry)
			got, gotErr := plan.Match(entry, selected)
			want, wantErr := substring.Match(entry)
			if flags != classMatcher.Match(entry) || got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Fatal("nil matcher behavior changed")
			}
		}
	}
}

func TestPreparedSubstringQueryPlanConcurrentOwnership(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	assertion := directory.Substring{Initial: []byte("alpha")}
	matcher, err := registry.PrepareSubstringMatcher("sample", assertion)
	if err != nil {
		t.Fatal(err)
	}
	plan := matcher.WithObjectClasses(classes)
	assertion.Initial[0] = '!'
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 50; i++ {
				entry := directory.Entry{Attributes: []directory.Attribute{
					{Description: "objectClass", Values: byteValues("ordinary")},
					{Description: "sampleAlias;lang-en", Values: byteValues("alpha")},
				}}
				before := entry.Clone()
				flags, selected := plan.Classify(entry)
				plan.Classify(directory.Entry{})
				if got, err := plan.Match(entry, selected); flags != 0 || !got || err != nil || !reflect.DeepEqual(entry, before) {
					t.Errorf("concurrent match or ownership changed: flags=%x match=%v/%v", flags, got, err)
					return
				}
				entry.Attributes[1].Values[0][0] = '!'
				_, selected = plan.Classify(entry)
				if got, err := plan.Match(entry, selected); got || err != nil {
					t.Errorf("query plan retained a previous row result: %v/%v", got, err)
					return
				}
			}
		}()
	}
	workers.Wait()
}
