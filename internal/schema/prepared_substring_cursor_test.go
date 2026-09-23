package schema

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func preparedCursorPlan(t testing.TB, registry *Registry, classes *PreparedObjectClassMatcher, requested string) *PreparedSubstringQueryPlan {
	t.Helper()
	matcher, err := registry.PrepareSubstringMatcher(requested, directory.Substring{Initial: []byte("alpha")})
	if err != nil {
		t.Fatal(err)
	}
	return matcher.WithObjectClasses(classes)
}

func checkPreparedCursor(t testing.TB, cursor *PreparedSubstringQueryCursor, plan *PreparedSubstringQueryPlan, entry directory.Entry) {
	t.Helper()
	before := entry.Clone()
	wantFlags, wantSelected := plan.Classify(entry)
	flags, selected := cursor.Classify(entry)
	if flags != wantFlags || selected != wantSelected {
		t.Fatalf("Classify = (%x, %x), want (%x, %x)", flags, selected, wantFlags, wantSelected)
	}
	got, gotErr := cursor.Match(entry, selected)
	want, wantErr := plan.Match(entry, wantSelected)
	if got != want || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
		t.Fatalf("Match = (%v, %v), want (%v, %v)", got, gotErr, want, wantErr)
	}
	if !entry.Equal(before) {
		t.Fatal("cursor changed borrowed entry attributes or values")
	}
}

func TestPreparedSubstringQueryCursorReference(t *testing.T) {
	for _, rule := range preparedSubstringRules {
		for _, ordered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ordered=%v", rule.name, ordered), func(t *testing.T) {
				registry := preparedSubstringRegistry(t, rule.name, ordered)
				classes := preparedQueryClasses(t, registry)
				for _, requested := range []string{"sample", "childAlias", "grandchild", "objectClass"} {
					plan := preparedCursorPlan(t, registry, classes, requested)
					cursor := plan.NewCursor()
					for _, description := range []string{
						"sample", " SAMPLEALIAS ;LANG-EN;binary", "1.2.3.1", "child;unknown", "grandchild",
						"orderedChild", "unrelated", "classAlias;lang-en", "1.2.3.7", "objectClass", "\u212a",
						"sample;", "sample;;", "sample;\xff", "missing", "", "\xff",
					} {
						for _, values := range [][][]byte{nil, {nil}, byteValues("Alpha"), byteValues("{bad}Alpha", "{2}Alpha"), byteValues("Other", "ALPHA", "Alpha$")} {
							entry := directory.Entry{Attributes: []directory.Attribute{
								{Description: description, Values: values},
								{Description: " CLASSALIAS ;binary", Values: byteValues(" \tSPECIALCHILD ")},
								{Description: "objectClass", Values: byteValues("subentry", "alpha")},
								{Description: "childAlias;lang-en", Values: byteValues("Alpha")},
							}}
							for range 2 {
								checkPreparedCursor(t, cursor, plan, entry)
							}
							slices.Reverse(entry.Attributes)
							checkPreparedCursor(t, cursor, plan, entry)
						}
					}
				}
			})
		}
	}
}

func TestPreparedSubstringQueryCursorFreshValues(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	otherClasses, err := registry.Clone().PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		t.Fatal(err)
	}
	for _, classMatcher := range []*PreparedObjectClassMatcher{classes, otherClasses} {
		for _, count := range []int{2, 64, 65} {
			plan := preparedCursorPlan(t, registry, classMatcher, "sample")
			cursor := plan.NewCursor()
			calls := 0
			normalize := plan.substring.normalize
			plan.substring.normalize = func(value []byte) []byte {
				calls++
				return normalize(value)
			}
			entry := directory.Entry{Attributes: make([]directory.Attribute, count)}
			entry.Attributes[0] = directory.Attribute{Description: "sample", Values: byteValues("alpha")}
			entry.Attributes[count-1] = directory.Attribute{Description: "objectClass", Values: byteValues("alias")}
			for _, hit := range []bool{true, false, true} {
				if hit {
					copy(entry.Attributes[0].Values[0], "alpha")
					copy(entry.Attributes[count-1].Values[0], "alias")
				} else {
					copy(entry.Attributes[0].Values[0], "omega")
					copy(entry.Attributes[count-1].Values[0], "other")
				}
				calls = 0
				flags, selected := cursor.Classify(entry)
				wantFlags, wantSelected := plan.Classify(entry)
				if calls != 0 || flags != wantFlags || selected != wantSelected || (flags == 2) != hit {
					t.Fatalf("fused=%v/count=%d: Classify = (%x, %x), want (%x, %x); substring calls=%d", plan.fused, count, flags, selected, wantFlags, wantSelected, calls)
				}
				if got, err := cursor.Match(entry, selected); got != hit || err != nil || calls != 1 {
					t.Fatalf("Match = (%v, %v), want (%v, nil); substring calls=%d", got, err, hit, calls)
				}
			}
			for _, values := range [][][]byte{nil, {}, {nil}, byteValues("omega", "alpha"), byteValues(strings.Repeat("alpha ", 1024)), byteValues("omega")} {
				entry.Attributes[0].Values = values
				entry.Attributes[count-1].Values = values
				checkPreparedCursor(t, cursor, plan, entry)
			}
		}
	}
}

func TestPreparedSubstringQueryCursorPositionBoundary(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	plan := preparedCursorPlan(t, registry, classes, "sample")
	cursor := plan.NewCursor()
	for _, count := range []int{64, 65, 1, 0, 63, 129, 2, 64, 0, 65, 64} {
		entry := directory.Entry{Attributes: make([]directory.Attribute, count)}
		if count > 1 {
			entry.Attributes[0] = directory.Attribute{Description: "objectClass", Values: byteValues("specialChild")}
		}
		if count != 0 {
			entry.Attributes[count-1] = directory.Attribute{Description: "childAlias;lang-en", Values: byteValues("alpha")}
		}
		checkPreparedCursor(t, cursor, plan, entry)
		_, selected := cursor.Classify(entry)
		var wantSelected uint64
		if count > 0 && count <= 64 {
			wantSelected = uint64(1) << (count - 1)
		}
		if selected != wantSelected {
			t.Fatalf("%d attributes: selection = %x, want %x", count, selected, wantSelected)
		}
		if matched, err := cursor.Match(entry, selected); matched != (count != 0) || err != nil {
			t.Fatalf("%d attributes: Match = (%v, %v)", count, matched, err)
		}
	}
}

func TestPreparedSubstringQueryCursorBoundedDescriptions(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	longName := strings.Repeat("long", 33)
	if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.99", Names: []string{longName}, Superior: "sample"}); err != nil {
		t.Fatal(err)
	}
	classes, err := registry.PrepareObjectClassMatcher("subentry", "alias", "referral")
	if err != nil {
		t.Fatal(err)
	}
	plan := preparedCursorPlan(t, registry, classes, "sample")
	entry := directory.Entry{Attributes: make([]directory.Attribute, 64)}
	for _, description := range []string{
		"sample", "SAMPLE", "sample;lang-en", "sample;lang-fr", "unrelated", "",
		"sample;" + strings.Repeat("x", 121),
		"sample;" + strings.Repeat("x", 122),
		longName, "objectClass;" + strings.Repeat("x", 1024),
		strings.Repeat("unknown", 1024), "classAlias", "sample",
	} {
		cursor := plan.NewCursor()
		for index := range entry.Attributes {
			entry.Attributes[index] = directory.Attribute{Description: "sample"}
		}
		cursor.Classify(entry)
		// A short slice must not pin the much larger source string in the cursor.
		backing := description + strings.Repeat("!", 1<<20)
		borrowed := backing[:len(description)]
		for index := range entry.Attributes {
			entry.Attributes[index] = directory.Attribute{Description: borrowed, Values: byteValues("alpha", "alias")}
		}
		for range 2 {
			checkPreparedCursor(t, cursor, plan, entry)
		}
		retained := 0
		for index, slot := range cursor.slots {
			retained += len(slot.description)
			if len(description) > 128 {
				if slot.valid || slot.description != "" || slot.roles != 0 {
					t.Fatalf("slot %d retained a long description or its old role", index)
				}
				continue
			}
			if !slot.valid || slot.description != description || slot.roles != plan.substring.attributes.roles(description) {
				t.Fatalf("slot %d did not cache the last exact description and role", index)
			}
			if description != "" && unsafe.StringData(slot.description) == unsafe.StringData(borrowed) {
				t.Fatalf("slot %d retained the borrowed string backing", index)
			}
		}
		if retained > 64*128 {
			t.Fatalf("cursor retained %d description bytes", retained)
		}
	}
}

func TestPreparedSubstringQueryCursorCopyBudget(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	plan := preparedCursorPlan(t, registry, classes, "sample")
	first := directory.Entry{Attributes: []directory.Attribute{
		{Description: "sample", Values: byteValues("alpha")},
		{Description: "objectClass", Values: byteValues("alias")},
	}}
	for index := range 9 {
		first.Attributes = append(first.Attributes, directory.Attribute{
			Description: fmt.Sprintf("unrelated;lang-x%d", index), Values: byteValues("omega"),
		})
	}
	second := first.Clone()
	second.Attributes[0].Values = byteValues("omega")
	second.Attributes[1].Values = byteValues("specialChild")
	slices.Reverse(second.Attributes)
	layouts := [2]directory.Entry{first, second}
	longEntry := directory.Entry{Attributes: []directory.Attribute{
		{Description: "sample;" + strings.Repeat("x", 128), Values: byteValues("alpha")},
	}}
	fallback := first.Clone()
	for len(fallback.Attributes) < 65 {
		fallback.Attributes = append(fallback.Attributes, longEntry.Attributes[0])
	}
	cursor := plan.NewCursor()
	check := func(entry directory.Entry) {
		flags, selected := cursor.Classify(entry)
		wantFlags, wantSelected := plan.Classify(entry)
		if flags != wantFlags || selected != wantSelected {
			t.Fatalf("Classify = (%x, %x), want (%x, %x)", flags, selected, wantFlags, wantSelected)
		}
		got, gotErr := cursor.Match(entry, selected)
		want, wantErr := plan.Match(entry, wantSelected)
		if got != want || gotErr != nil || wantErr != nil {
			t.Fatalf("Match = (%v, %v), want (%v, %v)", got, gotErr, want, wantErr)
		}
	}
	allocations := testing.AllocsPerRun(1, func() {
		*cursor = PreparedSubstringQueryCursor{plan: plan}
		for iteration := range 4 * maxPreparedSubstringCursorCopies {
			check(layouts[iteration%2])
			if iteration%3 == 0 {
				// Neither long descriptions nor fallback rows may refund copies.
				check(longEntry)
				check(fallback)
			}
		}
	})
	if allocations > 256 || cursor.descriptionCopies != maxPreparedSubstringCursorCopies {
		t.Fatalf("scan allocations=%v copies=%d, want at most 256 allocations and an exhausted budget", allocations, cursor.descriptionCopies)
	}
	for _, description := range []string{"classAlias", "child;lang-en", "unrelated", "", "SAMPLE", longEntry.Attributes[0].Description} {
		for _, values := range [][][]byte{nil, byteValues("alpha", "alias"), byteValues("omega", "specialChild")} {
			check(directory.Entry{Attributes: []directory.Attribute{{Description: description, Values: values}}})
		}
	}
	// Change values in the original layouts as well as descriptions after exhaustion.
	copy(first.Attributes[0].Values[0], "omega")
	copy(first.Attributes[1].Values[0], "other")
	copy(second.Attributes[10].Values[0], "alpha")
	if allocations := testing.AllocsPerRun(1, func() {
		for iteration := range 2 * maxPreparedSubstringCursorCopies {
			check(layouts[iteration%2])
			check(longEntry)
			check(fallback)
		}
	}); allocations != 0 {
		t.Fatalf("exhausted cursor allocated %v times", allocations)
	}
	if cursor.descriptionCopies != maxPreparedSubstringCursorCopies {
		t.Fatalf("exhausted budget changed: %d copies", cursor.descriptionCopies)
	}
	retained := 0
	for _, slot := range cursor.slots {
		if len(slot.description) > 128 {
			t.Fatalf("retained a %d-byte description", len(slot.description))
		}
		retained += len(slot.description)
	}
	if retained > 64*128 {
		t.Fatalf("cursor retained %d description bytes", retained)
	}
}

func TestPreparedSubstringQueryCursorSchemaSnapshots(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	oldPlan := preparedCursorPlan(t, registry, classes, "sample")
	oldCursor := oldPlan.NewCursor()
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "classAlias", Values: byteValues("alias", "alpha")}}}
	checkPreparedCursor(t, oldCursor, oldPlan, entry)
	for _, changed := range []*Registry{registry.Clone(), registry} {
		if err := changed.UpsertAttributeType(AttributeType{OID: "1.2.3.7", Names: []string{"classChild", "classAlias", "k"}, Superior: "sample"}); err != nil {
			t.Fatal(err)
		}
		newClasses, err := changed.PrepareObjectClassMatcher("subentry", "alias", "referral")
		if err != nil {
			t.Fatal(err)
		}
		newPlan := preparedCursorPlan(t, changed, newClasses, "sample")
		for _, plan := range []*PreparedSubstringQueryPlan{
			oldPlan, newPlan,
			newPlan.substring.WithObjectClasses(classes),
			oldPlan.substring.WithObjectClasses(newClasses),
		} {
			cursor := plan.NewCursor()
			for range 2 {
				checkPreparedCursor(t, cursor, plan, entry)
				checkPreparedCursor(t, oldCursor, oldPlan, entry)
			}
		}
		flags, selected := oldCursor.Classify(entry)
		if matched, err := oldCursor.Match(entry, selected); flags != 2 || selected != 0 || matched || err != nil {
			t.Fatalf("old cursor changed with schema: flags=%x selected=%x match=%v/%v", flags, selected, matched, err)
		}
		cursor := newPlan.NewCursor()
		flags, selected = cursor.Classify(entry)
		if matched, err := cursor.Match(entry, selected); flags != 0 || selected != 1 || !matched || err != nil {
			t.Fatalf("new cursor missed schema change: flags=%x selected=%x match=%v/%v", flags, selected, matched, err)
		}
	}
}

func TestPreparedSubstringQueryCursorNilMatchers(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	matcher := preparedCursorPlan(t, registry, classes, "sample").substring
	entry := directory.Entry{Attributes: []directory.Attribute{
		{Description: "sample", Values: byteValues("alpha")},
		{Description: "objectClass", Values: byteValues("alias")},
	}}
	for _, substring := range []*PreparedSubstringMatcher{nil, matcher} {
		for _, classMatcher := range []*PreparedObjectClassMatcher{nil, classes} {
			plan := substring.WithObjectClasses(classMatcher)
			checkPreparedCursor(t, plan.NewCursor(), plan, entry)
		}
	}
	plan := new(PreparedSubstringQueryPlan)
	checkPreparedCursor(t, plan.NewCursor(), plan, entry)
}

func TestPreparedSubstringQueryCursorNilPlan(t *testing.T) {
	var plan *PreparedSubstringQueryPlan
	cursor := plan.NewCursor()
	// Nil plans panic in the existing APIs; the cursor must not invent a result.
	for name, call := range map[string]func(){
		"plan Classify":   func() { plan.Classify(directory.Entry{}) },
		"cursor Classify": func() { cursor.Classify(directory.Entry{}) },
		"plan Match":      func() { _, _ = plan.Match(directory.Entry{}, 0) },
		"cursor Match":    func() { _, _ = cursor.Match(directory.Entry{}, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("nil plan did not preserve the existing panic")
				}
			}()
			call()
		})
	}
}

func TestPreparedSubstringQueryCursorIndependentScans(t *testing.T) {
	registry := preparedSubstringRegistry(t, "caseIgnoreSubstringsMatch", false)
	classes := preparedQueryClasses(t, registry)
	plan := preparedCursorPlan(t, registry, classes, "sample")
	before := *plan
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			cursor := plan.NewCursor()
			for iteration := range 30 {
				entry := directory.Entry{Attributes: []directory.Attribute{
					{Description: "sampleAlias;lang-en", Values: byteValues("alpha")},
					{Description: "classAlias", Values: byteValues("alias")},
				}}
				if (worker+iteration)%2 != 0 {
					slices.Reverse(entry.Attributes)
				}
				checkPreparedCursor(t, cursor, plan, entry)
				_, selected := cursor.Classify(entry)
				// A later classification must not replace the caller's selection.
				cursor.Classify(directory.Entry{})
				if matched, err := cursor.Match(entry, selected); !matched || err != nil {
					t.Errorf("interleaved selection match = %v/%v", matched, err)
					return
				}
				for index := range entry.Attributes {
					copy(entry.Attributes[index].Values[0], "other")
				}
				checkPreparedCursor(t, cursor, plan, entry)
			}
		})
	}
	workers.Wait()
	if *plan != before {
		t.Fatal("cursor changed the shared immutable plan")
	}
}
