package server

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

// Keep the pre-cache implementation as an oracle: only the first ParseDN may
// be cached, including when later routing or normalization fails.
func runtimeLegacyDNConnectionOracle(runtime *runtimeState, value string) (directory.DN, error) {
	legacy, err := directory.ParseDN(value)
	if err != nil {
		return directory.DN{}, err
	}
	if runtime == nil || isConfigurationDN(legacy) {
		return legacy, nil
	}
	if database := databaseForDN(runtime, legacy); database != nil {
		return parseRuntimeDN(value, database.dnNormalizer)
	}
	if runtime.schema != nil {
		return runtime.schema.NormalizeDN(value)
	}
	return legacy, nil
}

func runtimeLegacyDNInputs() []string {
	return []string{
		"", " ", "cn=config", "CN=CONFIG", "olcDatabase={1}mdb,cn=config",
		"undefinedName=still-valid,cn=config", "2.5.4.3=config",
		"CN=Alice,DC=Example,DC=Com", "cn=alice,dc=example,dc=com",
		"uid=Alice,dc=unconfigured", "cn=", "cn= Alice",
		"exactAlias=Alice,dc=example,dc=com", dnMultiAVAExactOID + "=alice,dc=example,dc=com",
		"foldAlias=ENGINEERING+exactAlias=Alice,dc=example,dc=com",
		"uid=alice+cn=Alice,dc=example,dc=com", "cn=Alice+uid=alice,dc=example,dc=com",
		`cn=Smith\, Alice,dc=example,dc=com`, `cn=\20Alice\20,dc=example,dc=com`,
		`cn=\c3\a9\+\00,dc=example,dc=com`, "cn=\u7528\u6237,dc=example,dc=com",
		`member=cn\=Alice\,dc\=example,dc=com`,
		"undefinedName=Alice,dc=example,dc=com", "jpegPhoto=x,dc=example,dc=com",
		"member=broken,dc=example,dc=com", "cn=broken,", "cn", `cn=bad\zz`,
		"cn=x+CN=y,dc=example,dc=com", "exactName=x+exactAlias=y,dc=example,dc=com",
		"undefinedName=x,broken", "cn=\xff,dc=example,dc=com",
	}
}

func assertRuntimeLegacyDNResult(t *testing.T, raw string, got directory.DN, gotErr error, want directory.DN, wantErr error) {
	t.Helper()
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
		t.Fatalf("parse %q: got %#v / %v; want %#v / %v", raw, got, gotErr, want, wantErr)
	}
}

func mustRuntimeLegacyDN(t *testing.T, cache *runtimeLegacyDNCache, raw string) directory.DN {
	t.Helper()
	dn, err := cache.parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return dn
}

func TestRuntimeLegacyDNCacheParseReference(t *testing.T) {
	for _, test := range []struct {
		name  string
		cache *runtimeLegacyDNCache
	}{
		{"nil", nil},
		{"zero", new(runtimeLegacyDNCache)},
		{"constructed", newRuntimeLegacyDNCache()},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, raw := range runtimeLegacyDNInputs() {
				want, wantErr := directory.ParseDN(raw)
				for range 3 {
					got, gotErr := test.cache.parse(raw)
					assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
				}
				if test.cache != nil {
					_, cached := test.cache.entries[raw]
					if cached != (wantErr == nil) {
						t.Fatalf("parse %q: cached=%t, syntax error=%v", raw, cached, wantErr)
					}
				}
			}
		})
	}
}

func TestRuntimeLegacyDNCacheConnectionReference(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	suffix := staticRuntimeDN("dc=example,dc=com")
	for _, test := range []struct {
		name    string
		runtime *runtimeState
	}{
		{"nil-runtime", nil},
		{"nil-cache", &runtimeState{schema: registry}},
		{"legacy", &runtimeState{legacyDNs: newRuntimeLegacyDNCache()}},
		{"schema", &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}},
		{"database-legacy", &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache(), databases: []runtimeDatabase{
			{suffixes: []directory.DN{suffix}},
		}}},
		{"database-schema", &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache(), databases: []runtimeDatabase{
			{suffixes: []directory.DN{suffix}, dnNormalizer: &databaseEqualityIndexNormalizer{registry: registry}},
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, raw := range runtimeLegacyDNInputs() {
				want, wantErr := runtimeLegacyDNConnectionOracle(test.runtime, raw)
				for range 3 {
					got, gotErr := parseRuntimeConnectionDN(test.runtime, raw)
					assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
				}
				if test.runtime != nil && test.runtime.legacyDNs != nil {
					legacy, syntaxErr := directory.ParseDN(raw)
					cached, ok := test.runtime.legacyDNs.entries[raw]
					if ok != (syntaxErr == nil) || ok && !reflect.DeepEqual(cached, legacy) {
						t.Fatalf("parse %q: cache must retain syntax only, even after normalization errors", raw)
					}
				}
			}
		})
	}
}

type runtimeLegacyDNCallbackTrace struct {
	calls  []string
	failAt int
	fail   error
}

func (trace *runtimeLegacyDNCallbackTrace) record(call string) error {
	trace.calls = append(trace.calls, call)
	if len(trace.calls) == trace.failAt {
		return trace.fail
	}
	return nil
}

type runtimeLegacyDNRecordingNormalizer struct {
	registry *schema.Registry
	name     string
	trace    *runtimeLegacyDNCallbackTrace
}

func (normalizer runtimeLegacyDNRecordingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	if err := normalizer.trace.record(fmt.Sprintf("%s:value:%s=%q", normalizer.name, attribute, value)); err != nil {
		return "", nil, err
	}
	return normalizer.registry.NormalizeDNAttribute(attribute, value)
}

func (normalizer runtimeLegacyDNRecordingNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	if err := normalizer.trace.record(normalizer.name + ":name:" + attribute); err != nil {
		return "", err
	}
	return normalizer.registry.CanonicalDNAttributeName(attribute)
}

func TestRuntimeLegacyDNCacheCallbackOrderAndChangingErrors(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	trace := new(runtimeLegacyDNCallbackTrace)
	runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache(), databases: []runtimeDatabase{
		{suffixes: []directory.DN{staticRuntimeDN("dc=other,dc=com")},
			dnNormalizer: runtimeLegacyDNRecordingNormalizer{registry, "first", trace}},
		{suffixes: []directory.DN{staticRuntimeDN("dc=example,dc=com")},
			dnNormalizer: runtimeLegacyDNRecordingNormalizer{registry, "second", trace}},
	}}
	for _, raw := range []string{
		"CN=Alice,DC=Example,DC=Com", "foldAlias=ENGINEERING+exactAlias=Alice,dc=example,dc=com",
		"cn=config", "undefinedName=x,cn=config", "", "undefinedName=x,broken", "cn=broken,",
	} {
		t.Run(raw, func(t *testing.T) {
			*trace = runtimeLegacyDNCallbackTrace{}
			_, _ = runtimeLegacyDNConnectionOracle(runtime, raw)
			baseline := slices.Clone(trace.calls)
			if strings.HasPrefix(raw, "CN=") || strings.HasPrefix(raw, "foldAlias=") {
				if len(baseline) == 0 || !strings.HasPrefix(baseline[0], "first:") ||
					!strings.HasPrefix(baseline[len(baseline)-1], "second:") {
					t.Fatalf("fixture did not exercise both databases and final normalization: %v", baseline)
				}
			}
			// Fail each callback in turn, including final normalization, and then
			// recover without replacing the already-warm syntax cache.
			for failAt := 0; failAt <= len(baseline); failAt++ {
				for _, failure := range []error{errors.New("first callback failure"), errors.New("changed callback failure"), nil} {
					*trace = runtimeLegacyDNCallbackTrace{failAt: failAt, fail: failure}
					want, wantErr := runtimeLegacyDNConnectionOracle(runtime, raw)
					wantCalls := slices.Clone(trace.calls)
					for range 2 {
						trace.calls = nil
						got, gotErr := parseRuntimeConnectionDN(runtime, raw)
						assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
						if !slices.Equal(trace.calls, wantCalls) {
							t.Fatalf("failure at callback %d: got %v; want %v", failAt, trace.calls, wantCalls)
						}
						if failure != nil && errors.Is(gotErr, failure) != errors.Is(wantErr, failure) {
							t.Fatalf("failure at callback %d: error identity changed", failAt)
						}
					}
				}
			}
		})
	}
}

func TestRuntimeLegacyDNCacheRuntimeMutations(t *testing.T) {
	fold := newDNMultiAVARegistry(t)
	exact := fold.Clone()
	attribute, _ := exact.AttributeType("uid")
	attribute.Equality = "caseExactMatch"
	if err := exact.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	const raw = "uid=Alice,dc=example,dc=com"
	runtime := &runtimeState{schema: fold, legacyDNs: newRuntimeLegacyDNCache()}
	check := func(label string, normalizer *schema.Registry) directory.DN {
		t.Helper()
		want, wantErr := normalizer.NormalizeDN(raw)
		for range 2 {
			oracle, oracleErr := runtimeLegacyDNConnectionOracle(runtime, raw)
			assertRuntimeLegacyDNResult(t, label, oracle, oracleErr, want, wantErr)
			got, gotErr := parseRuntimeConnectionDN(runtime, raw)
			assertRuntimeLegacyDNResult(t, label, got, gotErr, want, wantErr)
		}
		return want
	}
	before := check("schema fallback", fold)
	runtime.databases = []runtimeDatabase{{
		suffixes:     []directory.DN{staticRuntimeDN("dc=example,dc=com")},
		dnNormalizer: &databaseEqualityIndexNormalizer{registry: exact},
	}}
	after := check("added database", exact)
	if before.Equal(after) {
		t.Fatal("fixture did not change uid equality semantics")
	}
	runtime.databases[0].suffixes[0] = staticRuntimeDN("dc=elsewhere,dc=com")
	check("changed suffix", fold)
	runtime.databases[0].suffixes[0] = staticRuntimeDN("dc=example,dc=com")
	check("restored suffix", exact)
	runtime.databases[0].hidden = true
	check("hidden database", fold)
	runtime.databases[0].hidden = false
	runtime.databases[0].disabled = true
	check("disabled database", fold)
	runtime.databases[0].disabled = false
	runtime.databases = append(runtime.databases, runtimeDatabase{
		suffixes: []directory.DN{staticRuntimeDN("dc=example,dc=com")}, dnNormalizer: fold,
	})
	check("equal-depth first database wins", exact)
	slices.Reverse(runtime.databases)
	check("reordered databases", fold)
	runtime.databases[0].suffixes[0] = staticRuntimeDN("dc=com")
	check("longest suffix wins", exact)
	runtime.databases[1].dnNormalizer = fold
	check("replaced database normalizer", fold)
	runtime.databases = nil
	check("removed databases", fold)
	runtime.schema = exact
	check("replaced runtime schema", exact)
	attribute.Equality = "caseIgnoreMatch"
	if err := exact.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check("mutated runtime schema", fold)
	runtime.databases = []runtimeDatabase{{
		suffixes:     []directory.DN{staticRuntimeDN("dc=example,dc=com")},
		dnNormalizer: &databaseEqualityIndexNormalizer{registry: exact},
	}}
	check("database before schema mutation", fold)
	attribute.Equality = "caseExactMatch"
	if err := exact.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check("mutated database schema", exact)
	for _, root := range []string{raw, "uid=alice,dc=example,dc=com", raw, ""} {
		runtime.databases[0].rootDN = nil
		if root != "" {
			runtime.databases[0].rootDN = new(staticRuntimeDN(root))
		}
		dn := check("changed root", exact)
		got, err := parseRuntimeConnectionDN(runtime, raw)
		if err != nil || isAnyDatabaseRoot(runtime, got) != (root == raw) ||
			isAnyDatabaseRoot(runtime, got) != isAnyDatabaseRoot(runtime, dn) {
			t.Fatalf("root %q: stale root decision, parse error=%v", root, err)
		}
	}
}

func TestRuntimeLegacyDNCacheSchemaErrorsAreLive(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}
	const raw = "futureName=Alice,dc=example,dc=com"
	check := func(wantError bool) {
		t.Helper()
		for range 2 {
			want, wantErr := runtimeLegacyDNConnectionOracle(runtime, raw)
			got, gotErr := parseRuntimeConnectionDN(runtime, raw)
			assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
			if (gotErr != nil) != wantError {
				t.Fatalf("normalization error=%v, want error=%t", gotErr, wantError)
			}
		}
		if _, ok := runtime.legacyDNs.entries[raw]; !ok {
			t.Fatal("successful syntax parse was not cached")
		}
	}
	check(true)
	attribute := schema.AttributeType{OID: "1.2.3.999.42", Names: []string{"futureName"}, Equality: "caseIgnoreMatch"}
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check(false)
	attribute.Names = []string{"renamedFutureName"}
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	check(true)
}

func TestRuntimeLegacyDNCacheExactRawKeys(t *testing.T) {
	cache := newRuntimeLegacyDNCache()
	inputs := []string{"cn=Alice", "CN=Alice", "cn=alice", "cn= Alice", `cn=\41lice`, "2.5.4.3=Alice"}
	for _, raw := range inputs {
		want, err := directory.ParseDN(raw)
		if err != nil {
			t.Fatal(err)
		}
		got := mustRuntimeLegacyDN(t, cache, raw)
		assertRuntimeLegacyDNResult(t, raw, got, nil, want, nil)
		bytes := cache.bytes
		got = mustRuntimeLegacyDN(t, cache, raw)
		assertRuntimeLegacyDNResult(t, raw, got, nil, want, nil)
		if _, ok := cache.entries[raw]; !ok || cache.bytes != bytes {
			t.Fatalf("exact key %q missing or cache hit changed accounting", raw)
		}
	}
	if len(cache.entries) != len(inputs) {
		t.Fatal("case, aliases, whitespace or escaping collapsed exact raw keys")
	}
}

func TestRuntimeLegacyDNCacheBounds(t *testing.T) {
	if maxRuntimeLegacyDNs != 128 || maxRuntimeLegacyDNInput != 1024 ||
		maxRuntimeLegacyDNDepth != 32 || maxRuntimeLegacyDNBytes != 1<<20 {
		t.Fatal("runtime legacy DN cache limits changed")
	}
	for _, test := range []struct {
		name, raw string
		cached    bool
	}{
		{"input-limit", "cn=" + strings.Repeat("a", maxRuntimeLegacyDNInput-3), true},
		{"over-input-limit", "cn=" + strings.Repeat("a", maxRuntimeLegacyDNInput-2), false},
		{"depth-limit", strings.Repeat("cn=x,", maxRuntimeLegacyDNDepth-1) + "cn=x", true},
		{"over-depth-limit", strings.Repeat("cn=x,", maxRuntimeLegacyDNDepth) + "cn=x", false},
		{"escaped-commas", "cn=" + strings.Repeat(`x\,`, maxRuntimeLegacyDNDepth+1) + "x", true},
		{"escaped-equals", "cn=" + strings.Repeat(`x\=`, maxRuntimeLegacyDNDepth+1) + "x", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := newRuntimeLegacyDNCache()
			mustRuntimeLegacyDN(t, cache, "cn=retained")
			beforeBytes := cache.bytes
			want, err := directory.ParseDN(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				got := mustRuntimeLegacyDN(t, cache, test.raw)
				assertRuntimeLegacyDNResult(t, test.raw, got, nil, want, nil)
			}
			_, cached := cache.entries[test.raw]
			if cached != test.cached || !cached && (len(cache.entries) != 1 || cache.bytes != beforeBytes) {
				t.Fatalf("cached=%t, entries=%d, bytes=%d; want cached=%t", cached, len(cache.entries), cache.bytes, test.cached)
			}
		})
	}
}

func TestRuntimeLegacyDNCacheErrorsDoNotConsumeBudget(t *testing.T) {
	cache := newRuntimeLegacyDNCache()
	mustRuntimeLegacyDN(t, cache, "cn=retained")
	bytes := cache.bytes
	for i := range 2 * maxRuntimeLegacyDNs {
		raw := fmt.Sprintf("cn=broken-%d,", i)
		want, wantErr := directory.ParseDN(raw)
		if wantErr == nil {
			t.Fatal("fixture must fail syntax parsing")
		}
		for range 2 {
			got, gotErr := cache.parse(raw)
			assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
		}
	}
	if len(cache.entries) != 1 || cache.bytes != bytes {
		t.Fatal("syntax errors consumed cache budget or evicted valid entries")
	}
	if _, ok := cache.entries["cn=retained"]; !ok {
		t.Fatal("syntax errors evicted a valid entry")
	}
}

func TestRuntimeLegacyDNCacheByteBudget(t *testing.T) {
	cache := newRuntimeLegacyDNCache()
	charges := make(map[string]int)
	evicted := false
	for i := range maxRuntimeLegacyDNs {
		raw := fmt.Sprintf("uid=user%d,", i) + strings.Repeat("cn=x,", maxRuntimeLegacyDNDepth-2) + "dc=com"
		isolated := newRuntimeLegacyDNCache()
		want := mustRuntimeLegacyDN(t, isolated, raw)
		charges[raw] = isolated.bytes
		previous := len(cache.entries)
		got := mustRuntimeLegacyDN(t, cache, raw)
		assertRuntimeLegacyDNResult(t, raw, got, nil, want, nil)
		evicted = evicted || len(cache.entries) < previous
		retained := 0
		for key := range cache.entries {
			retained += charges[key]
		}
		if retained <= 0 || retained != cache.bytes || cache.bytes > maxRuntimeLegacyDNBytes || len(cache.entries) > maxRuntimeLegacyDNs {
			t.Fatalf("invalid budget: accounted=%d, bytes=%d, entries=%d", retained, cache.bytes, len(cache.entries))
		}
		mustRuntimeLegacyDN(t, cache, raw)
		if cache.bytes != retained {
			t.Fatal("cache hit charged the DN twice")
		}
	}
	if !evicted {
		t.Fatal("byte budget did not evict before the entry limit")
	}
}

type runtimeLegacyDNMutatingNormalizer struct{}

func (runtimeLegacyDNMutatingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	clear(value)
	return strings.ToLower(attribute), value, nil
}

func TestRuntimeLegacyDNCacheOwnershipAndEviction(t *testing.T) {
	cache := newRuntimeLegacyDNCache()
	const raw = "CN=Alice+UID=ALICE,DC=Example,DC=Com"
	want, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatal(err)
	}
	dn := mustRuntimeLegacyDN(t, cache, raw)
	parent, ok := dn.Parent()
	if !ok {
		t.Fatal("missing parent")
	}
	wantParent, _ := want.Parent()
	child, err := directory.ComposeDN("ou=child", dn)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := dn.ReplaceAncestor(parent, staticRuntimeDN("dc=elsewhere"))
	if err != nil {
		t.Fatal(err)
	}
	for _, derived := range []directory.DN{dn, parent, child, moved} {
		for _, value := range derived.RDNValues() {
			clear(value.Value)
		}
		normalized, err := derived.NormalizeWith(runtimeLegacyDNMutatingNormalizer{})
		if err != nil || normalized.Key() == derived.Key() {
			t.Fatalf("mutating normalizer did not create a distinct DN: %v", err)
		}
	}
	assertRuntimeLegacyDNResult(t, raw, dn, nil, want, nil)
	assertRuntimeLegacyDNResult(t, "parent", parent, nil, wantParent, nil)
	assertRuntimeLegacyDNResult(t, raw, mustRuntimeLegacyDN(t, cache, raw), nil, want, nil)
	for i := range maxRuntimeLegacyDNs - 1 {
		mustRuntimeLegacyDN(t, cache, fmt.Sprintf("cn=entry-%d", i))
	}
	if len(cache.entries) != maxRuntimeLegacyDNs {
		t.Fatal("cache did not reach its entry limit")
	}
	// A hit at capacity must not evict or recharge entries.
	bytes := cache.bytes
	mustRuntimeLegacyDN(t, cache, raw)
	if len(cache.entries) != maxRuntimeLegacyDNs || cache.bytes != bytes {
		t.Fatal("cache hit at capacity changed entries or accounting")
	}
	mustRuntimeLegacyDN(t, cache, "cn=evict")
	if len(cache.entries) > maxRuntimeLegacyDNs {
		t.Fatal("entry limit exceeded")
	}
	if _, ok := cache.entries[raw]; ok {
		t.Fatal("old entry survived eviction")
	}
	assertRuntimeLegacyDNResult(t, raw, dn, nil, want, nil)
	assertRuntimeLegacyDNResult(t, "parent", parent, nil, wantParent, nil)
	assertRuntimeLegacyDNResult(t, raw, mustRuntimeLegacyDN(t, cache, raw), nil, want, nil)
	if child.String() != "ou=child,"+want.String() || moved.String() != "cn=Alice+uid=ALICE,dc=elsewhere" {
		t.Fatal("eviction or derived DN operations mutated a published DN")
	}
}

func TestRuntimeLegacyDNCacheOwnsBorrowedStrings(t *testing.T) {
	const raw = "CN=Alice+UID=ALICE,DC=Example,DC=Com"
	backing := strings.Repeat("!", 1<<20) + raw + strings.Repeat("!", 1<<20)
	borrowed := backing[1<<20 : 1<<20+len(raw)]
	cache := newRuntimeLegacyDNCache()
	mustRuntimeLegacyDN(t, cache, borrowed)
	start := uintptr(unsafe.Pointer(unsafe.StringData(backing)))
	end := start + uintptr(len(backing))
	// Inspect strings without mutating them, including the DN's private parsed
	// attributes. Heap-size/GC assertions would depend on unrelated allocations.
	var checkOwned func(reflect.Value)
	checkOwned = func(value reflect.Value) {
		switch value.Kind() {
		case reflect.Pointer:
			if !value.IsNil() {
				checkOwned(value.Elem())
			}
		case reflect.Struct:
			for i := range value.NumField() {
				checkOwned(value.Field(i))
			}
		case reflect.Slice, reflect.Array:
			for i := range value.Len() {
				checkOwned(value.Index(i))
			}
		case reflect.String:
			text := value.String()
			address := uintptr(unsafe.Pointer(unsafe.StringData(text)))
			if len(text) != 0 && address >= start && address < end {
				t.Fatalf("cache retained %q in the large borrowed backing string", text)
			}
		}
	}
	for key, dn := range cache.entries {
		checkOwned(reflect.ValueOf(key))
		checkOwned(reflect.ValueOf(dn))
	}
	runtime.KeepAlive(backing)
}

func TestRuntimeLegacyDNCacheConcurrency(t *testing.T) {
	inputs := runtimeLegacyDNInputs()
	for i := range 2 * maxRuntimeLegacyDNs {
		inputs = append(inputs, fmt.Sprintf("uid=user%d,dc=example,dc=com", i))
	}
	inputs = append(inputs, "cn="+strings.Repeat("x", maxRuntimeLegacyDNInput), strings.Repeat("cn=x,", maxRuntimeLegacyDNDepth)+"cn=x")
	for _, test := range []struct {
		name   string
		inputs []string
	}{
		{"same-key-publication", []string{"CN=Alice,DC=Example,DC=Com"}},
		{"hits-misses-errors-bypass-and-eviction", inputs},
	} {
		t.Run(test.name, func(t *testing.T) {
			wants := make([]directory.DN, len(test.inputs))
			errors := make([]error, len(test.inputs))
			charges := make(map[string]int)
			for i, raw := range test.inputs {
				wants[i], errors[i] = directory.ParseDN(raw)
				isolated := newRuntimeLegacyDNCache()
				_, _ = isolated.parse(raw)
				charges[raw] = isolated.bytes
			}
			cache := newRuntimeLegacyDNCache()
			start := make(chan struct{})
			var workers sync.WaitGroup
			for worker := range 8 {
				workers.Go(func() {
					<-start
					for iteration := range 2 * len(test.inputs) {
						index := (iteration + worker*17) % len(test.inputs)
						got, err := cache.parse(test.inputs[index])
						if !reflect.DeepEqual(got, wants[index]) || !reflect.DeepEqual(err, errors[index]) {
							t.Errorf("concurrent parse %q: got %#v / %v; want %#v / %v", test.inputs[index], got, err, wants[index], errors[index])
							return
						}
					}
				})
			}
			close(start)
			workers.Wait()
			cache.mu.Lock()
			defer cache.mu.Unlock()
			retained := 0
			for raw := range cache.entries {
				if charges[raw] <= 0 {
					t.Fatalf("ineligible input %q was retained", raw)
				}
				retained += charges[raw]
			}
			if retained != cache.bytes || retained <= 0 || retained > maxRuntimeLegacyDNBytes || len(cache.entries) > maxRuntimeLegacyDNs {
				t.Fatalf("concurrent accounting: expected=%d, bytes=%d, entries=%d", retained, cache.bytes, len(cache.entries))
			}
		})
	}
}

func BenchmarkRuntimeLegacyDNCacheConnection(b *testing.B) {
	for _, test := range []struct{ name, raw string }{
		{"database-user", "uid=alice,dc=example,dc=com"},
		{"database-root", "cn=admin,dc=example,dc=com"},
		{"config-root", "cn=config"},
		{"config-database", "olcDatabase={1}mdb,cn=config"},
		{"empty", ""},
		{"multi-ava", "uid=alice+cn=Alice,dc=example,dc=com"},
		{"escaped", `cn=Smith\, Alice,dc=example,dc=com`},
	} {
		b.Run(test.name, func(b *testing.B) {
			for _, mode := range []string{"hot", "cold", "nil-cache"} {
				b.Run(mode, func(b *testing.B) {
					registry, err := schema.NewBuiltinRegistry()
					if err != nil {
						b.Fatal(err)
					}
					runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache(), databases: []runtimeDatabase{{
						suffixes:     []directory.DN{staticRuntimeDN("dc=example,dc=com")},
						rootDN:       new(staticRuntimeDN("cn=admin,dc=example,dc=com")),
						dnNormalizer: &databaseEqualityIndexNormalizer{registry: registry},
					}}}
					if _, err := parseRuntimeConnectionDN(runtime, test.raw); err != nil {
						b.Fatal(err)
					}
					if mode == "nil-cache" {
						runtime.legacyDNs = nil
					}
					b.ReportAllocs()
					if mode == "cold" {
						// Include construction/publication for a cold syntax cache;
						// downstream schema caches stay warm in all three modes.
						for b.Loop() {
							runtime.legacyDNs = newRuntimeLegacyDNCache()
							if _, err := parseRuntimeConnectionDN(runtime, test.raw); err != nil {
								b.Fatal(err)
							}
						}
					} else {
						for b.Loop() {
							if _, err := parseRuntimeConnectionDN(runtime, test.raw); err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		})
	}
}
