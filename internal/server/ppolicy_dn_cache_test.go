package server

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswordPolicyDNLegacyCacheParity(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	inputs := append(runtimeLegacyDNInputs(),
		"cn="+strings.Repeat("x", maxRuntimeLegacyDNInput),
		strings.Repeat("ou=x,", maxRuntimeLegacyDNDepth)+"dc=com",
	)
	for _, test := range []struct {
		name     string
		runtime  *runtimeState
		database *runtimeDatabase
	}{
		{name: "nil runtime"},
		{name: "nil cache", runtime: &runtimeState{schema: registry}},
		{name: "schema", runtime: &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}},
		{name: "database schema", runtime: &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()},
			database: &runtimeDatabase{dnNormalizer: registry}},
		{name: "database index normalizer", runtime: &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()},
			database: &runtimeDatabase{dnNormalizer: &databaseEqualityIndexNormalizer{registry: registry}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			uncached := test.runtime
			if uncached != nil {
				copy := *uncached
				copy.legacyDNs = nil
				uncached = &copy
			}
			for _, raw := range inputs {
				want, wantErr := normalizePasswordPolicyDN(uncached, test.database, nil, raw)
				for range 3 {
					got, gotErr := normalizePasswordPolicyDN(test.runtime, test.database, nil, raw)
					assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
				}
				if test.runtime == nil || test.runtime.legacyDNs == nil {
					continue
				}
				legacy, syntaxErr := directory.ParseDN(raw)
				cached, present := test.runtime.legacyDNs.entries[raw]
				cacheable := syntaxErr == nil && len(raw) <= maxRuntimeLegacyDNInput && legacy.Depth() <= maxRuntimeLegacyDNDepth
				if present != cacheable || present && !reflect.DeepEqual(cached, legacy) {
					t.Fatalf("%q: cache must contain only eligible legacy syntax; present=%v want=%v", raw, present, cacheable)
				}
			}
		})
	}
}

type passwordPolicyDNRecordingReader struct {
	storage.Reader
	registry *schema.Registry
	trace    *runtimeLegacyDNCallbackTrace
}

func (reader passwordPolicyDNRecordingReader) NormalizeDNIdentity(dn directory.DN) (directory.DN, error) {
	if err := reader.trace.record("reader:" + dn.String()); err != nil {
		return directory.DN{}, err
	}
	return reader.registry.NormalizeDN(dn.String())
}

type passwordPolicyDNRecordingParser struct {
	runtimeLegacyDNRecordingNormalizer
}

func (parser passwordPolicyDNRecordingParser) ParseDNIdentity(raw string) (directory.DN, error) {
	if err := parser.trace.record("parser:" + raw); err != nil {
		return directory.DN{}, err
	}
	return parser.registry.NormalizeDN(raw)
}

func TestPasswordPolicyDNLegacyCacheCallbackOrder(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	trace := new(runtimeLegacyDNCallbackTrace)
	normalizer := runtimeLegacyDNRecordingNormalizer{registry: registry, name: "database", trace: trace}
	reader := passwordPolicyDNRecordingReader{registry: registry, trace: trace}
	for _, custom := range []directory.DNAttributeNormalizer{normalizer, passwordPolicyDNRecordingParser{normalizer}} {
		runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}
		uncached := *runtime
		uncached.legacyDNs = nil
		database := &runtimeDatabase{dnNormalizer: custom}
		for _, raw := range []string{
			"uid=Alice,dc=example,dc=com",
			"foldAlias=ENGINEERING+exactAlias=Alice,dc=example,dc=com",
			"cn=config", "undefinedName=x,cn=config", "cn=broken,", "undefinedName=x,dc=example,dc=com",
		} {
			*trace = runtimeLegacyDNCallbackTrace{}
			_, _ = normalizePasswordPolicyDN(&uncached, database, reader, raw)
			baseline := slices.Clone(trace.calls)
			if strings.HasPrefix(raw, "uid=") && (len(baseline) < 2 || !strings.HasPrefix(baseline[len(baseline)-1], "reader:")) {
				t.Fatalf("fixture did not exercise database then reader normalization: %v", baseline)
			}
			if (raw == "cn=config" || raw == "undefinedName=x,cn=config" || raw == "cn=broken,") && len(baseline) != 0 {
				t.Fatalf("configuration or syntax failure reached callbacks: %v", baseline)
			}
			for failAt := 0; failAt <= len(baseline); failAt++ {
				for _, failure := range []error{errors.New("normalizer failed"), errors.New("changed failure"), nil} {
					*trace = runtimeLegacyDNCallbackTrace{failAt: failAt, fail: failure}
					want, wantErr := normalizePasswordPolicyDN(&uncached, database, reader, raw)
					wantCalls := slices.Clone(trace.calls)
					for range 2 {
						trace.calls = nil
						got, gotErr := normalizePasswordPolicyDN(runtime, database, reader, raw)
						assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
						if !slices.Equal(trace.calls, wantCalls) || errors.Is(gotErr, failure) != errors.Is(wantErr, failure) {
							t.Fatalf("%q failure at callback %d: got calls=%v error=%v; want calls=%v error=%v",
								raw, failAt, trace.calls, gotErr, wantCalls, wantErr)
						}
					}
				}
			}
		}
	}
}

func TestPasswordPolicyDNLegacyCacheKeepsSchemaAndDatabaseLive(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}
	const raw = "uid=Alice,dc=example,dc=com"
	before, err := normalizePasswordPolicyDN(runtime, nil, nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	attribute, _ := registry.AttributeType("uid")
	attribute.Equality = "caseExactMatch"
	if err := registry.UpsertAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	after, err := normalizePasswordPolicyDN(runtime, nil, nil, raw)
	if err != nil || before.Key() == after.Key() {
		t.Fatalf("schema change did not reach a warm legacy cache: before=%q after=%q error=%v", before.Key(), after.Key(), err)
	}
	fold := newDNMultiAVARegistry(t)
	database := &runtimeDatabase{dnNormalizer: fold}
	got, gotErr := normalizePasswordPolicyDN(runtime, database, nil, raw)
	want, wantErr := fold.NormalizeDN(raw)
	assertRuntimeLegacyDNResult(t, raw, got, gotErr, want, wantErr)
	database.dnNormalizer = registry
	got, gotErr = normalizePasswordPolicyDN(runtime, database, nil, raw)
	assertRuntimeLegacyDNResult(t, raw, got, gotErr, after, nil)
	legacy, err := directory.ParseDN(raw)
	if err != nil || !reflect.DeepEqual(runtime.legacyDNs.entries[raw], legacy) {
		t.Fatal("schema or database normalization replaced cached legacy syntax")
	}
}

func BenchmarkPasswordPolicyDNLegacyCache(b *testing.B) {
	for _, cached := range []bool{false, true} {
		name := "uncached"
		if cached {
			name = "cached"
		}
		b.Run(name, func(b *testing.B) {
			registry, err := schema.NewBuiltinRegistry()
			if err != nil {
				b.Fatal(err)
			}
			runtime := &runtimeState{schema: registry}
			if cached {
				runtime.legacyDNs = newRuntimeLegacyDNCache()
			}
			database := &runtimeDatabase{dnNormalizer: &databaseEqualityIndexNormalizer{registry: registry}}
			const raw = "uid=user1,ou=ldapcommonbench-profile,dc=scale,dc=qualification"
			for _, route := range []*runtimeDatabase{nil, database} {
				if _, err := normalizePasswordPolicyDN(runtime, route, nil, raw); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := normalizePasswordPolicyDN(runtime, nil, nil, raw); err != nil {
					b.Fatal(err)
				}
				if _, err := normalizePasswordPolicyDN(runtime, database, nil, raw); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(2, "normalizations/op")
		})
	}
}
