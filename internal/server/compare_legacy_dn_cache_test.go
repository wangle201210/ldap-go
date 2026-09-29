package server

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Preserve fa4d51a's three helpers as direct oracles for syntax-only reuse.
func compareLegacyCoreWriteDNOracle(runtime *runtimeState, value string) (directory.DN, error) {
	legacy, err := directory.ParseDN(value)
	if err != nil || runtime == nil || isConfigurationDN(legacy) {
		return legacy, err
	}
	if database := databaseForDN(runtime, legacy); database != nil {
		if isMonitorDatabase(*database) {
			return legacy, nil
		}
		return parseRuntimeDN(value, database.dnNormalizer)
	}
	if runtime.schema != nil {
		return runtime.schema.NormalizeDN(value)
	}
	return legacy, nil
}

func compareLegacyEntryDNOracle(reader storage.Reader, entry directory.Entry) (directory.Entry, error) {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	dn, err = storage.NormalizeReaderDN(reader, dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry.DN = dn.String()
	return entry, nil
}

func compareLegacyACLEntryOracle(runtime *runtimeState, database *runtimeDatabase, boundDN string, entry directory.Entry) (directory.Entry, error) {
	if runtime == nil || runtime.schema == nil || database == nil ||
		isConfigDatabase(*database) || isMonitorDatabase(*database) || boundDN == "" {
		return entry, nil
	}
	subject, err := runtime.schema.NormalizeDNCached(boundDN)
	if err != nil {
		return directory.Entry{}, err
	}
	target, err := runtime.schema.NormalizeDNCached(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	if subject.Equal(target) {
		return entry, nil
	}
	legacySubject, subjectErr := directory.ParseDN(boundDN)
	legacyTarget, targetErr := directory.ParseDN(entry.DN)
	if subjectErr != nil || targetErr != nil || !legacySubject.Equal(legacyTarget) {
		return entry, nil
	}
	entry.DN = fmt.Sprintf("cn=%x,%s", target.Key(), entry.DN)
	return entry, nil
}

func assertCompareLegacyEntry(t *testing.T, got directory.Entry, gotErr error, want directory.Entry, wantErr error) {
	t.Helper()
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
		t.Fatalf("entry = %#v / %v; want %#v / %v", got, gotErr, want, wantErr)
	}
}

func TestCompareLegacyDNCacheReference(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	for _, test := range []struct {
		name    string
		runtime *runtimeState
	}{
		{"nil runtime", nil},
		{"nil cache", &runtimeState{schema: registry}},
		{"legacy", &runtimeState{legacyDNs: newRuntimeLegacyDNCache()}},
		{"schema", &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}},
		{"database", &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache(), databases: []runtimeDatabase{{
			name: "{1}mdb", suffixes: []directory.DN{staticRuntimeDN("dc=example,dc=com")}, dnNormalizer: registry,
		}}}},
		{"monitor", &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache(), databases: []runtimeDatabase{{
			name: "{1}monitor", suffixes: []directory.DN{staticRuntimeDN("cn=monitor")}, dnNormalizer: registry,
		}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := &runtimeDatabase{name: "{1}mdb"}
			if test.runtime != nil && len(test.runtime.databases) != 0 {
				database = &test.runtime.databases[0]
			}
			for _, raw := range append(runtimeLegacyDNInputs(), "CN=Monitor", compareCoreUpperDN, compareCoreLowerDN) {
				t.Run(raw, func(t *testing.T) {
					entry := directory.Entry{DN: raw, Attributes: []directory.Attribute{{Description: "cn", Values: [][]byte{[]byte("Keep")}}}}
					trace := new(runtimeLegacyDNCallbackTrace)
					reader := passwordPolicyDNRecordingReader{registry: registry, trace: trace}
					wantDN, wantDNErr := compareLegacyCoreWriteDNOracle(test.runtime, raw)
					wantEntry, wantEntryErr := compareLegacyEntryDNOracle(reader, entry)
					wantCalls := slices.Clone(trace.calls)
					wantACL, wantACLErr := compareLegacyACLEntryOracle(test.runtime, database, compareCoreUpperDN, entry)
					for range 2 {
						got, err := parseCoreWriteDN(test.runtime, raw)
						assertRuntimeLegacyDNResult(t, raw, got, err, wantDN, wantDNErr)
						trace.calls = nil
						gotEntry, err := normalizeCompareEntryDN(test.runtime, reader, entry)
						assertCompareLegacyEntry(t, gotEntry, err, wantEntry, wantEntryErr)
						if !slices.Equal(trace.calls, wantCalls) {
							t.Fatalf("reader callbacks=%v; want %v", trace.calls, wantCalls)
						}
						gotEntry, err = normalizeCompareACLEntry(test.runtime, database, compareCoreUpperDN, entry)
						assertCompareLegacyEntry(t, gotEntry, err, wantACL, wantACLErr)
					}
				})
			}
			if test.runtime != nil && test.runtime.legacyDNs != nil {
				for raw, cached := range test.runtime.legacyDNs.entries {
					want, err := directory.ParseDN(raw)
					assertRuntimeLegacyDNResult(t, raw, cached, nil, want, err)
				}
			}
		})
	}
}

func TestCompareLegacyDNCacheLiveCallbacks(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	trace := new(runtimeLegacyDNCallbackTrace)
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{
		{suffixes: []directory.DN{staticRuntimeDN("dc=other,dc=com")},
			dnNormalizer: runtimeLegacyDNRecordingNormalizer{registry: registry, name: "first", trace: trace}},
		{suffixes: []directory.DN{staticRuntimeDN("dc=example,dc=com")},
			dnNormalizer: passwordPolicyDNRecordingParser{runtimeLegacyDNRecordingNormalizer{registry: registry, trace: trace}}},
	}}
	const raw = "foldAlias=ENGINEERING+" + dnMultiAVAExactOID + "=Alice,DC=EXAMPLE,DC=COM"
	if _, err := compareLegacyCoreWriteDNOracle(runtime, raw); err != nil {
		t.Fatal(err)
	}
	baseline := slices.Clone(trace.calls)
	if len(baseline) < 4 || baseline[len(baseline)-1] != "parser:"+raw {
		t.Fatalf("fixture must route then pass original request spelling to custom parser: %v", baseline)
	}
	stored, err := registry.NormalizeDN(compareCoreUpperDN)
	if err != nil {
		t.Fatal(err)
	}
	entry := (directory.Entry{DN: stored.String()}).WithNormalizedDNHint(stored, "stored-order")
	reader := passwordPolicyDNRecordingReader{registry: registry, trace: trace}
	// Exercise swallowed routing errors, final parser errors, and recovery on
	// the same warm syntax cache. The reader must still run despite its hint.
	for _, failAt := range []int{1, len(baseline)} {
		runtime.legacyDNs = newRuntimeLegacyDNCache()
		for _, failure := range []error{errors.New("callback failed"), errors.New("changed failure"), nil} {
			*trace = runtimeLegacyDNCallbackTrace{failAt: failAt, fail: failure}
			want, wantErr := compareLegacyCoreWriteDNOracle(runtime, raw)
			wantCalls := slices.Clone(trace.calls)
			for range 2 {
				trace.calls = nil
				got, err := parseCoreWriteDN(runtime, raw)
				assertRuntimeLegacyDNResult(t, raw, got, err, want, wantErr)
				if !slices.Equal(trace.calls, wantCalls) || errors.Is(err, failure) != errors.Is(wantErr, failure) {
					t.Fatalf("callback %d: calls=%v error=%v; want calls=%v error=%v", failAt, trace.calls, err, wantCalls, wantErr)
				}
			}
			*trace = runtimeLegacyDNCallbackTrace{failAt: 1, fail: failure}
			wantEntry, wantErr := compareLegacyEntryDNOracle(reader, entry)
			for range 2 {
				trace.calls = nil
				got, err := normalizeCompareEntryDN(runtime, reader, entry)
				assertCompareLegacyEntry(t, got, err, wantEntry, wantErr)
				if !slices.Equal(trace.calls, []string{"reader:" + staticRuntimeDN(entry.DN).String()}) || !errors.Is(err, failure) {
					t.Fatalf("reader callbacks=%v error=%v; want stored spelling and %v", trace.calls, err, failure)
				}
			}
		}
		for _, spelling := range []string{raw, entry.DN} {
			cached, ok := runtime.legacyDNs.entries[spelling]
			want, err := directory.ParseDN(spelling)
			if !ok {
				t.Fatalf("missing syntax cache entry for %q", spelling)
			}
			assertRuntimeLegacyDNResult(t, spelling, cached, nil, want, err)
		}
	}
}

func TestCompareLegacyDNCacheACLEarlyReturnsAndLiveSchema(t *testing.T) {
	registry := newDNMultiAVARegistry(t)
	runtime := &runtimeState{schema: registry, legacyDNs: newRuntimeLegacyDNCache()}
	for _, database := range []*runtimeDatabase{nil, {name: "{0}config"}, {name: "{1}monitor"}} {
		entry := directory.Entry{DN: "invalid target"}
		want, wantErr := compareLegacyACLEntryOracle(runtime, database, "invalid subject", entry)
		got, err := normalizeCompareACLEntry(runtime, database, "invalid subject", entry)
		assertCompareLegacyEntry(t, got, err, want, wantErr)
	}
	entry := directory.Entry{DN: compareCoreLowerDN}
	attribute, _ := registry.AttributeType("exactName")
	for _, equality := range []string{"caseExactMatch", "caseIgnoreMatch", "caseExactMatch"} {
		attribute.Equality = equality
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		wantDN, wantErr := compareLegacyCoreWriteDNOracle(runtime, compareCoreUpperDN)
		gotDN, err := parseCoreWriteDN(runtime, compareCoreUpperDN)
		assertRuntimeLegacyDNResult(t, equality, gotDN, err, wantDN, wantErr)
		want, wantErr := compareLegacyACLEntryOracle(runtime, &runtimeDatabase{}, compareCoreUpperDN, entry)
		got, err := normalizeCompareACLEntry(runtime, &runtimeDatabase{}, compareCoreUpperDN, entry)
		assertCompareLegacyEntry(t, got, err, want, wantErr)
		if err != nil || (got.DN != entry.DN) != (equality == "caseExactMatch") {
			t.Fatalf("schema mutation did not update ACL identity: entry=%#v error=%v", got, err)
		}
	}
}
