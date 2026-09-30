package server

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func compareDNPrefixTestRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func compareDNPrefixTestEntry(count int) directory.Entry {
	values := make([][]byte, count)
	for i := range values {
		values[i] = fmt.Appendf(nil, "cn=User%04d,ou=People,dc=example", i)
	}
	return directory.Entry{DN: "cn=group,dc=example", Attributes: []directory.Attribute{{Description: "member", Values: values}}}
}

func checkCompareDNPrefixQuery(t *testing.T, cache *compareDNPrefixCache, registry *schema.Registry, entry directory.Entry, description string, assertion []byte) {
	t.Helper()
	before, assertionBefore := entry.Clone(), bytes.Clone(assertion)
	wantPresent, wantMatched, wantErr := registry.CompareEntryAttributeCachedDN(entry, description, assertion)
	present, matched, err := cache.compare(registry, entry, description, assertion)
	if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
		t.Fatalf("%s=%q: got (%v,%v,%v), want (%v,%v,%v)", description, assertion, present, matched, err, wantPresent, wantMatched, wantErr)
	}
	// Clone may turn a nil attribute slice into an empty slice.
	if !reflect.DeepEqual(entry.Clone(), before) || !bytes.Equal(assertion, assertionBefore) {
		t.Fatal("comparison mutated caller input")
	}
}

// Include every outstanding lease, so retired records cannot disappear from
// the accounting oracle merely because they are no longer in the map.
func checkCompareDNPrefixAccounting(t *testing.T, cache *compareDNPrefixCache, leases ...*compareDNPrefixLease) {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	refs := make(map[*compareDNPrefixRecord]int)
	for key, record := range cache.records {
		refs[record]++
		wantCost := record.token.RetainedBytes() + 512 + 4*(len(key.dn)+len(key.description))
		if record.cost != wantCost {
			t.Fatalf("record cost=%d, want %d", record.cost, wantCost)
		}
	}
	reserved := 0
	for _, lease := range leases {
		reserved += lease.reserved
		if lease.reserved < 0 || lease.reserved > compareDNPrefixReserve {
			t.Fatalf("invalid lease reservation: %d", lease.reserved)
		}
		if lease.record != nil {
			refs[lease.record]++
		}
	}
	live := compareDNPrefixMetadata
	for record, wantRefs := range refs {
		if record.refs != wantRefs || record.token == nil || record.token.RetainedBytes() <= 0 || record.token.RetainedBytes() > compareDNPrefixMaxToken {
			t.Fatalf("invalid live record: refs=%d, want %d, retained=%d", record.refs, wantRefs, record.token.RetainedBytes())
		}
		live += record.cost
	}
	if cache.live != live || cache.reserved != reserved || live+reserved > compareDNPrefixMaxBytes || len(cache.records) > compareDNPrefixMaxRecords {
		t.Fatalf("accounting live=%d/%d reserved=%d/%d records=%d", cache.live, live, cache.reserved, reserved, len(cache.records))
	}
}

func acquireCompareDNPrefixForTest(t *testing.T, cache *compareDNPrefixCache, key compareDNPrefixKey) *compareDNPrefixLease {
	t.Helper()
	lease, ok := cache.acquire(key)
	if !ok {
		t.Fatal("unexpected reservation rejection")
	}
	t.Cleanup(func() { cache.release(&lease) })
	return &lease
}

func TestCompareDNPrefixCacheFallback(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	base := compareDNPrefixTestEntry(32)
	checkCompareDNPrefixQuery(t, nil, registry, base, "member", base.Attributes[0].Values[0])
	for _, tc := range []struct {
		name, description string
		change            func(*directory.Entry)
	}{
		{"empty description", "", nil},
		{"other description", "cn", nil},
		{"case alias", "MEMBER", nil},
		{"OID alias", "2.5.4.31", nil},
		{"option", "member;lang-en", nil},
		{"empty DN", "member", func(e *directory.Entry) { e.DN = "" }},
		{"long DN", "member", func(e *directory.Entry) { e.DN = strings.Repeat("x", 1025) }},
		{"absent", "member", func(e *directory.Entry) { e.Attributes = nil }},
		{"empty values", "member", func(e *directory.Entry) { e.Attributes[0].Values = nil }},
		{"31 values", "member", func(e *directory.Entry) { e.Attributes[0].Values = e.Attributes[0].Values[:31] }},
		{"stored alias", "member", func(e *directory.Entry) { e.Attributes[0].Description = "MEMBER" }},
		{"stored option", "member", func(e *directory.Entry) { e.Attributes[0].Description = "member;lang-en" }},
		{"other attribute large", "member", func(e *directory.Entry) {
			e.Attributes = append(e.Attributes, directory.Attribute{Description: "cn", Values: e.Attributes[0].Values})
			e.Attributes[0].Values = e.Attributes[0].Values[:31]
		}},
		{"split values", "member", func(e *directory.Entry) {
			e.Attributes = append(e.Attributes, directory.Attribute{Description: "member", Values: e.Attributes[0].Values[16:]})
			e.Attributes[0].Values = e.Attributes[0].Values[:16]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newCompareDNPrefixCache()
			checkCompareDNPrefixQuery(t, cache, registry, base, "member", []byte("cn=missing"))
			key := compareDNPrefixKey{base.DN, "member"}
			owner := cache.records[key]
			var leases []*compareDNPrefixLease
			for range 7 {
				leases = append(leases, acquireCompareDNPrefixForTest(t, cache, compareDNPrefixKey{dn: "unpublished"}))
			}
			entry := base.Clone()
			if tc.change != nil {
				tc.change(&entry)
			}
			for _, assertion := range [][]byte{base.Attributes[0].Values[0], []byte("cn=missing"), []byte("bad-dn")} {
				checkCompareDNPrefixQuery(t, cache, registry, entry, tc.description, assertion)
			}
			// An attempted reservation here would evict the unborrowed owner.
			if cache.records[key] != owner || len(cache.records) != 1 {
				t.Fatal("fallback touched the prefix container")
			}
			checkCompareDNPrefixAccounting(t, cache, leases...)
		})
	}
	cache := newCompareDNPrefixCache()
	base.DN = "cn=" + strings.Repeat("x", 1021)
	checkCompareDNPrefixQuery(t, cache, registry, base, "member", []byte("CN=User0000,ou=People,dc=example"))
	if len(cache.records) != 1 {
		t.Fatal("1024-byte DN should qualify")
	}
	checkCompareDNPrefixAccounting(t, cache)
}

func TestCompareDNPrefixCacheRawIdenticalFirst(t *testing.T) {
	baseRegistry := compareDNPrefixTestRegistry(t)
	if err := baseRegistry.RegisterAttributeType(schema.AttributeType{
		OID: "1.2.3.863", Names: []string{"prefixGuardChild"}, Superior: "member",
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, first, earlier, equality string
		malformedLater, wantErr        bool
	}{
		{name: "exact first"},
		{name: "match before malformed later value", malformedLater: true},
		{name: "unrelated attribute before literal member", earlier: "description"},
		{name: "malformed identical value and assertion", first: "bad-dn", wantErr: true},
		{name: "malformed earlier subtype", earlier: "prefixGuardChild", wantErr: true},
		{name: "malformed earlier option", earlier: "member;lang-en", wantErr: true},
		{name: "malformed earlier subtype with option", earlier: "prefixGuardChild;lang-en", wantErr: true},
		{name: "member rule accepts non-DN", first: "bad-dn", equality: "caseExactMatch"},
		{name: "member rule rejects identical DN", equality: "integerMatch", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := baseRegistry.Clone()
			if tc.equality != "" {
				member, _ := registry.AttributeType("member")
				member.Equality = tc.equality
				if err := registry.UpsertAttributeType(member); err != nil {
					t.Fatal(err)
				}
			}
			entry := compareDNPrefixTestEntry(32)
			if tc.first != "" {
				entry.Attributes[0].Values[0] = []byte(tc.first)
			}
			if tc.malformedLater {
				entry.Attributes[0].Values[1] = []byte("bad-dn")
			}
			assertion := bytes.Clone(entry.Attributes[0].Values[0])
			if tc.earlier != "" {
				entry.Attributes = append([]directory.Attribute{{
					Description: tc.earlier, Values: [][]byte{[]byte("bad-dn")},
				}}, entry.Attributes...)
			}
			if !compareDNPrefixEligible(entry, "member") {
				t.Fatal("fixture must qualify for the prefix cache before the raw-identical guard")
			}
			present, matched, err := registry.CompareEntryAttributeCachedDN(entry, "member", assertion)
			if !present || matched != !tc.wantErr || (err != nil) != tc.wantErr {
				t.Fatalf("original comparator returned (%v,%v,%v), want present=true, matched=%v, error=%v", present, matched, err, !tc.wantErr, tc.wantErr)
			}
			cache := newCompareDNPrefixCache()
			checkCompareDNPrefixQuery(t, cache, registry, entry, "member", assertion)
			if len(cache.records) != 0 {
				t.Fatal("raw-identical first value populated the prefix cache")
			}
			checkCompareDNPrefixAccounting(t, cache)

			other := compareDNPrefixTestEntry(32)
			other.DN = "cn=other,dc=example"
			checkCompareDNPrefixQuery(t, cache, baseRegistry, other, "member", []byte("cn=missing"))
			key := compareDNPrefixKey{other.DN, "member"}
			owner := cache.records[key]
			if owner == nil {
				t.Fatal("reservation-pressure fixture did not publish a token")
			}
			var leases []*compareDNPrefixLease
			for range 7 {
				leases = append(leases, acquireCompareDNPrefixForTest(t, cache, compareDNPrefixKey{dn: "unpublished"}))
			}
			// Even an unsuccessful acquisition would evict the unrelated owner.
			checkCompareDNPrefixQuery(t, cache, registry, entry, "member", assertion)
			if cache.records[key] != owner || len(cache.records) != 1 {
				t.Fatal("raw-identical first value acquired the prefix cache")
			}
			checkCompareDNPrefixAccounting(t, cache, leases...)
		})
	}
}

func TestCompareDNPrefixCacheQueryChanges(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	cache := newCompareDNPrefixCache()
	entry := compareDNPrefixTestEntry(32)
	for range len(entry.Attributes[0].Values) {
		checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	}
	old := bytes.Clone(entry.Attributes[0].Values[0])
	copy(entry.Attributes[0].Values[0][3:7], "Else")
	for _, assertion := range [][]byte{old, entry.Attributes[0].Values[0], entry.Attributes[0].Values[31], []byte("cn=missing"), []byte("bad-dn")} {
		checkCompareDNPrefixQuery(t, cache, registry, entry, "member", assertion)
	}
	slices.Reverse(entry.Attributes[0].Values)
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", old)
	for _, values := range [][][]byte{
		{[]byte("bad-dn"), []byte("cn=target")},
		{[]byte("cn=target"), []byte("bad-dn")},
	} {
		copy(entry.Attributes[0].Values, values)
		checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=target"))
		checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	}
	entry = compareDNPrefixTestEntry(32)
	entry.Attributes = append(entry.Attributes, directory.Attribute{Description: "member;lang-en", Values: [][]byte{[]byte("bad-dn")}})
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	entry.Attributes = entry.Attributes[:1]
	entry.Attributes[0].Values = entry.Attributes[0].Values[:31]
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	entry.Attributes[0].Values = nil
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("bad-dn"))
	checkCompareDNPrefixAccounting(t, cache)
}

func TestCompareDNPrefixCacheRegistryChecks(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	cache := newCompareDNPrefixCache()
	entry := compareDNPrefixTestEntry(32)
	assertion := []byte("cn=user0000,ou=People,dc=example")
	attribute, _ := registry.AttributeType("cn")
	for _, rule := range []string{"caseIgnoreMatch", "caseExactMatch", "caseIgnoreMatch"} {
		attribute.Equality = rule
		if err := registry.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		checkCompareDNPrefixQuery(t, cache, registry, entry, "member", assertion)
	}
	left, right := registry.Clone(), registry.Clone()
	for i, other := range []*schema.Registry{left, right} {
		attribute.Equality = []string{"caseExactMatch", "caseIgnoreMatch"}[i]
		if err := other.UpsertAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	// Equal mutation counts with different Registry owners and naming rules.
	for _, other := range []*schema.Registry{left, right, left, right} {
		checkCompareDNPrefixQuery(t, cache, other, entry, "member", assertion)
	}
	member, _ := registry.AttributeType("member")
	member.Equality = "caseExactMatch"
	if err := registry.UpsertAttributeType(member); err != nil {
		t.Fatal(err)
	}
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", assertion)
	checkCompareDNPrefixAccounting(t, cache)
}

func TestCompareDNPrefixCacheGrowthAndOwnedKeys(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	entry := compareDNPrefixTestEntry(40)
	backing := strings.Repeat("x", 1<<20) + entry.DN + "member"
	entry.DN = backing[1<<20 : len(backing)-len("member")]
	description := backing[len(backing)-len("member"):]
	full, early := newCompareDNPrefixCache(), newCompareDNPrefixCache()
	key := compareDNPrefixKey{entry.DN, description}
	for pass := range len(entry.Attributes[0].Values) {
		checkCompareDNPrefixQuery(t, full, registry, entry, description, []byte("cn=missing"))
		// Equivalent DN spelling still exercises prefix growth on the first value.
		assertion := bytes.Clone(entry.Attributes[0].Values[pass])
		assertion[0], assertion[1] = 'C', 'N'
		checkCompareDNPrefixQuery(t, early, registry, entry, description, assertion)
		fullRecord, earlyRecord := full.records[key], early.records[key]
		if fullRecord == nil || earlyRecord == nil {
			t.Fatal("equivalent non-identical assertion did not publish a prefix")
		}
		if fullRecord.token.RetainedBytes() != earlyRecord.token.RetainedBytes() {
			t.Fatal("one call extended beyond one new value")
		}
		checkCompareDNPrefixAccounting(t, full)
		checkCompareDNPrefixAccounting(t, early)
	}
	owner, live := full.records[key], full.live
	checkCompareDNPrefixQuery(t, full, registry, entry, description, []byte("cn=missing"))
	if full.records[key] != owner || full.live != live {
		t.Fatal("unchanged token created another owner or charge")
	}
	for stored := range full.records {
		if unsafe.StringData(stored.dn) == unsafe.StringData(entry.DN) || unsafe.StringData(stored.description) == unsafe.StringData(description) {
			t.Fatal("key retains caller string backing storage")
		}
	}
	checkCompareDNPrefixAccounting(t, full)
}

func TestCompareDNPrefixCacheReservationLimit(t *testing.T) {
	cache := newCompareDNPrefixCache()
	var leases []*compareDNPrefixLease
	for range 7 {
		leases = append(leases, acquireCompareDNPrefixForTest(t, cache, compareDNPrefixKey{}))
		checkCompareDNPrefixAccounting(t, cache, leases...)
	}
	if _, ok := cache.acquire(compareDNPrefixKey{}); ok {
		t.Fatal("metadata plus eight reservations exceeds 8 MiB")
	}
	entry := compareDNPrefixTestEntry(32)
	registry := compareDNPrefixTestRegistry(t)
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", entry.Attributes[0].Values[31])
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("bad-dn"))
	checkCompareDNPrefixAccounting(t, cache, leases...)
	for _, lease := range leases {
		cache.release(lease)
	}
	checkCompareDNPrefixAccounting(t, cache)
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	if len(cache.records) != 1 {
		t.Fatal("reservation rejection prevented later publication")
	}
	checkCompareDNPrefixAccounting(t, cache)
}

func TestCompareDNPrefixCacheReplacementAndRetirement(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	entry := compareDNPrefixTestEntry(32)
	cache := newCompareDNPrefixCache()
	key := compareDNPrefixKey{entry.DN, "member"}
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	slow := acquireCompareDNPrefixForTest(t, cache, key)
	fast := acquireCompareDNPrefixForTest(t, cache, key)
	old := slow.record
	oldBytes := old.token.RetainedBytes()
	checkCompareDNPrefixAccounting(t, cache, slow, fast)
	present, matched, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", []byte("cn=missing"), fast.record.token)
	if !present || matched || err != nil || next == nil || next == old.token {
		t.Fatalf("extension failed: (%v,%v,%v)", present, matched, err)
	}
	before := cache.live + cache.reserved
	cache.publish(key, fast, next)
	current := cache.records[key]
	if current == old || cache.live+cache.reserved != before || fast.reserved != compareDNPrefixReserve-current.cost {
		t.Fatal("publication did not convert its reservation exactly once")
	}
	checkCompareDNPrefixAccounting(t, cache, slow, fast)
	changed := entry.Clone()
	changed.Attributes[0].Values[0] = []byte("cn=replaced")
	present, matched, shorter, err := registry.CompareEntryAttributeWithDNPrefix(changed, "member", changed.Attributes[0].Values[0], slow.record.token)
	if !present || !matched || err != nil || shorter == nil || shorter.RetainedBytes() >= next.RetainedBytes() {
		t.Fatalf("short branch failed: (%v,%v,%v)", present, matched, err)
	}
	cache.publish(key, slow, shorter)
	if cache.records[key] != current || slow.reserved != compareDNPrefixReserve {
		t.Fatal("stale borrower overwrote the newer publication")
	}
	cache.release(fast)
	checkCompareDNPrefixAccounting(t, cache, slow)
	if old.refs != 1 || old.token.RetainedBytes() != oldBytes {
		t.Fatal("replacement lost or mutated a borrowed old token")
	}
	// Seven reservations leave no room for an eighth even after evicting the
	// new owner. The retired old record must remain charged and usable.
	leases := []*compareDNPrefixLease{slow}
	for range 6 {
		leases = append(leases, acquireCompareDNPrefixForTest(t, cache, compareDNPrefixKey{}))
	}
	if _, ok := cache.acquire(key); ok {
		t.Fatal("budget admitted an eighth reservation")
	}
	// acquire(key) pins current, so pressure cannot evict it.
	if cache.records[key] != current || current.refs != 1 {
		t.Fatal("failed acquisition changed the current owner")
	}
	if _, ok := cache.acquire(compareDNPrefixKey{dn: "missing"}); ok {
		t.Fatal("eviction incorrectly released a borrowed retired token")
	}
	if len(cache.records) != 0 || cache.live != compareDNPrefixMetadata+old.cost || old.token == nil {
		t.Fatal("eviction hid retired live memory")
	}
	checkCompareDNPrefixAccounting(t, cache, leases...)
	present, matched, _, err = registry.CompareEntryAttributeWithDNPrefix(entry, "member", entry.Attributes[0].Values[0], old.token)
	if !present || !matched || err != nil || old.token.RetainedBytes() != oldBytes {
		t.Fatal("retired token is not usable by its remaining borrower")
	}
	for _, lease := range leases {
		cache.release(lease)
	}
	if old.refs != 0 || old.token != nil {
		t.Fatal("last release retained the retired token")
	}
	checkCompareDNPrefixAccounting(t, cache)
}

func TestCompareDNPrefixCacheColdPublicationAndRecordLimit(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	entry := compareDNPrefixTestEntry(32)
	cache := newCompareDNPrefixCache()
	key := compareDNPrefixKey{entry.DN, "member"}
	slow := acquireCompareDNPrefixForTest(t, cache, key)
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	owner := cache.records[key]
	_, _, next, err := registry.CompareEntryAttributeWithDNPrefix(entry, "member", entry.Attributes[0].Values[0], nil)
	if err != nil || next == nil {
		t.Fatal("cold branch failed")
	}
	cache.publish(key, slow, next)
	if cache.records[key] != owner {
		t.Fatal("cold loser replaced the first publication")
	}
	checkCompareDNPrefixAccounting(t, cache, slow)
	cache.release(slow)
	for i := range 64 {
		entry.DN = fmt.Sprintf("cn=group%d,dc=example", i)
		checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
		checkCompareDNPrefixAccounting(t, cache)
	}
	if len(cache.records) != 64 || cache.records[compareDNPrefixKey{entry.DN, "member"}] != nil {
		t.Fatal("record limit did not reject the 65th key")
	}
	entry.DN = key.dn
	checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
	if cache.records[key] == owner {
		t.Fatal("full map prevented replacement of an existing record")
	}
	checkCompareDNPrefixAccounting(t, cache)
}

func TestCompareDNPrefixCacheLiveBudgetEviction(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	entry := compareDNPrefixTestEntry(128)
	for i := range entry.Attributes[0].Values {
		entry.Attributes[0].Values[i] = fmt.Appendf(nil, "cn=%04d%s,dc=example", i, strings.Repeat("x", 970))
	}
	cache := newCompareDNPrefixCache()
	for i := range 40 {
		entry.DN = fmt.Sprintf("cn=large%d,dc=example", i)
		key := compareDNPrefixKey{entry.DN, "member"}
		for pass := range len(entry.Attributes[0].Values) + 1 {
			previous := cache.records[key]
			checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
			checkCompareDNPrefixAccounting(t, cache)
			if cache.records[key] == nil {
				t.Fatal("warming did not publish a token")
			}
			if cache.records[key] == previous {
				break
			}
			if pass == len(entry.Attributes[0].Values) {
				t.Fatal("prefix did not stop growing")
			}
		}
	}
	if len(cache.records) >= 40 || cache.live < 4<<20 {
		t.Fatalf("fixture did not exercise live-budget eviction: records=%d live=%d", len(cache.records), cache.live)
	}
}

func TestCompareDNPrefixCachePanicReleases(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	entry := compareDNPrefixTestEntry(32)
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprintf("warm=%t", warm), func(t *testing.T) {
			cache := newCompareDNPrefixCache()
			if warm {
				checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
			}
			before := cache.live
			for range 3 {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("nil registry did not panic")
						}
					}()
					cache.compare(nil, entry, "member", []byte("cn=missing"))
				}()
				if cache.live != before {
					t.Fatal("panic changed retained ownership")
				}
				checkCompareDNPrefixAccounting(t, cache)
			}
			checkCompareDNPrefixQuery(t, cache, registry, entry, "member", []byte("cn=missing"))
			checkCompareDNPrefixAccounting(t, cache)
		})
	}
}

func TestCompareDNPrefixCacheConcurrentQueries(t *testing.T) {
	registry := compareDNPrefixTestRegistry(t)
	cache := newCompareDNPrefixCache()
	start := make(chan struct{})
	failures := make(chan error, 16)
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Go(func() {
			entry := compareDNPrefixTestEntry(64)
			entry.Attributes[0].Values[0] = fmt.Appendf(nil, "cn=worker%d,dc=example", worker)
			<-start
			for round := range 24 {
				assertion := [][]byte{entry.Attributes[0].Values[0], entry.Attributes[0].Values[63], []byte("cn=missing"), []byte("bad-dn")}[round%4]
				wantPresent, wantMatched, wantErr := registry.CompareEntryAttributeCachedDN(entry, "member", assertion)
				present, matched, err := cache.compare(registry, entry, "member", assertion)
				if present != wantPresent || matched != wantMatched || !reflect.DeepEqual(err, wantErr) {
					failures <- fmt.Errorf("worker %d round %d: got (%v,%v,%v), want (%v,%v,%v)", worker, round, present, matched, err, wantPresent, wantMatched, wantErr)
					return
				}
				cache.mu.Lock()
				bounded := cache.live >= compareDNPrefixMetadata && cache.reserved >= 0 && cache.live+cache.reserved <= compareDNPrefixMaxBytes && len(cache.records) <= compareDNPrefixMaxRecords
				cache.mu.Unlock()
				if !bounded {
					failures <- fmt.Errorf("worker %d observed an invalid budget", worker)
					return
				}
			}
		})
	}
	close(start)
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	checkCompareDNPrefixAccounting(t, cache)
}
