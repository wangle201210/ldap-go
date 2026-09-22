package server

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// get preserves the original copying lookup as the reference for shared hits.
func (cache *pagedSnapshotCache) get(
	fingerprint [sha256.Size]byte,
	revision uint64,
) []pagedSortedItem {
	if cache == nil {
		return nil
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, ok := cache.entries[pagedSnapshotCacheKey{
		fingerprint: fingerprint,
		revision:    revision,
	}]
	if !ok {
		return nil
	}
	return append([]pagedSortedItem(nil), entry.items...)
}

func TestPagedSnapshotSharedCapacityAccounting(t *testing.T) {
	for _, size := range []int{1, 7, 1000, 4096, 100000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			items := make([]pagedSortedItem, size, size*2)
			for index := range items {
				items[index] = pagedSortedItem{route: index, dn: "uid=sample,dc=example"}
			}
			items[0].hasSelected = true
			items[0].selected = directory.Entry{
				DN: "uid=sample,dc=example",
				Attributes: []directory.Attribute{{
					Description: "description", Values: [][]byte{[]byte("one"), []byte("two")},
				}},
			}
			cacheBytes := pagedSortedSearchRetainedBytes(&pagedSortedSearch{items: items}) -
				pagedSortedSearchRetainedBytes(nil)
			fingerprint := [sha256.Size]byte{1}
			cache := newPagedSnapshotCache(cacheBytes - 1)
			cache.put(fingerprint, 1, items)
			if cache.getShared(fingerprint, 1) != nil || cache.bytes != 0 {
				t.Fatal("cache admission no longer uses the input capacity")
			}
			cache.maximum = cacheBytes
			cache.put(fingerprint, 1, items)
			shared := cache.getShared(fingerprint, 1)
			if shared == nil || !shared.live || !shared.shared || cache.bytes != cacheBytes {
				t.Fatal("shared snapshot or cache accounting changed")
			}
			legacy := &pagedSortedSearch{items: cache.get(fingerprint, 1), live: true}
			if !reflect.DeepEqual(shared.items, legacy.items) {
				t.Fatal("shared lookup changed snapshot contents or order")
			}
			backing := &shared.items[0]
			for page := range 4 {
				if cap(shared.items) != cap(legacy.items) ||
					pagedSortedSearchRetainedBytes(shared) != pagedSortedSearchRetainedBytes(legacy) {
					t.Fatalf("page %d changed capacity or retained-byte accounting", page)
				}
				if &shared.items[0] != backing {
					t.Fatalf("page %d copied the shared snapshot", page)
				}
				previous := shared
				shared = clonePagedSortedSearch(shared)
				legacy = clonePagedSortedSearch(legacy)
				shared.offset++
				if previous.offset != page {
					t.Fatal("continuation changed its preceding cursor")
				}
			}
		})
	}
}

func TestPagedSnapshotSharedOwnership(t *testing.T) {
	var absent *pagedSnapshotCache
	fingerprint := [sha256.Size]byte{1}
	cache := newPagedSnapshotCache(1 << 20)
	if absent.getShared(fingerprint, 1) != nil || cache.getShared(fingerprint, 1) != nil {
		t.Fatal("missing cache entry returned a shared snapshot")
	}
	items := []pagedSortedItem{{dn: "cn=original"}}
	cache.put(fingerprint, 1, items)
	items[0].dn = "cn=changed-input"
	ordinary := cache.get(fingerprint, 1)
	ordinary[0].dn = "cn=changed-output"
	shared := cache.getShared(fingerprint, 1)
	if shared == nil || shared.items[0].dn != "cn=original" {
		t.Fatal("ordinary get or put allowed a caller to modify cached items")
	}
	shared.offset++
	fresh := cache.getShared(fingerprint, 1)
	if fresh == shared || fresh.offset != 0 || &fresh.items[0] != &shared.items[0] {
		t.Fatal("shared lookups must share items but own their cursor")
	}
	if cache.getShared(fingerprint, 2) != nil {
		t.Fatal("shared lookup ignored the storage revision")
	}
	cache.put(fingerprint, 1, []pagedSortedItem{{dn: "cn=replacement"}})
	if shared.items[0].dn != "cn=original" || cache.getShared(fingerprint, 1).items[0].dn != "cn=replacement" {
		t.Fatal("replacement mutated an existing shared snapshot")
	}
	cache.maximum = cache.bytes
	cache.put([sha256.Size]byte{2}, 1, []pagedSortedItem{{dn: "cn=evict"}})
	if cache.getShared(fingerprint, 1) != nil {
		t.Fatal("cache did not evict the original key")
	}
	state := &connectionState{pagedSearch: &pagedSearchState{sorted: shared}}
	instance := &Server{}
	instance.clearStoppedSearchState(state, ldapwire.Message{
		Request: ldapwire.SearchRequest{}, Controls: []ldapwire.Control{{OID: pagedResultsControlOID}},
	}, searchSessionSnapshot{})
	if state.pagedSearch != nil || fresh.offset != 0 || fresh.items[0].dn != "cn=original" {
		t.Fatal("eviction or cancel cleanup changed another cursor's snapshot")
	}
}

func TestPagedSnapshotSharedDoubleAdmission(t *testing.T) {
	for _, shortfall := range []int64{1, 0} {
		t.Run(fmt.Sprintf("shortfall=%d", shortfall), func(t *testing.T) {
			instance := &Server{searchMemoryLimiter: newResourceByteLimiter(1 << 20)}
			state := &connectionState{runtime: &runtimeState{}}
			t.Cleanup(func() { clearPagedSearch(state) })
			request := ldapwire.SearchRequest{}
			fingerprint := pagedSearchFingerprint("", request, nil)
			cache := newPagedSnapshotCache(1 << 20)
			cache.put(fingerprint, 1, []pagedSortedItem{{dn: "cn=one"}, {dn: "cn=two"}})
			retained := pagedSortedSearchRetainedBytes(&pagedSortedSearch{items: cache.get(fingerprint, 1)})
			paging := &pagedSearchContext{
				fingerprint: fingerprint, runtime: state.runtime, totalLimit: 10,
				sorted: cache.getShared(fingerprint, 1),
			}
			if _, err := instance.completePagedSearch(state, paging, ldapwire.Result{Code: ldapwire.ResultSuccess},
				1, pagedSearchCursor{}, true); err != nil {
				t.Fatal(err)
			}
			if instance.searchMemoryLimiter.active.Load() != retained {
				t.Fatal("shared state changed the persistent memory charge")
			}
			previous := state.pagedSearch.sorted
			instance.searchMemoryLimiter.maximum = retained*2 - shortfall
			continuation, failure := instance.preparePagedSearch(t.Context(), state, request, nil,
				&pagedResultsRequest{size: 1, cookie: state.pagedSearch.cookie}, databaseSearchExecutionLimits{pageTotal: 10})
			if shortfall != 0 {
				if continuation != nil || failure == nil || failure.Code != ldapwire.ResultAdminLimitExceeded ||
					failure.DiagnosticMessage != "paged search state memory budget exceeded" || state.pagedSearch != nil {
					t.Fatal("shared continuation changed the double-admission failure boundary")
				}
			} else {
				if failure != nil || continuation == nil || continuation.sorted == nil ||
					instance.searchMemoryLimiter.active.Load() != retained*2 {
					t.Fatal("shared continuation did not reserve a second full lease")
				}
				if continuation.sorted == previous || &continuation.sorted.items[0] != &previous.items[0] {
					t.Fatal("continuation must copy only the cursor")
				}
				continuation.releaseRetainedMemory()
				clearPagedSearch(state)
			}
			if instance.searchMemoryLimiter.active.Load() != 0 {
				t.Fatal("shared state cleanup leaked its memory lease")
			}
		})
	}
}

func BenchmarkPagedSnapshotCacheHit(b *testing.B) {
	cache := newPagedSnapshotCache(64 << 20)
	fingerprint := [sha256.Size]byte{1}
	cache.put(fingerprint, 1, make([]pagedSortedItem, 100000))
	for _, shared := range []bool{false, true} {
		b.Run(fmt.Sprintf("shared=%t", shared), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var cursor *pagedSortedSearch
				if shared {
					cursor = cache.getShared(fingerprint, 1)
				} else {
					cursor = &pagedSortedSearch{items: cache.get(fingerprint, 1), live: true}
					cursor.retainedBytes = pagedSortedSearchRetainedBytes(cursor)
				}
				cursor = clonePagedSortedSearch(cursor)
				cursor.offset++
				if cursor.offset != 1 || len(cursor.items) != 100000 {
					b.Fatal("cache hit changed the snapshot or cursor")
				}
			}
		})
	}
}
