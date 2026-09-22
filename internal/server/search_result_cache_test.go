package server

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestSearchResultCacheSeparatesStorageRevisions(t *testing.T) {
	t.Parallel()

	cache := newSearchResultCache(1 << 20)
	fingerprint := [32]byte{1, 2, 3}
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "uid",
			Values:      [][]byte{[]byte("alice")},
		}},
	}
	cache.put(fingerprint, 7, []directory.Entry{entry})
	got, found := cache.get(fingerprint, 7)
	if !found || len(got) != 1 || !entry.Equal(got[0]) {
		t.Fatalf("cached entries = %#v, found=%t", got, found)
	}
	if _, found := cache.get(fingerprint, 8); found {
		t.Fatal("cache reused a result across storage revisions")
	}
	entry.Attributes[0].Description = "cn"
	entry.Attributes[0].Values[0][0] = 'X'
	got[0] = directory.Entry{}
	again, found := cache.get(fingerprint, 7)
	if !found || again[0].Attributes[0].Description != "uid" ||
		string(again[0].Attributes[0].Values[0]) != "alice" {
		t.Fatalf("caller mutation changed cached value: %#v", again)
	}
}

func TestSearchBaseCacheSeparatesRevisionsAndOwnsEntries(t *testing.T) {
	t.Parallel()

	cache := newSearchBaseCache()
	dn, err := directory.ParseDN("ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: dn.String(),
		Attributes: []directory.Attribute{{
			Description: "ou",
			Values:      [][]byte{[]byte("people")},
		}},
	}
	cache.put("db", dn, 7, entry)
	entry.Attributes[0].Values[0][0] = 'X'
	got, found := cache.get("db", dn, 7)
	if !found || string(got.Attributes[0].Values[0]) != "people" {
		t.Fatalf("cached base = %#v, found=%t", got, found)
	}
	if _, found := cache.get("db", dn, 8); found {
		t.Fatal("base cache reused an entry across storage revisions")
	}
	if _, found := cache.get("other", dn, 7); found {
		t.Fatal("base cache reused an entry across partitions")
	}
	cache.put("db", dn, 7, entry)
	if string(got.Attributes[0].Values[0]) != "people" {
		t.Fatal("replacement changed an earlier base snapshot")
	}
}

func TestRootEqualitySearchFingerprintSeparatesRequestFields(t *testing.T) {
	t.Parallel()

	request := ldapwire.SearchRequest{
		BaseDN:     "ou=people,dc=example,dc=com",
		Scope:      directory.ScopeWholeSubtree,
		Filter:     directory.Filter{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("alice")},
		Attributes: []string{"uid"},
	}
	baseline := rootEqualitySearchFingerprint("cn=admin,dc=example,dc=com", request)
	tests := []ldapwire.SearchRequest{
		func() ldapwire.SearchRequest { value := request; value.BaseDN = "dc=example,dc=com"; return value }(),
		func() ldapwire.SearchRequest {
			value := request
			value.Scope = directory.ScopeSingleLevel
			return value
		}(),
		func() ldapwire.SearchRequest { value := request; value.TypesOnly = true; return value }(),
		func() ldapwire.SearchRequest { value := request; value.Filter.Assertion = []byte("bob"); return value }(),
		func() ldapwire.SearchRequest { value := request; value.Attributes = []string{"cn"}; return value }(),
	}
	for index, candidate := range tests {
		if got := rootEqualitySearchFingerprint("cn=admin,dc=example,dc=com", candidate); got == baseline {
			t.Fatalf("candidate %d reused the baseline fingerprint", index)
		}
	}
	if got := rootEqualitySearchFingerprint("uid=alice,dc=example,dc=com", request); got == baseline {
		t.Fatal("bound DN reused the baseline fingerprint")
	}
}

func BenchmarkRootEqualitySearchFingerprint(b *testing.B) {
	request := ldapwire.SearchRequest{
		BaseDN:     "ou=people,dc=example,dc=com",
		Scope:      directory.ScopeWholeSubtree,
		Filter:     directory.Filter{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("alice")},
		Attributes: []string{"uid"},
	}
	boundDN := "cn=admin,dc=example,dc=com"
	b.Run("binary", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = rootEqualitySearchFingerprint(boundDN, request)
		}
	})
	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			encoded, _ := json.Marshal(struct {
				BoundDN string
				Request ldapwire.SearchRequest
			}{BoundDN: boundDN, Request: request})
			_ = encoded
		}
	})
}

func TestSearchResultCacheRetainsEmptyResults(t *testing.T) {
	t.Parallel()

	cache := newSearchResultCache(1024)
	fingerprint := [32]byte{9}
	cache.put(fingerprint, 1, nil)
	entries, found := cache.get(fingerprint, 1)
	if !found || len(entries) != 0 {
		t.Fatalf("empty cache result = %#v, found=%t", entries, found)
	}
}

func TestSearchResultCacheHonorsMemoryLimit(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN:         "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{Description: "uid", Values: [][]byte{[]byte("alice")}}},
	}
	larger := entry.Clone()
	larger.Attributes = append(larger.Attributes, directory.Attribute{
		Description: "jpegPhoto", Values: [][]byte{make([]byte, 256)},
	})
	cache := newSearchResultCache(64 + searchResultCacheEntryBytes(larger) + 64)
	fingerprint, emptyFingerprint := [32]byte{1}, [32]byte{2}
	cache.put(emptyFingerprint, 7, nil)
	cache.put(fingerprint, 7, []directory.Entry{entry})
	previous, _ := cache.get(fingerprint, 7)
	cache.put(fingerprint, 7, []directory.Entry{larger})
	got, found := cache.get(fingerprint, 7)
	if !found || len(got) != 1 || !got[0].Equal(larger) {
		t.Fatalf("replacement = %#v, found=%t", got, found)
	}
	if cache.bytes != cache.maximum || len(cache.entries) != 2 {
		t.Fatalf("replacement accounting: bytes=%d, entries=%d", cache.bytes, len(cache.entries))
	}
	if _, found := cache.get(emptyFingerprint, 7); !found {
		t.Fatal("replacement evicted an entry despite fitting exactly")
	}
	if len(previous) != 1 || !previous[0].Equal(entry) {
		t.Fatal("replacement changed an earlier result snapshot")
	}

	oversized := larger.Clone()
	oversized.Attributes[1].Values[0] = make([]byte, 256+65)
	cache.put(fingerprint, 7, []directory.Entry{oversized})
	again, found := cache.get(fingerprint, 7)
	if !found || len(again) != 1 || !again[0].Equal(larger) ||
		cache.bytes != cache.maximum || len(cache.entries) != 2 {
		t.Fatal("rejected replacement changed cached entries or accounting")
	}

	cache.put([32]byte{3}, 7, nil)
	if cache.bytes != 64 || len(cache.entries) != 1 {
		t.Fatalf("eviction accounting: bytes=%d, entries=%d", cache.bytes, len(cache.entries))
	}
	if _, found := cache.get(fingerprint, 7); found {
		t.Fatal("memory limit did not evict previous results")
	}
	if !got[0].Equal(larger) || !previous[0].Equal(entry) {
		t.Fatal("eviction changed an earlier result snapshot")
	}
}

func TestSearchResultCacheRejectsOversizedWithoutCloning(t *testing.T) {
	entries := []directory.Entry{
		{DN: "dc=example,dc=com"},
		{Attributes: []directory.Attribute{{Description: "jpegPhoto", Values: [][]byte{make([]byte, 4096)}}}},
	}
	for _, maximum := range []int64{-1, 0, 63, 1024} {
		t.Run(fmt.Sprint(maximum), func(t *testing.T) {
			cache := newSearchResultCache(maximum)
			allocations := testing.AllocsPerRun(10, func() {
				cache.put([32]byte{1}, 7, entries)
			})
			if allocations != 0 {
				t.Fatalf("rejected result allocated %g times", allocations)
			}
			if cache.bytes != 0 || len(cache.entries) != 0 {
				t.Fatal("oversized result was retained")
			}
		})
	}
}

func TestSearchResultCacheEntryLimits(t *testing.T) {
	t.Parallel()

	results := newSearchResultCache(32 << 20)
	for revision := uint64(0); revision < searchResultCacheMaximumEntries; revision++ {
		results.put([32]byte{1}, revision, nil)
	}
	if len(results.entries) != searchResultCacheMaximumEntries || results.bytes != 64*searchResultCacheMaximumEntries {
		t.Fatal("result entry limit evicted entries too early")
	}
	results.put([32]byte{1}, searchResultCacheMaximumEntries, nil)
	if len(results.entries) != 1 || results.bytes != 64 {
		t.Fatalf("result entry limit: entries=%d, bytes=%d", len(results.entries), results.bytes)
	}
	bases := newSearchBaseCache()
	dn, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	for revision := uint64(0); revision < searchBaseCacheMaximumEntries; revision++ {
		bases.put("db", dn, revision, directory.Entry{DN: dn.String()})
	}
	if len(bases.entries) != searchBaseCacheMaximumEntries {
		t.Fatal("base entry limit evicted entries too early")
	}
	bases.put("db", dn, searchBaseCacheMaximumEntries, directory.Entry{DN: dn.String()})
	if len(bases.entries) != 1 {
		t.Fatalf("base entry limit: entries=%d", len(bases.entries))
	}
	if _, found := bases.get("db", dn, searchBaseCacheMaximumEntries); !found {
		t.Fatal("base eviction did not retain the new entry")
	}
}

func TestSearchResultCacheConcurrentAccess(t *testing.T) {
	t.Parallel()

	results, bases := newSearchResultCache(2048), newSearchBaseCache()
	dn, err := directory.ParseDN("ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for worker := range 8 {
		workers.Go(func() {
			for iteration := range 128 {
				revision := uint64((worker*17 + iteration) % (searchBaseCacheMaximumEntries + 1))
				want := directory.Entry{
					DN: dn.String(),
					Attributes: []directory.Attribute{{
						Description: "description", Values: [][]byte{[]byte(fmt.Sprint(revision))},
					}},
				}
				entry := want.Clone()
				results.put([32]byte{1}, revision, []directory.Entry{entry})
				bases.put("db", dn, revision, entry)
				entry.Attributes[0].Values[0][0] = 'X'
				if got, found := results.get([32]byte{1}, revision); found {
					if len(got) != 1 || !got[0].Equal(want) {
						t.Error("concurrent result lookup returned a mutated entry or wrong revision")
						return
					}
					got[0] = directory.Entry{}
				}
				if got, found := bases.get("db", dn, revision); found && !got.Equal(want) {
					t.Error("concurrent base lookup returned a mutated entry or wrong revision")
					return
				}
			}
		})
	}
	workers.Wait()
	var retained int64
	for _, entry := range results.entries {
		retained += entry.bytes
	}
	if results.bytes != retained || retained > results.maximum ||
		len(results.entries) > searchResultCacheMaximumEntries || len(bases.entries) > searchBaseCacheMaximumEntries {
		t.Fatalf("concurrent cache accounting: bytes=%d, retained=%d, results=%d, bases=%d",
			results.bytes, retained, len(results.entries), len(bases.entries))
	}
}

func BenchmarkSearchResultCache(b *testing.B) {
	entry := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "uid", Values: [][]byte{[]byte("alice")}},
			{Description: "cn", Values: [][]byte{[]byte("Alice Example")}},
			{Description: "mail", Values: [][]byte{[]byte("alice@example.com")}},
		},
	}
	fingerprint := [32]byte{1}
	for _, count := range []int{1, 4} {
		entries := make([]directory.Entry, count)
		for index := range entries {
			entries[index] = entry
		}
		b.Run(fmt.Sprintf("entries=%d", count), func(b *testing.B) {
			cache := newSearchResultCache(32 << 20)
			cache.put(fingerprint, 7, entries)
			b.Run("get", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_, _ = cache.get(fingerprint, 7)
				}
			})
			b.Run("get_parallel", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						if got, found := cache.get(fingerprint, 7); !found || len(got) != count {
							b.Error("cached result missing")
						}
					}
				})
			})
			b.Run("put", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					cache.put(fingerprint, 7, entries)
				}
			})
		})
	}
	b.Run("reject_oversized", func(b *testing.B) {
		cache := newSearchResultCache(32 << 10)
		entries := []directory.Entry{{
			DN: entry.DN,
			Attributes: []directory.Attribute{{
				Description: "jpegPhoto",
				Values:      [][]byte{make([]byte, 64<<10)},
			}},
		}}
		b.ReportAllocs()
		for b.Loop() {
			cache.put(fingerprint, 7, entries)
		}
	})
}

func BenchmarkSearchBaseCache(b *testing.B) {
	dn, err := directory.ParseDN("ou=people,dc=example,dc=com")
	if err != nil {
		b.Fatal(err)
	}
	entry := directory.Entry{
		DN: dn.String(),
		Attributes: []directory.Attribute{
			{Description: "ou", Values: [][]byte{[]byte("people")}},
			{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("organizationalUnit")}},
		},
	}
	cache := newSearchBaseCache()
	cache.put("db", dn, 7, entry)
	b.Run("get", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = cache.get("db", dn, 7)
		}
	})
	b.Run("get_parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, found := cache.get("db", dn, 7); !found {
					b.Error("cached base missing")
				}
			}
		})
	})
	b.Run("put", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			cache.put("db", dn, 7, entry)
		}
	})
	b.Run("put_parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				cache.put("db", dn, 7, entry)
			}
		})
	})
}
