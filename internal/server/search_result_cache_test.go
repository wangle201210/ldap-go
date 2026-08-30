package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
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
	got[0] = directory.Entry{}
	again, found := cache.get(fingerprint, 7)
	if !found || string(again[0].Attributes[0].Values[0]) != "alice" {
		t.Fatalf("caller mutation changed cached value: %#v", again)
	}
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
