package server

import (
	"encoding/json"
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
	got[0] = directory.Entry{}
	again, found := cache.get(fingerprint, 7)
	if !found || string(again[0].Attributes[0].Values[0]) != "alice" {
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
