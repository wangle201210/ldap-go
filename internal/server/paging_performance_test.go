package server

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestCachedPagedSearchClientsHaveIndependentCursors(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			var store storage.Store = storage.NewMemory()
			if backend == "bolt" {
				var err error
				store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			expected := seedPagedPeople(t, store, 17)
			address, stop := startServer(t, store, Config{
				RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret"),
			})
			defer stop()
			first := bindPagedRootClient(t, address)
			defer first.Close()
			second := bindPagedRootClient(t, address)
			defer second.Close()
			firstControl, secondControl := ldap.NewControlPaging(2), ldap.NewControlPaging(2)
			firstRequest := newPagedPeopleSearch(0, firstControl)
			secondRequest := newPagedPeopleSearch(0, secondControl)
			firstPage, err := first.Search(firstRequest)
			if err != nil {
				t.Fatal(err)
			}
			secondPage, err := second.Search(secondRequest)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pagedResultUIDs(t, firstPage), pagedResultUIDs(t, secondPage)) {
				t.Fatal("starting another cursor changed the first page")
			}
			firstControl.SetCookie(bytes.Clone(pagedResponseControl(t, firstPage).Cookie))
			advanced, err := first.Search(firstRequest)
			if err != nil {
				t.Fatal(err)
			}
			firstControl.SetCookie(bytes.Clone(pagedResponseControl(t, advanced).Cookie))
			firstControl.PagingSize = 0
			if _, err := first.Search(firstRequest); err != nil {
				t.Fatalf("abandon first cursor: %v", err)
			}
			got := pagedResultUIDs(t, secondPage)
			cookie := bytes.Clone(pagedResponseControl(t, secondPage).Cookie)
			for page := 0; len(cookie) > 0; page++ {
				if page > len(expected) {
					t.Fatal("second cursor did not terminate")
				}
				secondControl.SetCookie(cookie)
				secondControl.PagingSize = uint32(1 + page%4)
				result, err := second.Search(secondRequest)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, pagedResultUIDs(t, result)...)
				cookie = bytes.Clone(pagedResponseControl(t, result).Cookie)
			}
			slices.Sort(got)
			if !slices.Equal(got, expected) {
				t.Fatalf("second cursor returned %v, want %v", got, expected)
			}
			fresh, err := first.SearchWithPaging(newPagedPeopleSearch(0, nil), 3)
			if err != nil {
				t.Fatal(err)
			}
			got = pagedResultUIDs(t, fresh)
			slices.Sort(got)
			if !slices.Equal(got, expected) {
				t.Fatalf("cached snapshot was changed by its readers: %v", got)
			}
		})
	}
}

func TestTrustedSearchDNOrderMatchesReader(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ParseAndRegisterAttributeType("( 1.3.6.1.4.1.99999.916.1 NAME ( 'exactName' 'exactAlias' ) EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"); err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	defer store.Close()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		reader = storage.ReaderInPartitionWithNormalizer(reader, "test", registry)
		for _, value := range []string{
			"UID=Alice,OU=People,DC=Example,DC=COM",
			"exactName=Alpha,dc=example,dc=com",
			"exactAlias=alpha,dc=example,dc=com",
			`2.5.4.3=Alice\, Smith+exactAlias=Upper,dc=example,dc=com`,
			`exactName=Upper+CN=Alice\, Smith,dc=example,dc=com`,
			`cn=\20Space\20,dc=example,dc=com`,
		} {
			original, err := directory.ParseDNWithNormalizer(value, registry)
			if err != nil {
				return err
			}
			trusted, err := directory.ParseDNWithIdentityKey(value, original.Key())
			if err != nil {
				return err
			}
			want, err := storage.ReaderDNOrderKey(reader, trusted)
			if err != nil {
				return err
			}
			if got := trusted.LegacyKey() + "\x00" + trusted.Key(); got != want {
				t.Fatalf("order for %q = %q, want %q", value, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkPagedSnapshotContinuationState(b *testing.B) {
	source := &pagedSortedSearch{items: make([]pagedSortedItem, 100000), live: true}
	source = clonePagedSortedSearch(source)
	b.ReportAllocs()
	for b.Loop() {
		cloned := clonePagedSortedSearch(source)
		cloned.offset++
		if source.offset != 0 || len(cloned.items) != 100000 {
			b.Fatal("continuation changed the published snapshot")
		}
	}
}

func TestPagedContinuationPreservesLegacyCapacityAccounting(t *testing.T) {
	for _, size := range []int{1, 7, 100, 1000} {
		current := &pagedSortedSearch{items: make([]pagedSortedItem, size, size*2), live: true}
		for index := range current.items {
			current.items[index] = pagedSortedItem{
				dn: "uid=sample,dc=example",
				selected: directory.Entry{DN: "uid=sample,dc=example", Attributes: []directory.Attribute{{
					Description: "description", Values: [][]byte{[]byte("one"), []byte("two")},
				}}},
				hasSelected: index%2 == 0,
			}
		}
		legacy := *current
		current.retainedBytes = pagedSortedSearchRetainedBytes(current)
		for page := 0; page < 4; page++ {
			previous := current
			current = clonePagedSortedSearch(current)
			legacy.items = append([]pagedSortedItem(nil), legacy.items...)
			if cap(current.items) != cap(legacy.items) ||
				pagedSortedSearchRetainedBytes(current) != pagedSortedSearchRetainedBytes(&legacy) {
				t.Fatalf("size %d page %d changed retained capacity", size, page)
			}
			current.offset++
			if previous.offset != page {
				t.Fatal("continuation changed the preceding cursor")
			}
		}
	}
}

func BenchmarkPagedSnapshotMemoryAccounting(b *testing.B) {
	snapshot := &pagedSortedSearch{items: make([]pagedSortedItem, 100000), live: true}
	snapshot.retainedBytes = pagedSortedSearchRetainedBytes(snapshot)
	b.ReportAllocs()
	for b.Loop() {
		if pagedSortedSearchRetainedBytes(snapshot) <= 0 {
			b.Fatal("snapshot was not charged")
		}
	}
}
