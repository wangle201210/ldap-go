package server

import (
	"fmt"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPagedSnapshotBuilderPreservesItems(t *testing.T) {
	for _, count := range []int{0, 1, 50, 4095, 4096, 5000, 10001, 100000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var builder pagedSnapshotBuilder
			var want []pagedSortedItem
			for index := range count {
				item := pagedSortedItem{route: index % 3, dn: fmt.Sprintf("uid=user%d,dc=example", index)}
				builder.append(item)
				want = append(want, item)
				if index%2 == 0 {
					builder.last().selected = directory.Entry{DN: item.dn}
					builder.last().hasSelected = true
					want[index].selected, want[index].hasSelected = builder.last().selected, true
				}
			}
			got := builder.finish()
			if !reflect.DeepEqual(got, want) || cap(got) > cap(want) {
				t.Fatal("builder changed items or increased retained capacity")
			}
			if count < pagedSnapshotChunkSize && cap(got) != cap(want) {
				t.Fatal("small snapshot changed capacity")
			}
			builder.append(pagedSortedItem{dn: "cn=next"})
			if !reflect.DeepEqual(got, want) || builder.count != 1 {
				t.Fatal("reusing builder changed its published snapshot")
			}
		})
	}
}

func TestPagedSnapshotDoesNotCacheTruncatedResults(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	seedDirectory(t, store)
	seedPagedPeople(t, store, 8)
	address, stop := startServer(t, store, Config{
		RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret"), MaxSearchEntries: 5,
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()
	for attempt := range 2 {
		result, err := client.SearchWithPaging(newPagedPeopleSearch(0, nil), 2)
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			t.Fatalf("attempt %d masked truncation: result=%#v, err=%v", attempt, result, err)
		}
	}
}

func TestPagedSnapshotDoesNotCacheFailedResults(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	seedDirectory(t, store)
	seedPagedPeople(t, store, 8)
	address, stop := startServer(t, store, Config{
		RootDN: "cn=admin,dc=example,dc=com", RootPassword: []byte("admin-secret"), MaxSearchCandidateBytes: 1000,
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()
	for attempt := range 2 {
		result, err := client.SearchWithPaging(newPagedPeopleSearch(0, nil), 2)
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultAdminLimitExceeded) {
			t.Fatalf("attempt %d masked memory failure: result=%#v, err=%v", attempt, result, err)
		}
	}
}

func BenchmarkPagedSnapshotBuild(b *testing.B) {
	for _, count := range []int{50, 5000, 100000} {
		for _, chunked := range []bool{false, true} {
			b.Run(fmt.Sprintf("entries=%d/chunked=%t", count, chunked), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var items []pagedSortedItem
					if chunked {
						var builder pagedSnapshotBuilder
						for index := range count {
							builder.append(pagedSortedItem{route: index})
						}
						items = builder.finish()
					} else {
						for index := range count {
							items = append(items, pagedSortedItem{route: index})
						}
					}
					if len(items) != count {
						b.Fatal("lost snapshot entries")
					}
				}
			})
		}
	}
}
