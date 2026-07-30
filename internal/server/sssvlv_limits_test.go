package server

import (
	"context"
	"fmt"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientVirtualListViewMaxPerConnection(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	contextIDs := make([][]byte, 0, defaultServerSideSortMaxPerConn)
	for index := 0; index < defaultServerSideSortMaxPerConn; index++ {
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			sortControl,
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset:     true,
				Offset:       int64(index%4 + 1),
				ContentCount: 4,
			}),
		}))
		if err != nil {
			t.Fatalf("VLV context %d Search(): %v", index, err)
		}
		response := decodeVirtualListViewResponse(t, result)
		contextIDs = append(contextIDs, response.ContextID)
	}

	_, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
		}),
	}))
	assertLDAPResultCode(t, err, ldap.LDAPResultBusy)

	continued, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       2,
			ContentCount: 4,
			ContextID:    contextIDs[0],
			HasContextID: true,
		}),
	}))
	if err != nil {
		t.Fatalf("continue existing VLV at max: %v", err)
	}
	assertSortedUIDs(t, continued, []string{"sort-4"})

	rebindVirtualListViewClient(t, client)
	_, err = client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
			ContextID:    contextIDs[0],
			HasContextID: true,
		}),
	}))
	assertLDAPResultCode(
		t,
		err,
		ldap.LDAPResultVirtualListViewErrorOrControlError,
	)

	result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
		}),
	}))
	if err != nil {
		t.Fatalf("VLV after Bind release: %v", err)
	}
	assertSortedUIDs(t, result, []string{"sort-2"})
}

func TestLDAPClientServerSideSortGlobalMaximum(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)
	configureServerSideSortLimits(t, store, 1, 5)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	first := bindPagedRootClient(t, address)
	defer first.Close()
	second := bindPagedRootClient(t, address)
	defer second.Close()

	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	if _, err := first.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
		}),
	})); err != nil {
		t.Fatalf("first VLV Search(): %v", err)
	}

	_, err := second.Search(newSortablePeopleSearch(
		[]ldap.Control{sortControl},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultBusy)

	rebindVirtualListViewClient(t, first)
	result, err := second.Search(newSortablePeopleSearch(
		[]ldap.Control{sortControl},
	))
	if err != nil {
		t.Fatalf("sort after global lease release: %v", err)
	}
	assertSortedUIDs(t, result, []string{
		"sort-2",
		"sort-4",
		"sort-3",
		"sort-1",
	})
}

func TestLDAPClientSortedPagingHoldsServerSideSortLease(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)
	configureServerSideSortLimits(t, store, 1, 5)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	first := bindPagedRootClient(t, address)
	defer first.Close()
	second := bindPagedRootClient(t, address)
	defer second.Close()

	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	paging := ldap.NewControlPaging(1)
	request := newSortablePeopleSearch([]ldap.Control{
		sortControl,
		paging,
	})
	page, err := first.Search(request)
	if err != nil {
		t.Fatalf("first sorted page: %v", err)
	}
	assertSortedUIDs(t, page, []string{"sort-2"})

	_, err = second.Search(newSortablePeopleSearch(
		[]ldap.Control{sortControl},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultBusy)

	cookie := pagedResponseControl(t, page).Cookie
	for len(cookie) != 0 {
		paging.SetCookie(cookie)
		page, err = first.Search(request)
		if err != nil {
			t.Fatalf("continued sorted page: %v", err)
		}
		cookie = pagedResponseControl(t, page).Cookie
	}

	result, err := second.Search(newSortablePeopleSearch(
		[]ldap.Control{sortControl},
	))
	if err != nil {
		t.Fatalf("sort after paging completion: %v", err)
	}
	assertSortedUIDs(t, result, []string{
		"sort-2",
		"sort-4",
		"sort-3",
		"sort-1",
	})
}

func TestServerSideSortLeaseRollsBackCombinedLimiters(t *testing.T) {
	t.Parallel()

	frontend := &serverSideSortLimiter{
		max:        1,
		maxPerConn: 1,
		active:     1,
	}
	target := &serverSideSortLimiter{
		max:        1,
		maxPerConn: 1,
	}
	state := connectionState{runtime: &runtimeState{
		databases: []runtimeDatabase{
			{
				name:           "{-1}frontend",
				serverSideSort: true,
				sortLimiter:    frontend,
			},
			{
				name:           "{1}mdb",
				serverSideSort: true,
				sortLimiter:    target,
			},
		},
	}}

	if lease, ok := acquireServerSideSortLease(&state, 1); ok || lease != nil {
		t.Fatalf("saturated combined lease = %#v, %t", lease, ok)
	}
	if target.active != 0 || len(state.sortSessionCounts) != 0 {
		t.Fatalf(
			"failed combined lease leaked state: target=%d counts=%v",
			target.active,
			state.sortSessionCounts,
		)
	}

	frontend.active = 0
	lease, ok := acquireServerSideSortLease(&state, 1)
	if !ok || lease == nil {
		t.Fatalf("combined lease = %#v, %t", lease, ok)
	}
	if frontend.active != 1 ||
		target.active != 1 ||
		state.sortSessionCounts[frontend] != 1 ||
		state.sortSessionCounts[target] != 1 {
		t.Fatalf(
			"combined lease state: frontend=%d target=%d counts=%v",
			frontend.active,
			target.active,
			state.sortSessionCounts,
		)
	}
	if second, ok := acquireServerSideSortLease(&state, 1); ok || second != nil {
		t.Fatalf("per-connection limit lease = %#v, %t", second, ok)
	}

	releaseServerSideSortLease(&state, lease)
	if frontend.active != 0 ||
		target.active != 0 ||
		len(state.sortSessionCounts) != 0 {
		t.Fatalf(
			"released combined lease state: frontend=%d target=%d counts=%v",
			frontend.active,
			target.active,
			state.sortSessionCounts,
		)
	}
}

func configureServerSideSortLimits(
	t *testing.T,
	store storage.Store,
	maximum,
	maxPerConnection int,
) {
	t.Helper()

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(
			"olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"olcSssVlvMax",
			stringValues(fmt.Sprintf("%d", maximum)),
		)
		entry.ReplaceValues(
			"olcSssVlvMaxPerConn",
			stringValues(fmt.Sprintf("%d", maxPerConnection)),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure sssvlv limits: %v", err)
	}
}
