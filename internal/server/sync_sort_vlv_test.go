package server

import (
	"context"
	"fmt"
	"slices"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncRefreshOnlyWithServerSideSort(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncSortDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(uid=sort-*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
		rawSyncSortControl(),
	)
	refresh := readRawSyncRefresh(t, connection, 2)
	assertRawSyncDNs(t, refresh.entries, []string{
		"uid=sort-2,ou=people,dc=example,dc=com",
		"uid=sort-4,ou=people,dc=example,dc=com",
		"uid=sort-3,ou=people,dc=example,dc=com",
		"uid=sort-1,ou=people,dc=example,dc=com",
	})
	assertRawSyncEntryControls(t, refresh.entries)
	assertSuccessfulSyncSortControls(t, refresh.doneControls)
}

func TestSyncRefreshOnlyWithVirtualListViewContinuation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncSortDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	search := rawSyncSearchRequestFor(
		t,
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		"(uid=sort-*)",
	)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		search,
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
		rawSyncSortControl(),
		rawSyncVLVControl(ldapwire.VirtualListViewRequest{
			AfterCount:   1,
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
		}),
	)
	first := readRawSyncRefresh(t, connection, 2)
	assertRawSyncDNs(t, first.entries, []string{
		"uid=sort-2,ou=people,dc=example,dc=com",
		"uid=sort-4,ou=people,dc=example,dc=com",
	})
	assertRawSyncEntryControls(t, first.entries)
	assertSuccessfulSyncSortControls(t, first.doneControls)
	firstVLV := decodeRawSyncVLVResponse(t, first.doneControls)
	if firstVLV.TargetPosition != 1 ||
		firstVLV.ContentCount != 4 ||
		!firstVLV.HasContextID {
		t.Fatalf("first Sync VLV response = %#v", firstVLV)
	}

	writeRawLDAPRequest(
		t,
		connection,
		3,
		search,
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
		rawSyncSortControl(),
		rawSyncVLVControl(ldapwire.VirtualListViewRequest{
			AfterCount:   1,
			ByOffset:     true,
			Offset:       3,
			ContentCount: 4,
			ContextID:    firstVLV.ContextID,
			HasContextID: true,
		}),
	)
	second := readRawSyncRefresh(t, connection, 3)
	assertRawSyncDNs(t, second.entries, []string{
		"uid=sort-3,ou=people,dc=example,dc=com",
		"uid=sort-1,ou=people,dc=example,dc=com",
	})
	assertRawSyncEntryControls(t, second.entries)
	assertSuccessfulSyncSortControls(t, second.doneControls)
	secondVLV := decodeRawSyncVLVResponse(t, second.doneControls)
	if secondVLV.TargetPosition != 3 ||
		secondVLV.ContentCount != 4 ||
		!slices.Equal(secondVLV.ContextID, firstVLV.ContextID) {
		t.Fatalf("continued Sync VLV response = %#v", secondVLV)
	}
}

func TestPersistentSyncSortResultsUseRefreshDoneControls(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncSortDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(uid=sort-*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
		rawSyncSortControl(),
	)

	var entries []rawSyncEntry
	for {
		message := readRawSyncMessage(t, connection, 2)
		switch {
		case message.entry != nil:
			entries = append(entries, *message.entry)
		case message.info != nil &&
			(message.info.Kind == ldapwire.SyncInfoRefreshPresent ||
				message.info.Kind == ldapwire.SyncInfoRefreshDelete) &&
			message.info.RefreshDone:
			assertRawSyncDNs(t, entries, []string{
				"uid=sort-2,ou=people,dc=example,dc=com",
				"uid=sort-4,ou=people,dc=example,dc=com",
				"uid=sort-3,ou=people,dc=example,dc=com",
				"uid=sort-1,ou=people,dc=example,dc=com",
			})
			assertRawSyncEntryControls(t, entries)
			assertSuccessfulSortControl(t, message.controls)
			if _, exists := message.controls[syncDoneControlOID]; exists {
				t.Fatal("persistent refreshDone carried a SyncDone control")
			}
			return
		default:
			t.Fatalf("unexpected persistent sorted Sync response = %#v", message)
		}
	}
}

func TestPersistentSyncVLVResultsUseRefreshDoneControls(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncSortDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(uid=sort-*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
		rawSyncSortControl(),
		rawSyncVLVControl(ldapwire.VirtualListViewRequest{
			AfterCount:   1,
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
		}),
	)

	var entries []rawSyncEntry
	for {
		message := readRawSyncMessage(t, connection, 2)
		switch {
		case message.entry != nil:
			entries = append(entries, *message.entry)
		case message.info != nil &&
			(message.info.Kind == ldapwire.SyncInfoRefreshPresent ||
				message.info.Kind == ldapwire.SyncInfoRefreshDelete) &&
			message.info.RefreshDone:
			assertRawSyncDNs(t, entries, []string{
				"uid=sort-2,ou=people,dc=example,dc=com",
				"uid=sort-4,ou=people,dc=example,dc=com",
			})
			assertRawSyncEntryControls(t, entries)
			assertSuccessfulSortControl(t, message.controls)
			response := decodeRawSyncVLVResponse(t, message.controls)
			if response.TargetPosition != 1 ||
				response.ContentCount != 4 ||
				!response.HasContextID {
				t.Fatalf("persistent Sync VLV response = %#v", response)
			}
			return
		default:
			t.Fatalf("unexpected persistent VLV Sync response = %#v", message)
		}
	}
}

func rawSyncSortControl() *ber.Packet {
	return encodeRawLDAPControl(ldapwire.Control{
		OID:      sortRequestControlOID,
		Critical: true,
		Value: ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
			AttributeType: "cn",
			OrderingRule:  "caseIgnoreOrderingMatch",
		}}),
		HasValue: true,
	})
}

func rawSyncVLVControl(request ldapwire.VirtualListViewRequest) *ber.Packet {
	return encodeRawLDAPControl(ldapwire.Control{
		OID:      vlvRequestControlOID,
		Critical: true,
		Value:    ldapwire.EncodeVirtualListViewRequestValue(request),
		HasValue: true,
	})
}

func assertRawSyncDNs(
	t *testing.T,
	entries []rawSyncEntry,
	want []string,
) {
	t.Helper()
	got := make([]string, len(entries))
	for index, entry := range entries {
		got[index] = entry.dn
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Sync entry DNs = %q, want %q", got, want)
	}
}

func assertRawSyncEntryControls(t *testing.T, entries []rawSyncEntry) {
	t.Helper()
	for _, entry := range entries {
		if entry.state.State != ldapwire.SyncStateAdd {
			t.Fatalf("Sync entry state = %#v", entry)
		}
		if _, exists := entry.controls[syncStateControlOID]; !exists {
			t.Fatalf("SyncState control missing from %s", entry.dn)
		}
		if _, exists := entry.controls[syncDoneControlOID]; exists {
			t.Fatalf("SyncDone control was attached to entry %s", entry.dn)
		}
	}
}

func assertSuccessfulSyncSortControls(
	t *testing.T,
	controls map[string][]byte,
) {
	t.Helper()
	if _, exists := controls[syncDoneControlOID]; !exists {
		t.Fatal("SyncDone response control is missing")
	}
	assertSuccessfulSortControl(t, controls)
}

func assertSuccessfulSortControl(
	t *testing.T,
	controls map[string][]byte,
) {
	t.Helper()
	value, exists := controls[sortResponseControlOID]
	if !exists {
		t.Fatal("server-side sort response control is missing")
	}
	result, attribute, err := ldapwire.DecodeSortResultValue(value)
	if err != nil ||
		result != ldapwire.ResultSuccess ||
		attribute != "" {
		t.Fatalf(
			"sort response = result %d attribute %q error %v",
			result,
			attribute,
			err,
		)
	}
}

func decodeRawSyncVLVResponse(
	t *testing.T,
	controls map[string][]byte,
) ldapwire.VirtualListViewResponse {
	t.Helper()
	value, exists := controls[vlvResponseControlOID]
	if !exists {
		t.Fatal("VLV response control is missing")
	}
	response, err := ldapwire.DecodeVirtualListViewResponseValue(value)
	if err != nil {
		t.Fatalf("decode VLV response: %v", err)
	}
	if response.Result != ldapwire.ResultSuccess {
		t.Fatalf("VLV response = %#v", response)
	}
	return response
}

func seedSyncSortDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	seedSyncProviderDirectory(t, store)
	seedSortablePeople(t, store)

	sortDNs := []string{
		"uid=sort-1,ou=people,dc=example,dc=com",
		"uid=sort-2,ou=people,dc=example,dc=com",
		"uid=sort-3,ou=people,dc=example,dc=com",
		"uid=sort-4,ou=people,dc=example,dc=com",
	}
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		oldOverlayDN, err := directory.ParseDN(
			"olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		overlay, err := writer.Get(oldOverlayDN)
		if err != nil {
			return err
		}
		if err := writer.Delete(oldOverlayDN); err != nil {
			return err
		}
		overlay.DN = "olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config"
		overlay.ReplaceValues("olcOverlay", stringValues("{1}sssvlv"))
		if err := writer.Put(overlay, false); err != nil {
			return err
		}

		var contextCSN string
		for index, rawDN := range sortDNs {
			dn, err := directory.ParseDN(rawDN)
			if err != nil {
				return err
			}
			entry, err := writer.Get(dn)
			if err != nil {
				return err
			}
			contextCSN = fmt.Sprintf(
				"20260730010102.%06dZ#000000#000#000000",
				index+1,
			)
			entry.ReplaceValues(
				"entryUUID",
				stringValues(fmt.Sprintf(
					"10000000-0000-4000-8000-%012x",
					index+1,
				)),
			)
			entry.ReplaceValues("entryCSN", stringValues(contextCSN))
			if err := writer.Put(entry, true); err != nil {
				return err
			}
		}
		suffixDN, err := directory.ParseDN("dc=example,dc=com")
		if err != nil {
			return err
		}
		suffix, err := writer.Get(suffixDN)
		if err != nil {
			return err
		}
		suffix.ReplaceValues("contextCSN", stringValues(contextCSN))
		return writer.Put(suffix, true)
	})
	if err != nil {
		t.Fatalf("seed Sync sort directory: %v", err)
	}
}
