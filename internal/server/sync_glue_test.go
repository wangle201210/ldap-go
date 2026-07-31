package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestEffectiveSyncProviderDatabaseFollowsGlueHierarchy(t *testing.T) {
	t.Parallel()

	mustDN := func(raw string) directory.DN {
		t.Helper()
		dn, err := directory.ParseDN(raw)
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", raw, err)
		}
		return dn
	}
	databases := []runtimeDatabase{
		{
			name:         "root",
			partition:    "root",
			suffixes:     []directory.DN{mustDN("dc=example,dc=com")},
			syncProvider: true,
		},
		{
			name:         "people",
			partition:    "people",
			suffixes:     []directory.DN{mustDN("ou=people,dc=example,dc=com")},
			subordinate:  true,
			syncProvider: true,
		},
		{
			name:        "teams",
			partition:   "teams",
			suffixes:    []directory.DN{mustDN("ou=teams,ou=people,dc=example,dc=com")},
			subordinate: true,
		},
		{
			name:        "devices",
			partition:   "devices",
			suffixes:    []directory.DN{mustDN("ou=devices,dc=example,dc=com")},
			subordinate: true,
		},
		{
			name:      "external",
			partition: "external",
			suffixes:  []directory.DN{mustDN("ou=external,dc=example,dc=com")},
		},
		{
			name:        "managed",
			partition:   "managed",
			suffixes:    []directory.DN{mustDN("ou=managed,ou=external,dc=example,dc=com")},
			subordinate: true,
		},
	}

	tests := []struct {
		name  string
		index int
		want  int
	}{
		{name: "root provider", index: 0, want: 0},
		{name: "branch provider", index: 1, want: 1},
		{name: "nested branch uses nearest provider", index: 2, want: 1},
		{name: "sibling branch uses root provider", index: 3, want: 0},
		{name: "independent database does not inherit outer provider", index: 4, want: -1},
		{name: "independent subordinate stays isolated", index: 5, want: -1},
		{name: "invalid database", index: -1, want: -1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if got := effectiveSyncProviderDatabaseIndex(
				databases,
				test.index,
			); got != test.want {
				t.Fatalf(
					"effectiveSyncProviderDatabaseIndex(%d) = %d, want %d",
					test.index,
					got,
					test.want,
				)
			}
		})
	}

	databases[1].syncProvider = false
	if got := effectiveSyncProviderDatabaseIndex(databases, 2); got != 0 {
		t.Fatalf("nested branch fallback provider = %d, want 0", got)
	}
	databases[4].syncProvider = true
	if got := effectiveSyncProviderDatabaseIndex(databases, 5); got != 4 {
		t.Fatalf("independent branch provider = %d, want 4", got)
	}
}

func TestSyncProviderCoversGluedSubordinates(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlueSyncProvider(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	contextCSN := func(base string) string {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(
			base,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"contextCSN"},
			nil,
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("Search(%q, contextCSN) = %#v, %v", base, result, err)
		}
		return result.Entries[0].GetAttributeValue("contextCSN")
	}
	initialContextCSN := contextCSN("dc=example,dc=com")
	if initialContextCSN == "" {
		t.Fatal("root sync provider has no contextCSN")
	}
	if got := contextCSN("ou=people,dc=example,dc=com"); got != "" {
		t.Fatalf("inherited subordinate exposed contextCSN %q", got)
	}

	refreshConnection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer refreshConnection.Close()
	initial := requestRawSyncRefresh(
		t,
		refreshConnection,
		2,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)
	wantRootDNs := []string{
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
		"cn=operators,ou=groups,dc=example,dc=com",
		"cn=router,ou=devices,dc=example,dc=com",
		"dc=example,dc=com",
		"ou=devices,dc=example,dc=com",
		"ou=groups,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"ou=teams,ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	}
	assertRawSyncRefreshDNs(t, initial, wantRootDNs)
	if initial.resultCode != int64(ldapwire.ResultSuccess) ||
		initial.done == nil ||
		!initial.done.HasCookie {
		t.Fatalf("initial glued Sync refresh = %#v", initial)
	}
	coreUUID := rawSyncUUIDForDN(
		t,
		initial,
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
	)

	people := requestRawSyncRefresh(
		t,
		refreshConnection,
		3,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)
	assertRawSyncRefreshDNs(t, people, []string{
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"ou=teams,ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
	})

	external := requestRawSyncRefresh(
		t,
		refreshConnection,
		4,
		rawSyncSearchRequestFor(
			t,
			"ou=external,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		ldapwire.SyncRequestValue{Mode: ldapwire.SyncRefreshOnly},
	)
	if external.resultCode !=
		int64(ldapwire.ResultUnavailableCriticalExtension) {
		t.Fatalf("independent database Sync result = %#v", external)
	}

	persistentConnection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer persistentConnection.Close()
	writeRawLDAPRequest(
		t,
		persistentConnection,
		2,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)
	persistentEntries := 0
	for {
		message := readRawSyncMessage(t, persistentConnection, 2)
		if message.entry != nil {
			persistentEntries++
			continue
		}
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoRefreshPresent &&
			message.info.RefreshDone {
			break
		}
		t.Fatalf("unexpected glued persistent refresh response = %#v", message)
	}
	if persistentEntries != len(wantRootDNs) {
		t.Fatalf(
			"glued persistent refresh entries = %d, want %d",
			persistentEntries,
			len(wantRootDNs),
		)
	}

	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Glue Sync"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(alice): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(core): %v", err)
	}

	modified := readRawSyncEntryState(t, persistentConnection, 2)
	if modified.dn != "uid=alice,ou=people,dc=example,dc=com" ||
		modified.state.State != ldapwire.SyncStateModify ||
		!modified.state.HasCookie {
		t.Fatalf("persistent subordinate modify = %#v", modified)
	}
	deleted := readRawSyncEntryState(t, persistentConnection, 2)
	if deleted.dn !=
		"cn=core,ou=teams,ou=people,dc=example,dc=com" ||
		deleted.state.State != ldapwire.SyncStateDelete ||
		deleted.state.EntryUUID != coreUUID ||
		!deleted.state.HasCookie {
		t.Fatalf("persistent nested subordinate delete = %#v", deleted)
	}

	incremental := requestRawSyncRefresh(
		t,
		refreshConnection,
		5,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    bytes.Clone(initial.done.Cookie),
			HasCookie: true,
		},
	)
	assertRawSyncRefreshDNs(t, incremental, []string{
		"uid=alice,ou=people,dc=example,dc=com",
	})
	deletedUUIDs := rawSyncDeletedUUIDs(incremental)
	if incremental.resultCode != int64(ldapwire.ResultSuccess) ||
		incremental.done == nil ||
		!incremental.done.RefreshDeletes ||
		len(deletedUUIDs) != 1 ||
		deletedUUIDs[0] != coreUUID {
		t.Fatalf("glued session-log refresh = %#v", incremental)
	}

	currentContextCSN := contextCSN("dc=example,dc=com")
	if currentContextCSN == "" || currentContextCSN == initialContextCSN {
		t.Fatalf(
			"root contextCSN after subordinate writes = %q, initial %q",
			currentContextCSN,
			initialContextCSN,
		)
	}
	assertGlueSyncMetadata(t, store, currentContextCSN)
}

func TestSyncSortAndVLVSpanGluePartitions(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlueSyncProvider(t, store)
	enableGlueServerSideSort(t, store)

	address, stop := startServer(t, store, Config{})
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
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(cn=*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
		rawSyncSortControl(),
		rawSyncVLVControl(ldapwire.VirtualListViewRequest{
			AfterCount:   1,
			ByOffset:     true,
			Offset:       2,
			ContentCount: 4,
		}),
	)
	refresh := readRawSyncRefresh(t, connection, 2)
	assertRawSyncDNs(t, refresh.entries, []string{
		"cn=core,ou=teams,ou=people,dc=example,dc=com",
		"cn=operators,ou=groups,dc=example,dc=com",
	})
	assertRawSyncEntryControls(t, refresh.entries)
	assertSuccessfulSyncSortControls(t, refresh.doneControls)
	response := decodeRawSyncVLVResponse(t, refresh.doneControls)
	if response.TargetPosition != 2 ||
		response.ContentCount != 4 ||
		!response.HasContextID {
		t.Fatalf("glued Sync VLV response = %#v", response)
	}
}

func seedGlueSyncProvider(t *testing.T, store storage.Store) {
	t.Helper()
	seedGlueConfiguration(t, store)

	type partitionedEntry struct {
		partition string
		entry     directory.Entry
	}
	partitions := []string{
		configuredDatabasePartition("{1}mdb"),
		configuredDatabasePartition("{2}mdb"),
		configuredDatabasePartition("{3}mdb"),
		configuredDatabasePartition("{4}mdb"),
	}
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		var entries []partitionedEntry
		for _, partition := range partitions {
			tx := storage.WriterInPartition(writer, partition)
			if err := tx.ForEach(func(entry directory.Entry) error {
				entries = append(entries, partitionedEntry{
					partition: partition,
					entry:     entry,
				})
				return nil
			}); err != nil {
				return err
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].entry.DN < entries[j].entry.DN
		})
		var contextCSN string
		for index := range entries {
			contextCSN = fmt.Sprintf(
				"20260730020202.%06dZ#000000#000#000000",
				index+1,
			)
			entries[index].entry.ReplaceValues(
				"entryUUID",
				stringValues(fmt.Sprintf(
					"10000000-0000-4000-8000-%012x",
					index+1,
				)),
			)
			entries[index].entry.ReplaceValues(
				"entryCSN",
				stringValues(contextCSN),
			)
		}
		for index := range entries {
			if entries[index].entry.DN == "dc=example,dc=com" {
				entries[index].entry.ReplaceValues(
					"contextCSN",
					stringValues(contextCSN),
				)
			}
			if err := writer.PutIn(
				entries[index].partition,
				entries[index].entry,
				true,
			); err != nil {
				return err
			}
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcOverlay",
					Values:      stringValues("{0}syncprov"),
				},
				{
					Description: "olcSpSessionlog",
					Values:      stringValues("10"),
				},
			},
		}, false)
	})
	if err != nil {
		t.Fatalf("seed glue Sync provider: %v", err)
	}
}

func enableGlueServerSideSort(t *testing.T, store storage.Store) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcOverlay",
				Values:      stringValues("{1}sssvlv"),
			}},
		}, false)
	})
	if err != nil {
		t.Fatalf("enable glue server-side sort: %v", err)
	}
}

func assertRawSyncRefreshDNs(
	t *testing.T,
	refresh rawSyncRefresh,
	want []string,
) {
	t.Helper()
	got := make([]string, len(refresh.entries))
	for index := range refresh.entries {
		got[index] = refresh.entries[index].dn
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("Sync DNs = %v, want %v", got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("Sync DNs = %v, want %v", got, want)
		}
	}
}

func assertGlueSyncMetadata(
	t *testing.T,
	store storage.Store,
	wantContextCSN string,
) {
	t.Helper()
	err := store.View(context.Background(), func(reader storage.Reader) error {
		rootPartition := configuredDatabasePartition("{1}mdb")
		rawContextCSN, err := reader.Metadata(
			syncContextCSNMetadataKey(rootPartition),
		)
		if err != nil {
			return err
		}
		if string(rawContextCSN) != wantContextCSN {
			return fmt.Errorf(
				"root sync metadata = %q, want %q",
				rawContextCSN,
				wantContextCSN,
			)
		}
		for _, name := range []string{"{2}mdb", "{3}mdb"} {
			_, err := reader.Metadata(syncContextCSNMetadataKey(
				configuredDatabasePartition(name),
			))
			if !errors.Is(err, storage.ErrMetadataNotFound) {
				return fmt.Errorf(
					"subordinate %s sync metadata error = %v, want not found",
					name,
					err,
				)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify glue Sync metadata: %v", err)
	}
}
