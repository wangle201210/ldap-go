package server

import (
	"context"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDatabaseMonitoringStartup(t *testing.T) {
	for _, backend := range []string{"frontend", "config", "mdb", "monitor", "null", "ldap", "meta", "relay", "ldif"} {
		for _, value := range []string{"", "TRUE", "FALSE"} {
			t.Run(backend+"/"+value, func(t *testing.T) {
				entry := directory.Entry{DN: "olcDatabase={1}" + backend + ",cn=config"}
				if value != "" {
					entry.ReplaceValues("olcMonitoring", stringValues(value))
				}
				database := runtimeDatabase{name: "{1}" + backend}
				if err := loadDatabaseMonitoring(entry, &database); err != nil {
					t.Fatal(err)
				}
				want := value == "TRUE" || value == "" && backend == "mdb"
				if database.monitoring != want || database.monitoringConfigured != (value != "") {
					t.Fatalf("monitoring = %t, configured = %t; want %t, %t", database.monitoring, database.monitoringConfigured, want, value != "")
				}
			})
		}
	}
}

func TestDatabaseMonitoringValidation(t *testing.T) {
	for _, values := range [][]string{{"MAYBE"}, {"TRUE", "FALSE"}, {"false"}, {" TRUE"}, {""}} {
		t.Run(strings.Join(values, ","), func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			setMonitoringValues(t, store, "olcDatabase={1}mdb,cn=config", values...)
			if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err == nil || !strings.Contains(err.Error(), "olcMonitoring") {
				t.Fatalf("ValidateConfiguration: %v", err)
			}
			if instance, err := New(Config{Store: store}); err == nil {
				instance.closeSQLBackends()
				t.Fatal("New accepted invalid olcMonitoring")
			}
		})
	}
}

func TestDatabaseMonitoringOnlineRollbackAndRestart(t *testing.T) {
	for _, initial := range []string{"", "TRUE", "FALSE"} {
		t.Run(initial, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			seedMonitorConfiguration(t, store)
			if initial != "" {
				setMonitoringValues(t, store, "olcDatabase={1}mdb,cn=config", initial)
			}
			instance, address, stop := startConfigurationCapabilityServer(t, store)
			stopped := false
			t.Cleanup(func() {
				if !stopped {
					stop()
				}
			})
			client := bindConstraintClient(t, address, "cn=config", "config-secret")
			defer client.Close()
			registered := initial != "FALSE"
			check := func(enabled bool) {
				t.Helper()
				database := databaseForDN(instance.runtime.Load(), staticRuntimeDN("dc=example,dc=com"))
				if database.monitoring != enabled || database.monitoringRegistered != registered {
					t.Fatalf("monitoring=%t registered=%t; want %t, %t", database.monitoring, database.monitoringRegistered, enabled, registered)
				}
				entry := monitorSearch(t, client, "cn=Database 1,cn=Databases,cn=Monitor", ldap.ScopeBaseObject, "(objectClass=*)", []string{"objectClass", "olmMDBEntries", "namingContexts"}).Entries[0]
				if entry.GetAttributeValue("namingContexts") != "dc=example,dc=com" || (entry.GetAttributeValue("olmMDBEntries") != "") != registered {
					t.Fatalf("unexpected monitor entry: %#v", entry)
				}
			}
			check(initial != "FALSE")
			empty := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
			empty.Replace("olcMonitoring", nil)
			if err := client.Modify(empty); err != nil {
				t.Fatal(err)
			}
			check(false)
			for _, value := range []string{"FALSE", "TRUE"} {
				request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
				request.Replace("olcMonitoring", []string{value})
				if err := client.Modify(request); err != nil {
					t.Fatal(err)
				}
				check(value == "TRUE")
			}
			for _, test := range []struct {
				values   []string
				code     uint16
				rollback bool
			}{
				{[]string{"MAYBE"}, ldap.LDAPResultInvalidAttributeSyntax, false},
				{[]string{"FALSE", "TRUE"}, ldap.LDAPResultConstraintViolation, false},
				{[]string{"FALSE"}, ldap.LDAPResultConstraintViolation, true},
			} {
				active := instance.runtime.Load()
				before := readStoredEntry(t, store, "olcDatabase={1}mdb,cn=config")
				request := ldap.NewModifyRequest(before.DN, nil)
				request.Replace("olcMonitoring", test.values)
				if test.rollback {
					request.Replace("olcDbNoSync", []string{"TRUE"})
				}
				assertLDAPResultCode(t, client.Modify(request), test.code)
				if instance.runtime.Load() != active || !reflect.DeepEqual(before, readStoredEntry(t, store, before.DN)) {
					t.Fatal("failed update changed the active runtime or stored entry")
				}
				check(true)
			}
			remove := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
			remove.Delete("olcMonitoring", nil)
			if err := client.Modify(remove); err != nil {
				t.Fatal(err)
			}
			check(false)
			unrelated := ldap.NewModifyRequest("cn=config", nil)
			unrelated.Replace("olcLogLevel", []string{"0"})
			if err := client.Modify(unrelated); err != nil {
				t.Fatal(err)
			}
			check(false)
			if values := readStoredEntry(t, store, remove.DN).Values("olcMonitoring"); len(values) != 0 {
				t.Fatalf("deleted monitoring persisted as %q", values)
			}
			client.Close()
			stop()
			stopped = true
			restarted, _, restartStop := startConfigurationCapabilityServer(t, store)
			defer restartStop()
			database := databaseForDN(restarted.runtime.Load(), staticRuntimeDN("dc=example,dc=com"))
			if !database.monitoring || !database.monitoringRegistered {
				t.Fatal("restart did not restore the MDB default after attribute deletion")
			}
		})
	}
}

func TestDatabaseMonitoringWithoutMonitor(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	database := databaseForDN(instance.runtime.Load(), staticRuntimeDN("dc=example,dc=com"))
	if !database.monitoring || database.monitoringRegistered {
		t.Fatal("monitoring flag must not create a monitor database")
	}
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	for _, disabled := range []string{"TRUE", "FALSE"} {
		request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
		request.Replace("olcDisabled", []string{disabled})
		if err := client.Modify(request); err != nil {
			t.Fatal(err)
		}
		for _, database := range instance.runtime.Load().databases {
			if database.monitoringRegistered {
				t.Fatal("reopening registered monitoring without a monitor database")
			}
		}
	}
	root := monitorSearch(t, client, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"monitorContext"})
	if len(root.Entries[0].GetAttributeValues("monitorContext")) != 0 {
		t.Fatal("unexpected monitorContext")
	}
	_, err := client.Search(ldap.NewSearchRequest("cn=Monitor", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func TestDatabaseMonitoringEntryCounts(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			var store storage.Store
			if backend == "bolt" {
				var err error
				store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				store = storage.NewMemory()
			}
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			seedMonitorConfiguration(t, store)
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if err := writer.Put(directory.Entry{
					DN: "olcDatabase={3}mdb,cn=config",
					Attributes: []directory.Attribute{
						{Description: "olcDatabase", Values: stringValues("{3}mdb")},
						{Description: "olcSuffix", Values: stringValues("dc=other")},
					},
				}, false); err != nil {
					return err
				}
				return writer.Put(directory.Entry{DN: "dc=other", Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("domain")},
					{Description: "dc", Values: stringValues("other")},
				}}, false)
			}); err != nil {
				t.Fatal(err)
			}
			instance, address, stop := startConfigurationCapabilityServer(t, store)
			defer stop()
			client := bindConstraintClient(t, address, "cn=config", "config-secret")
			defer client.Close()
			const monitoredDN = "cn=Database 1,cn=Databases,cn=Monitor"
			for dn, count := range map[string]string{monitoredDN: "4", "cn=Database 3,cn=Databases,cn=Monitor": "1"} {
				entry := monitorSearch(t, client, dn, ldap.ScopeBaseObject, "(olmMDBEntries="+count+")", []string{"+"})
				if len(entry.Entries) != 1 || entry.Entries[0].GetAttributeValue("olmMDBEntries") != count {
					t.Fatalf("%s: count does not match %s", dn, count)
				}
			}
			entry := monitorSearch(t, client, monitoredDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"*"}).Entries[0]
			if entry.GetAttributeValue("olmMDBEntries") != "" {
				t.Fatal("operational count leaked into user attributes")
			}
			database := databaseForDN(instance.runtime.Load(), staticRuntimeDN("dc=example,dc=com"))
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				return writer.DeleteIn(database.partition, staticRuntimeDN("ou=archive,dc=example,dc=com"))
			}); err != nil {
				t.Fatal(err)
			}
			matched, err := client.Compare(monitoredDN, "olmMDBEntries", "3")
			if err != nil || !matched {
				t.Fatalf("live count after deletion: %t, %v", matched, err)
			}
		})
	}
}

func TestDatabaseMonitoringCountTracksLDAPTransactions(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedMonitorConfiguration(t, store)
	setDatabaseRootCredentials(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	monitorClient := bindConstraintClient(t, address, "cn=admin,cn=Monitor", "monitor-secret")
	defer monitorClient.Close()
	assertMonitoredMDBCount(t, monitorClient, 4)

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"data-secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("monitor-count")
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(entry),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldap.LDAPResultSuccess))
	assertMonitoredMDBCount(t, monitorClient, 4)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, true, identifier),
		int64(ldap.LDAPResultSuccess),
	)
	assertMonitoredMDBCount(t, monitorClient, 5)

	identifier = startRawLDAPTransaction(t, connection, 5)
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		6,
		rawDeleteRequest(entry.DN),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldap.LDAPResultSuccess))
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 7, false, identifier),
		int64(ldap.LDAPResultSuccess),
	)
	assertMonitoredMDBCount(t, monitorClient, 5)
}

func TestDatabaseMonitoringCountTracksSyncrepl(t *testing.T) {
	instance, store, config := newSyncConsumerUnitServer(t)
	identifier := "11111111-2222-3333-4444-555555555555"
	assertStoragePartitionCount(t, store, config.partition, 0)
	apply := func(state ldap.ControlSyncStateState, dn, cn, csn string) {
		t.Helper()
		entry := ldap.NewEntry(dn, map[string][]string{
			"objectClass": {"inetOrgPerson"},
			"uid":         {strings.TrimPrefix(strings.SplitN(dn, ",", 2)[0], "uid=")},
			"cn":          {cn},
			"sn":          {"Example"},
			"entryCSN":    {csn},
		})
		if err := instance.applySyncConsumerEntry(
			context.Background(),
			config,
			entry,
			&ldap.ControlSyncState{
				State:     state,
				EntryUUID: uuid.MustParse(identifier),
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	apply(
		ldap.SyncStateAdd,
		"uid=alice,dc=example,dc=com",
		"Alice",
		"20260730010101.000001Z#000000#001#000000",
	)
	assertStoragePartitionCount(t, store, config.partition, 1)
	apply(
		ldap.SyncStateModify,
		"uid=renamed,dc=example,dc=com",
		"Renamed",
		"20260730010102.000001Z#000000#001#000000",
	)
	assertStoragePartitionCount(t, store, config.partition, 1)
	if err := instance.applySyncConsumerEntry(
		context.Background(),
		config,
		ldap.NewEntry("uid=renamed,dc=example,dc=com", nil),
		&ldap.ControlSyncState{
			State:     ldap.SyncStateDelete,
			EntryUUID: uuid.MustParse(identifier),
		},
	); err != nil {
		t.Fatal(err)
	}
	assertStoragePartitionCount(t, store, config.partition, 0)
}

func setDatabaseRootCredentials(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(staticRuntimeDN("olcDatabase={1}mdb,cn=config"))
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRootDN", stringValues("cn=admin,dc=example,dc=com"))
		entry.ReplaceValues("olcRootPW", stringValues("data-secret"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
}

func assertMonitoredMDBCount(t *testing.T, client *ldap.Conn, want int) {
	t.Helper()
	entry := monitorSearch(
		t,
		client,
		"cn=Database 1,cn=Databases,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"olmMDBEntries"},
	).Entries[0]
	got, err := strconv.Atoi(entry.GetAttributeValue("olmMDBEntries"))
	if err != nil || got != want {
		t.Fatalf("olmMDBEntries = %q, %v; want %d", entry.GetAttributeValue("olmMDBEntries"), err, want)
	}
}

func assertStoragePartitionCount(
	t *testing.T,
	store storage.Store,
	partition string,
	want uint64,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		got, err := storage.PartitionEntryCount(reader, partition)
		if err != nil || got != want {
			t.Fatalf("PartitionEntryCount(%q) = %d, %v; want %d", partition, got, err, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseMonitoringBoundedReads(t *testing.T) {
	const databaseDN = "cn=Database 1,cn=Databases,cn=Monitor"
	start := func(t *testing.T, access ...string) (*monitorReadProbeStore, *ldap.Conn) {
		t.Helper()
		store := &monitorReadProbeStore{Store: storage.NewMemory()}
		t.Cleanup(func() { _ = store.Close() })
		seedOnlineConfiguration(t, store)
		seedMonitorConfiguration(t, store)
		if len(access) != 0 {
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				entry, err := writer.Get(staticRuntimeDN("olcDatabase={2}monitor,cn=config"))
				if err != nil {
					return err
				}
				entry.ReplaceValues("olcAccess", stringValues(access...))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatal(err)
			}
		}
		address, stop := startServer(t, store, Config{})
		t.Cleanup(stop)
		client, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		if err := client.UnauthenticatedBind(""); err != nil {
			t.Fatal(err)
		}
		store.reset()
		return store, client
	}
	search := func(
		t *testing.T,
		store *monitorReadProbeStore,
		client *ldap.Conn,
		base string,
		scope,
		sizeLimit int,
		typesOnly bool,
		filter string,
		attributes []string,
	) (*ldap.SearchResult, error) {
		t.Helper()
		store.reset()
		return client.Search(ldap.NewSearchRequest(
			base, scope, ldap.NeverDerefAliases, sizeLimit, 0, typesOnly,
			filter, attributes, nil,
		))
	}
	assertReads := func(t *testing.T, store *monitorReadProbeStore, counts, scans uint64) {
		t.Helper()
		if got := store.counts.Load(); got != counts {
			t.Fatalf("partition count reads = %d, want %d", got, counts)
		}
		if got := store.scans.Load(); got != scans {
			t.Fatalf("entry scans = %d, want %d", got, scans)
		}
	}

	t.Run("projection", func(t *testing.T) {
		store, client := start(t)
		for _, test := range []struct {
			name       string
			typesOnly  bool
			filter     string
			attributes []string
			counts     uint64
		}{
			{"no-attributes", false, "(objectClass=*)", []string{"1.1"}, 0},
			{"user-attributes", false, "(objectClass=*)", []string{"*"}, 0},
			{"types-only", true, "(objectClass=*)", []string{"+"}, 0},
			{"present-filter", false, "(olmMDBEntries=*)", []string{"1.1"}, 0},
			{"value-filter", false, "(olmMDBEntries=4)", []string{"1.1"}, 1},
			{"explicit-value", false, "(objectClass=*)", []string{"olmMDBEntries"}, 1},
		} {
			t.Run(test.name, func(t *testing.T) {
				result, err := search(
					t, store, client, databaseDN, ldap.ScopeBaseObject, 0,
					test.typesOnly, test.filter, test.attributes,
				)
				if err != nil || len(result.Entries) != 1 {
					t.Fatalf("Search = %#v, %v", result, err)
				}
				assertReads(t, store, test.counts, 0)
			})
		}
		_, err := search(
			t, store, client, "cn=Databases,cn=Monitor", ldap.ScopeSingleLevel,
			1, false, "(objectClass=*)", []string{"+"},
		)
		assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
		assertReads(t, store, 0, 0)
	})

	t.Run("attribute-denied", func(t *testing.T) {
		store, client := start(t,
			`{0}to dn.base="`+databaseDN+`" attrs=olmMDBEntries by * none`,
			"{1}to * by * read",
		)
		result, err := search(
			t, store, client, databaseDN, ldap.ScopeBaseObject, 0,
			false, "(objectClass=*)", []string{"olmMDBEntries"},
		)
		if err != nil || len(result.Entries) != 1 ||
			result.Entries[0].GetAttributeValue("olmMDBEntries") != "" {
			t.Fatalf("denied projection Search = %#v, %v", result, err)
		}
		assertReads(t, store, 0, 0)

		result, err = search(
			t, store, client, databaseDN, ldap.ScopeBaseObject, 0,
			false, "(olmMDBEntries=4)", []string{"1.1"},
		)
		if err != nil || len(result.Entries) != 0 {
			t.Fatalf("denied filter Search = %#v, %v", result, err)
		}
		assertReads(t, store, 0, 0)

		store.reset()
		_, err = client.Compare(databaseDN, "olmMDBEntries", "4")
		assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)
		assertReads(t, store, 0, 0)
	})

	t.Run("entry-denied", func(t *testing.T) {
		store, client := start(t,
			`{0}to dn.base="`+databaseDN+`" by * none`,
			"{1}to * by * read",
		)
		_, err := search(
			t, store, client, databaseDN, ldap.ScopeBaseObject, 0,
			false, "(objectClass=*)", []string{"olmMDBEntries"},
		)
		assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
		assertReads(t, store, 0, 0)
	})
}

type monitorReadProbeStore struct {
	storage.Store
	counts atomic.Uint64
	scans  atomic.Uint64
}

func (store *monitorReadProbeStore) View(
	ctx context.Context,
	view func(storage.Reader) error,
) error {
	return store.Store.View(ctx, func(reader storage.Reader) error {
		return view(&monitorReadProbeReader{Reader: reader, store: store})
	})
}

func (store *monitorReadProbeStore) reset() {
	store.counts.Store(0)
	store.scans.Store(0)
}

type monitorReadProbeReader struct {
	storage.Reader
	store *monitorReadProbeStore
}

func (reader *monitorReadProbeReader) MaintenanceStorageReader() storage.Reader {
	return reader.Reader
}

func (reader *monitorReadProbeReader) PartitionEntryCount(partition string) (uint64, error) {
	reader.store.counts.Add(1)
	return storage.PartitionEntryCount(reader.Reader, partition)
}

func (reader *monitorReadProbeReader) ForEach(visit func(directory.Entry) error) error {
	reader.store.scans.Add(1)
	return reader.Reader.ForEach(visit)
}

func (reader *monitorReadProbeReader) ForEachIn(
	partition string,
	visit func(directory.Entry) error,
) error {
	reader.store.scans.Add(1)
	return reader.Reader.ForEachIn(partition, visit)
}

func (reader *monitorReadProbeReader) ForEachPartition(
	visit func(string, directory.Entry) error,
) error {
	reader.store.scans.Add(1)
	return reader.Reader.ForEachPartition(visit)
}

func setMonitoringValues(t *testing.T, store storage.Store, rawDN string, values ...string) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(staticRuntimeDN(rawDN))
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcMonitoring", stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
}
