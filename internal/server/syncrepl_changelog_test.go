package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerDSEEUUID(t *testing.T) {
	t.Parallel()

	identifier, err := parseSyncConsumerDSEEUUID(
		"11111111-22223333-44445555-55555555",
	)
	if err != nil {
		t.Fatalf("parseSyncConsumerDSEEUUID(): %v", err)
	}
	if got, want := identifier.String(), "11111111-2222-3333-4444-555555555555"; got != want {
		t.Fatalf("DSEE UUID = %q, want %q", got, want)
	}
	for _, malformed := range []string{
		"",
		"11111111-22223333-44445555",
		"11111111-22223333-44445555-5555555z",
	} {
		if _, err := parseSyncConsumerDSEEUUID(malformed); err == nil {
			t.Fatalf("accepted malformed DSEE UUID %q", malformed)
		}
	}
}

func TestSyncConsumerChangelogAppliesOperationsAndStateAtomically(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	config.syncData = "changelog"
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
				{Description: "entryUUID", Values: stringValues("00000000-0000-0000-0000-000000000001")},
			},
		},
		{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "organizationalUnit")},
				{Description: "ou", Values: stringValues("people")},
				{Description: "entryUUID", Values: stringValues("00000000-0000-0000-0000-000000000002")},
			},
		},
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerChangelogState(writer, config, 0)
	}); err != nil {
		t.Fatalf("seed changelog state: %v", err)
	}

	if err := server.applySyncConsumerChangelogEntry(
		context.Background(),
		config,
		syncConsumerChangelogTestEntry(
			1,
			"uid=alice,ou=people,dc=example,dc=com",
			"add",
			"objectClass: top\n"+
				"objectClass: person\n"+
				"objectClass: organizationalPerson\n"+
				"objectClass: inetOrgPerson\n"+
				"uid: alice\n"+
				"cn: Alice\n"+
				"sn: Example",
			map[string][]string{
				"targetUniqueId": {"11111111-22223333-44445555-55555555"},
			},
		),
	); err != nil {
		t.Fatalf("apply DSEE add: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice",
	)
	assertSyncConsumerChangelogState(t, store, config, 1)

	if err := server.applySyncConsumerChangelogEntry(
		context.Background(),
		config,
		syncConsumerChangelogTestEntry(
			2,
			"uid=alice,ou=people,dc=example,dc=com",
			"modify",
			"replace: cn\ncn: Alice Delta\n-\n"+
				"add: description\ndescription: first\n"+
				"description: second\n-",
			nil,
		),
	); err != nil {
		t.Fatalf("apply DSEE modify: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Delta",
	)
	assertSyncConsumerEntryValues(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
		"description",
		[]string{"first", "second"},
	)

	if err := server.applySyncConsumerChangelogEntry(
		context.Background(),
		config,
		syncConsumerChangelogTestEntry(
			3,
			"uid=alice,ou=people,dc=example,dc=com",
			"modrdn",
			"",
			map[string][]string{
				"newRDN":       {"uid=renamed"},
				"deleteOldRDN": {"TRUE"},
			},
		),
	); err != nil {
		t.Fatalf("apply DSEE modrdn: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=renamed,ou=people,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Delta",
	)

	if err := server.applySyncConsumerChangelogEntry(
		context.Background(),
		config,
		syncConsumerChangelogTestEntry(
			4,
			"uid=renamed,ou=people,dc=example,dc=com",
			"delete",
			"",
			nil,
		),
	); err != nil {
		t.Fatalf("apply DSEE delete: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=renamed,ou=people,dc=example,dc=com",
	)
	assertSyncConsumerChangelogState(t, store, config, 4)
}

func TestSyncConsumerChangelogGapRollsBackOperationAndState(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	config.syncData = "changelog"
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
		syncConsumerTestEntry(
			"uid=alice,dc=example,dc=com",
			"11111111-2222-3333-4444-555555555555",
			"Current",
		),
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerChangelogState(writer, config, 4)
	}); err != nil {
		t.Fatalf("seed changelog state: %v", err)
	}

	err := server.applySyncConsumerChangelogEntry(
		context.Background(),
		config,
		syncConsumerChangelogTestEntry(
			6,
			"uid=alice,dc=example,dc=com",
			"modify",
			"replace: cn\ncn: Skipped\n-",
			nil,
		),
	)
	if err == nil || !stringsContains(err.Error(), "changeNumber gap") {
		t.Fatalf("gap error = %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Current",
	)
	assertSyncConsumerChangelogState(t, store, config, 4)
}

func TestSyncConsumerChangelogSnapshotMapsUUIDAndRemovesStaleEntries(t *testing.T) {
	t.Parallel()

	server, store, config := newSyncConsumerUnitServer(t)
	config.syncData = "changelog"
	runtime := server.runtime.Load()
	suffixSource := ldap.NewEntry("dc=example,dc=com", map[string][]string{
		"objectClass": {"top", "domain"},
		"dc":          {"example"},
		"nsUniqueId":  {"00000000-00000000-00000000-00000001"},
	})
	suffix, err := syncConsumerChangelogSnapshotEntry(runtime, config, suffixSource)
	if err != nil {
		t.Fatalf("map suffix snapshot: %v", err)
	}
	presentSource := ldap.NewEntry("uid=present,dc=example,dc=com", map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"uid":         {"present"},
		"cn":          {"Present"},
		"sn":          {"Example"},
		"nsUniqueId":  {"11111111-22223333-44445555-55555555"},
	})
	present, err := syncConsumerChangelogSnapshotEntry(runtime, config, presentSource)
	if err != nil {
		t.Fatalf("map present snapshot: %v", err)
	}
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		suffix,
		present,
		syncConsumerTestEntry(
			"uid=stale,dc=example,dc=com",
			"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"Stale",
		),
	})
	seen := map[string]struct{}{
		mustSyncConsumerDN(t, suffix.DN).Key():  {},
		mustSyncConsumerDN(t, present.DN).Key(): {},
	}
	if err := server.finishSyncConsumerChangelogSnapshot(
		context.Background(),
		config,
		seen,
		12,
	); err != nil {
		t.Fatalf("finish changelog snapshot: %v", err)
	}
	assertSyncConsumerMissingEntry(
		t,
		store,
		config.partition,
		"uid=stale,dc=example,dc=com",
	)
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=present,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Present",
	)
	assertSyncConsumerChangelogState(t, store, config, 12)
}

func TestSyncConsumerChangelogPersistentSearchControl(t *testing.T) {
	t.Parallel()

	controls := syncConsumerChangelogControls(syncConsumerConfig{}, true)
	control := ldap.FindControl(controls, syncConsumerPersistentSearchOID)
	if control == nil {
		t.Fatal("persistent search control is missing")
	}
	typed, ok := control.(*ldap.ControlString)
	if !ok || typed.Criticality {
		t.Fatalf("persistent search control = %#v", control)
	}
	packet, err := ber.DecodePacketErr([]byte(typed.ControlValue))
	if err != nil {
		t.Fatalf("decode persistent search value: %v", err)
	}
	if len(packet.Children) != 3 ||
		packet.Children[0].Value != int64(1) ||
		packet.Children[1].Value != false ||
		packet.Children[2].Value != true {
		t.Fatalf("persistent search value = %#v", packet.Children)
	}
	if control := ldap.FindControl(
		syncConsumerChangelogControls(syncConsumerConfig{}, false),
		syncConsumerPersistentSearchOID,
	); control != nil {
		t.Fatalf("refresh-only controls include persistent search: %#v", control)
	}
}

func TestSyncConsumerChangelogPersistedZeroForcesSnapshot(t *testing.T) {
	provider := newSyncConsumerDSEETestProvider(t)
	provider.setData(
		1,
		1,
		[]*ldap.Entry{
			ldap.NewEntry("dc=example,dc=com", map[string][]string{
				"objectClass": {"top", "domain"},
				"dc":          {"example"},
				"nsUniqueId":  {"00000000-00000000-00000000-00000001"},
			}),
			ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
				"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
				"uid":         {"alice"},
				"cn":          {"Alice Snapshot"},
				"sn":          {"Example"},
				"nsUniqueId":  {"11111111-22223333-44445555-55555555"},
			}),
		},
		nil,
	)

	consumer, store, config := newSyncConsumerUnitServer(t)
	config.syncData = "changelog"
	config.mode = syncConsumerRefreshOnly
	config.providerURLs = []string{"ldap://" + provider.address()}
	config.operationTimeout = 2 * time.Second
	config.networkTimeout = 2 * time.Second
	logBase := mustSyncConsumerDN(t, "cn=changelog")
	config.logBase = &logBase
	seedSyncConsumerEntries(t, store, config.partition, []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerChangelogState(writer, config, 0)
	}); err != nil {
		t.Fatalf("seed zero changelog state: %v", err)
	}
	assertSyncConsumerChangelogState(t, store, config, 0)

	if err := consumer.runSyncConsumerCycle(
		context.Background(),
		config,
		config.providerURLs[0],
	); err != nil {
		t.Fatalf("DSEE consumer cycle from zero state: %v", err)
	}
	if got := provider.snapshotSearches(); got != 1 {
		t.Fatalf("snapshot searches from zero state = %d, want 1", got)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Snapshot",
	)
	assertSyncConsumerChangelogState(t, store, config, 1)
}

func TestSyncConsumerChangelogProtocolSnapshotReplayRestartAndPersist(t *testing.T) {
	provider := newSyncConsumerDSEETestProvider(t)
	provider.setData(
		1,
		1,
		[]*ldap.Entry{
			ldap.NewEntry("dc=example,dc=com", map[string][]string{
				"objectClass": {"top", "domain"},
				"dc":          {"example"},
				"nsUniqueId":  {"00000000-00000000-00000000-00000001"},
			}),
			ldap.NewEntry("uid=alice,dc=example,dc=com", map[string][]string{
				"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
				"uid":         {"alice"},
				"cn":          {"Alice"},
				"sn":          {"Example"},
				"nsUniqueId":  {"11111111-22223333-44445555-55555555"},
			}),
		},
		[]*ldap.Entry{
			syncConsumerChangelogTestEntry(
				2,
				"uid=alice,dc=example,dc=com",
				"modify",
				"replace: cn\ncn: Alice Delta\n-",
				nil,
			),
		},
	)

	consumer, store, config := newSyncConsumerUnitServer(t)
	config.syncData = "changelog"
	config.mode = syncConsumerRefreshOnly
	config.providerURLs = []string{"ldap://" + provider.address()}
	config.operationTimeout = 2 * time.Second
	config.networkTimeout = 2 * time.Second
	logBase := mustSyncConsumerDN(t, "cn=changelog")
	config.logBase = &logBase
	if err := consumer.runSyncConsumerCycle(
		context.Background(),
		config,
		config.providerURLs[0],
	); err != nil {
		t.Fatalf("initial DSEE consumer cycle: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Delta",
	)
	assertSyncConsumerChangelogState(t, store, config, 2)

	provider.setData(
		1,
		3,
		nil,
		[]*ldap.Entry{
			syncConsumerChangelogTestEntry(
				2,
				"uid=alice,dc=example,dc=com",
				"modify",
				"replace: cn\ncn: Alice Delta\n-",
				nil,
			),
			syncConsumerChangelogTestEntry(
				3,
				"uid=bob,dc=example,dc=com",
				"add",
				"objectClass: top\nobjectClass: person\n"+
					"objectClass: organizationalPerson\n"+
					"objectClass: inetOrgPerson\nuid: bob\n"+
					"cn: Bob\nsn: Example",
				map[string][]string{
					"targetUniqueId": {"aaaaaaaa-bbbbcccc-ddddeeee-eeeeeeee"},
				},
			),
		},
	)
	if err := consumer.runSyncConsumerCycle(
		context.Background(),
		config,
		config.providerURLs[0],
	); err != nil {
		t.Fatalf("restarted DSEE consumer cycle: %v", err)
	}
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=bob,dc=example,dc=com",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"Bob",
	)
	assertSyncConsumerChangelogState(t, store, config, 3)
	if got := provider.snapshotSearches(); got != 1 {
		t.Fatalf("snapshot searches after restart = %d, want 1", got)
	}

	provider.setData(
		1,
		4,
		nil,
		[]*ldap.Entry{
			syncConsumerChangelogTestEntry(
				4,
				"uid=alice,dc=example,dc=com",
				"modify",
				"replace: cn\ncn: Alice Persistent\n-",
				nil,
			),
		},
	)
	config.mode = syncConsumerRefreshAndPersist
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- consumer.runSyncConsumerCycle(
			ctx,
			config,
			config.providerURLs[0],
		)
	}()
	waitForSyncConsumerChangelogState(t, store, config, 4)
	assertSyncConsumerStoredEntry(
		t,
		store,
		config.partition,
		"uid=alice,dc=example,dc=com",
		"11111111-2222-3333-4444-555555555555",
		"Alice Persistent",
	)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("persistent DSEE consumer stop error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("persistent DSEE consumer did not stop after cancellation")
	}
	if !provider.sawPersistentSearch() {
		t.Fatal("provider did not receive a Persistent Search control")
	}
	if got, want := provider.changelogFilters(), []string{
		"(changeNumber>=2)",
		"(changeNumber>=3)",
		"(changeNumber>=4)",
	}; !slices.Equal(got, want) {
		t.Fatalf("changelog filters = %q, want %q", got, want)
	}
}

type syncConsumerDSEETestProvider struct {
	listener net.Listener

	mu              sync.Mutex
	first           uint64
	last            uint64
	snapshot        []*ldap.Entry
	changes         []*ldap.Entry
	snapshotCount   int
	filters         []string
	persistent      bool
	connections     map[net.Conn]struct{}
	connectionGroup sync.WaitGroup
	errors          chan error
}

func newSyncConsumerDSEETestProvider(t *testing.T) *syncConsumerDSEETestProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DSEE test provider: %v", err)
	}
	provider := &syncConsumerDSEETestProvider{
		listener:    listener,
		connections: make(map[net.Conn]struct{}),
		errors:      make(chan error, 16),
	}
	provider.connectionGroup.Add(1)
	go provider.accept()
	t.Cleanup(func() {
		provider.close()
		select {
		case err := <-provider.errors:
			if err != nil {
				t.Errorf("DSEE test provider: %v", err)
			}
		default:
		}
	})
	return provider
}

func (provider *syncConsumerDSEETestProvider) address() string {
	return provider.listener.Addr().String()
}

func (provider *syncConsumerDSEETestProvider) setData(
	first,
	last uint64,
	snapshot,
	changes []*ldap.Entry,
) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.first = first
	provider.last = last
	if snapshot != nil {
		provider.snapshot = append([]*ldap.Entry(nil), snapshot...)
	}
	provider.changes = append([]*ldap.Entry(nil), changes...)
}

func (provider *syncConsumerDSEETestProvider) snapshotSearches() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.snapshotCount
}

func (provider *syncConsumerDSEETestProvider) changelogFilters() []string {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]string(nil), provider.filters...)
}

func (provider *syncConsumerDSEETestProvider) sawPersistentSearch() bool {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.persistent
}

func (provider *syncConsumerDSEETestProvider) accept() {
	defer provider.connectionGroup.Done()
	for {
		connection, err := provider.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				provider.report(err)
			}
			return
		}
		provider.mu.Lock()
		provider.connections[connection] = struct{}{}
		provider.mu.Unlock()
		provider.connectionGroup.Add(1)
		go provider.serve(connection)
	}
}

func (provider *syncConsumerDSEETestProvider) serve(connection net.Conn) {
	defer provider.connectionGroup.Done()
	defer func() {
		_ = connection.Close()
		provider.mu.Lock()
		delete(provider.connections, connection)
		provider.mu.Unlock()
	}()
	for {
		request, err := ber.ReadPacket(connection)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				provider.report(err)
			}
			return
		}
		if len(request.Children) < 2 {
			provider.report(errors.New("LDAP request has fewer than two children"))
			return
		}
		messageID, ok := request.Children[0].Value.(int64)
		if !ok {
			provider.report(fmt.Errorf("LDAP message ID = %#v", request.Children[0].Value))
			return
		}
		operation := request.Children[1]
		switch operation.Tag {
		case ldap.ApplicationSearchRequest:
			if err := provider.respondToSearch(connection, messageID, request); err != nil {
				provider.report(err)
				return
			}
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationAbandonRequest:
			continue
		default:
			provider.report(fmt.Errorf("unexpected LDAP operation tag %d", operation.Tag))
			return
		}
	}
}

func (provider *syncConsumerDSEETestProvider) respondToSearch(
	connection net.Conn,
	messageID int64,
	request *ber.Packet,
) error {
	operation := request.Children[1]
	if len(operation.Children) < 8 {
		return errors.New("search request is truncated")
	}
	base, ok := operation.Children[0].Value.(string)
	if !ok {
		return fmt.Errorf("search base = %#v", operation.Children[0].Value)
	}
	switch strings.ToLower(base) {
	case "":
		provider.mu.Lock()
		first, last := provider.first, provider.last
		provider.mu.Unlock()
		if err := writeSyncConsumerPacket(connection, encodeDSEETestSearchEntry(
			messageID,
			ldap.NewEntry("", map[string][]string{
				"firstChangeNumber": {strconv.FormatUint(first, 10)},
				"lastChangeNumber":  {strconv.FormatUint(last, 10)},
			}),
			false,
		)); err != nil {
			return err
		}
		return writeSyncConsumerPacket(connection, encodeDSEETestSearchDone(messageID))
	case "dc=example,dc=com":
		provider.mu.Lock()
		provider.snapshotCount++
		entries := append([]*ldap.Entry(nil), provider.snapshot...)
		provider.mu.Unlock()
		for _, entry := range entries {
			if err := writeSyncConsumerPacket(
				connection,
				encodeDSEETestSearchEntry(messageID, entry, false),
			); err != nil {
				return err
			}
		}
		return writeSyncConsumerPacket(connection, encodeDSEETestSearchDone(messageID))
	case "cn=changelog":
		filter, err := ldap.DecompileFilter(operation.Children[6])
		if err != nil {
			return fmt.Errorf("decompile changelog filter: %w", err)
		}
		minimum, err := parseDSEETestChangeFilter(filter)
		if err != nil {
			return err
		}
		persistent := dseeTestRequestHasControl(request, syncConsumerPersistentSearchOID)
		provider.mu.Lock()
		provider.filters = append(provider.filters, filter)
		provider.persistent = provider.persistent || persistent
		entries := append([]*ldap.Entry(nil), provider.changes...)
		provider.mu.Unlock()
		sort.Slice(entries, func(i, j int) bool {
			left, _ := strconv.ParseUint(entries[i].GetAttributeValue("changeNumber"), 10, 64)
			right, _ := strconv.ParseUint(entries[j].GetAttributeValue("changeNumber"), 10, 64)
			return left < right
		})
		for _, entry := range entries {
			number, err := strconv.ParseUint(entry.GetAttributeValue("changeNumber"), 10, 64)
			if err != nil || number < minimum {
				continue
			}
			if err := writeSyncConsumerPacket(
				connection,
				encodeDSEETestSearchEntry(messageID, entry, persistent),
			); err != nil {
				return err
			}
		}
		if persistent {
			return nil
		}
		return writeSyncConsumerPacket(connection, encodeDSEETestSearchDone(messageID))
	default:
		return fmt.Errorf("unexpected search base %q", base)
	}
}

func (provider *syncConsumerDSEETestProvider) close() {
	_ = provider.listener.Close()
	provider.mu.Lock()
	for connection := range provider.connections {
		_ = connection.Close()
	}
	provider.mu.Unlock()
	provider.connectionGroup.Wait()
}

func (provider *syncConsumerDSEETestProvider) report(err error) {
	select {
	case provider.errors <- err:
	default:
	}
}

func parseDSEETestChangeFilter(filter string) (uint64, error) {
	const prefix = "(changeNumber>="
	if !strings.HasPrefix(filter, prefix) || !strings.HasSuffix(filter, ")") {
		return 0, fmt.Errorf("unexpected changelog filter %q", filter)
	}
	value := strings.TrimSuffix(strings.TrimPrefix(filter, prefix), ")")
	minimum, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse changelog filter %q: %w", filter, err)
	}
	return minimum, nil
}

func dseeTestRequestHasControl(request *ber.Packet, oid string) bool {
	if len(request.Children) < 3 {
		return false
	}
	for _, control := range request.Children[2].Children {
		if len(control.Children) > 0 && control.Children[0].Value == oid {
			return true
		}
	}
	return false
}

func encodeDSEETestSearchEntry(
	messageID int64,
	entry *ldap.Entry,
	entryChangeNotice bool,
) []byte {
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationSearchResultEntry,
		nil,
		"SearchResultEntry",
	)
	response.AppendChild(syncConsumerOctetString([]byte(entry.DN), "objectName"))
	attributes := ber.NewSequence("attributes")
	for _, attribute := range entry.Attributes {
		partial := ber.NewSequence("partialAttribute")
		partial.AppendChild(syncConsumerOctetString([]byte(attribute.Name), "type"))
		values := ber.Encode(
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSet,
			nil,
			"vals",
		)
		for _, value := range attribute.ByteValues {
			values.AppendChild(syncConsumerOctetString(value, "value"))
		}
		partial.AppendChild(values)
		attributes.AppendChild(partial)
	}
	response.AppendChild(attributes)
	message.AppendChild(response)
	if entryChangeNotice {
		controls := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			0,
			nil,
			"Controls",
		)
		control := ber.NewSequence("Control")
		control.AppendChild(syncConsumerOctetString(
			[]byte(syncConsumerEntryChangeNoticeOID),
			"controlType",
		))
		value := ber.NewSequence("EntryChangeNotification")
		value.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int64(1),
			"changeType",
		))
		control.AppendChild(syncConsumerOctetString(value.Bytes(), "controlValue"))
		controls.AppendChild(control)
		message.AppendChild(controls)
	}
	return message.Bytes()
}

func encodeDSEETestSearchDone(messageID int64) []byte {
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationSearchResultDone,
		nil,
		"SearchResultDone",
	)
	response.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(ldap.LDAPResultSuccess),
		"resultCode",
	))
	response.AppendChild(syncConsumerOctetString(nil, "matchedDN"))
	response.AppendChild(syncConsumerOctetString(nil, "diagnosticMessage"))
	message.AppendChild(response)
	return message.Bytes()
}

func waitForSyncConsumerChangelogState(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	want uint64,
) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var (
			value uint64
			found bool
		)
		err := store.View(context.Background(), func(reader storage.Reader) error {
			var err error
			value, found, err = readSyncConsumerChangelogState(reader, config)
			return err
		})
		if err == nil && found && value == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("changelog state did not reach %d", want)
}

func syncConsumerChangelogTestEntry(
	changeNumber uint64,
	targetDN,
	changeType,
	changes string,
	extra map[string][]string,
) *ldap.Entry {
	attributes := map[string][]string{
		"objectClass":  {"changeLogEntry"},
		"changeNumber": {strconvFormatUint(changeNumber)},
		"targetDN":     {targetDN},
		"changeType":   {changeType},
	}
	if changes != "" {
		attributes["changes"] = []string{changes}
	}
	for description, values := range extra {
		attributes[description] = values
	}
	return ldap.NewEntry(
		"changeNumber="+strconvFormatUint(changeNumber)+",cn=changelog",
		attributes,
	)
}

func assertSyncConsumerChangelogState(
	t *testing.T,
	store storage.Store,
	config syncConsumerConfig,
	want uint64,
) {
	t.Helper()
	var (
		got   uint64
		found bool
	)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		got, found, err = readSyncConsumerChangelogState(reader, config)
		return err
	}); err != nil {
		t.Fatalf("read changelog state: %v", err)
	}
	if !found || got != want {
		t.Fatalf("changelog state = %d, found %t, want %d", got, found, want)
	}
	var values [][]byte
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(config.partition, config.localBase)
		if err != nil {
			return err
		}
		values = entry.Values("lastChangeNumber")
		return nil
	}); err != nil {
		t.Fatalf("read context lastChangeNumber: %v", err)
	}
	if len(values) != 1 || string(values[0]) != strconvFormatUint(want) {
		t.Fatalf("context lastChangeNumber = %q, want %d", values, want)
	}
}

func strconvFormatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func stringsContains(value, fragment string) bool {
	return strings.Contains(value, fragment)
}
