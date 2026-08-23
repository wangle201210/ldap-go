package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPcachePrivateModifyMaterializesQueryEntryOutsideFilter(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	entry := pcachePrivateValidTestEntry(ldapBackendTestUserDN, "alice", "Visible")
	commitPcachePrivateEntryQuery(
		t,
		state,
		"query-only-modify",
		entry,
		ldapBackendTestSuffix,
		directory.Filter{
			Kind:      directory.FilterEquality,
			Attribute: "cn",
			Assertion: []byte("Visible"),
		},
	)

	request := ldapwire.ModifyRequest{
		DN: ldapBackendTestUserDN,
		Changes: []ldapwire.Modification{{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{
				Description: "cn",
				Values:      stringValues("Hidden"),
			},
		}},
	}
	connection := &pcacheBindCaptureConnection{}
	server := &Server{}
	if err := server.handlePcachePrivateModify(
		context.Background(),
		connection,
		&connectionState{runtime: runtime, boundDN: database.rootDN.String()},
		ldapwire.Message{
			ID:       1,
			Request:  request,
			Controls: []ldapwire.Control{{OID: pcachePrivateDBControl, Critical: true}},
		},
		request,
	); err != nil {
		t.Fatalf("private query-entry Modify: %v", err)
	}
	if code, ok := auditLDAPResultCode(connection.Bytes()); !ok || code != int(ldapwire.ResultSuccess) {
		t.Fatalf("private query-entry Modify result = %d, %t", code, ok)
	}

	dn, _ := runtime.schema.NormalizeDN(ldapBackendTestUserDN)
	entries, ok := state.privateEntries(runtime, database, true)
	if !ok || string(entries[dn.Key()].Values("cn")[0]) != "Hidden" {
		t.Fatalf("materialized private entry = %#v, available %t", entries[dn.Key()], ok)
	}
	state.mu.Lock()
	query := state.queries["query-only-modify"]
	_, materialized := state.private[dn.Key()]
	state.mu.Unlock()
	if query.entries != 0 || query.response.entryCount() != 0 || !materialized {
		t.Fatalf("reconciled query = %#v, materialized %t", query, materialized)
	}
}

func TestPcachePrivateModifyDNMaterializesQueryEntryOutsideBase(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	server := &Server{}
	connectionState := &connectionState{runtime: runtime, boundDN: database.rootDN.String()}
	entry := pcachePrivateValidTestEntry(ldapBackendTestUserDN, "alice", "Alice")
	commitPcachePrivateEntryQuery(
		t,
		state,
		"query-only-rename",
		entry,
		ldapBackendTestPeopleDN,
		directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	)
	archiveDN := "ou=archive," + ldapBackendTestSuffix
	archive := ldapwire.AddRequest{Entry: directory.Entry{
		DN: archiveDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("organizationalUnit")},
			{Description: "ou", Values: stringValues("archive")},
		},
	}}
	addConnection := &pcacheBindCaptureConnection{}
	if err := server.handlePcachePrivateAdd(
		context.Background(),
		addConnection,
		connectionState,
		ldapwire.Message{
			ID:       1,
			Request:  archive,
			Controls: []ldapwire.Control{{OID: pcachePrivateDBControl, Critical: true}},
		},
		archive,
	); err != nil {
		t.Fatalf("add destination superior: %v", err)
	}
	if code, ok := auditLDAPResultCode(addConnection.Bytes()); !ok || code != int(ldapwire.ResultSuccess) {
		t.Fatalf("add destination superior result = %d, %t", code, ok)
	}

	request := ldapwire.ModifyDNRequest{
		DN:             ldapBackendTestUserDN,
		NewRDN:         "uid=alice",
		DeleteOldRDN:   true,
		HasNewSuperior: true,
		NewSuperior:    archiveDN,
	}
	renameConnection := &pcacheBindCaptureConnection{}
	if err := server.handlePcachePrivateModifyDN(
		context.Background(),
		renameConnection,
		connectionState,
		ldapwire.Message{
			ID:       2,
			Request:  request,
			Controls: []ldapwire.Control{{OID: pcachePrivateDBControl, Critical: true}},
		},
		request,
	); err != nil {
		t.Fatalf("private query-entry ModifyDN: %v", err)
	}
	if code, ok := auditLDAPResultCode(renameConnection.Bytes()); !ok || code != int(ldapwire.ResultSuccess) {
		t.Fatalf("private query-entry ModifyDN result = %d, %t", code, ok)
	}

	oldDN, _ := runtime.schema.NormalizeDN(ldapBackendTestUserDN)
	newDN, _ := runtime.schema.NormalizeDN("uid=alice," + archiveDN)
	entries, ok := state.privateEntries(runtime, database, true)
	if !ok || entries[newDN.Key()].DN == "" {
		t.Fatalf("renamed materialized entry = %#v, available %t", entries[newDN.Key()], ok)
	}
	if _, exists := entries[oldDN.Key()]; exists {
		t.Fatalf("old query DN remained visible: %#v", entries[oldDN.Key()])
	}
	state.mu.Lock()
	query := state.queries["query-only-rename"]
	_, materialized := state.private[newDN.Key()]
	state.mu.Unlock()
	if query.entries != 0 || !materialized {
		t.Fatalf("renamed query = %#v, materialized %t", query, materialized)
	}
}

func TestPcachePrivateWriteSchemaFailures(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	server := &Server{}
	connectionState := &connectionState{runtime: runtime, boundDN: database.rootDN.String()}
	controls := []ldapwire.Control{{OID: pcachePrivateDBControl, Critical: true}}

	invalidAdd := ldapwire.AddRequest{Entry: directory.Entry{
		DN: "uid=invalid," + ldapBackendTestSuffix,
		Attributes: []directory.Attribute{
			{Description: "uid", Values: stringValues("invalid")},
			{Description: "cn", Values: stringValues("Invalid")},
			{Description: "sn", Values: stringValues("Invalid")},
		},
	}}
	invalidConnection := &pcacheBindCaptureConnection{}
	if err := server.handlePcachePrivateAdd(
		context.Background(), invalidConnection, connectionState,
		ldapwire.Message{ID: 1, Request: invalidAdd, Controls: controls}, invalidAdd,
	); err != nil {
		t.Fatalf("schema-invalid private Add: %v", err)
	}
	if code, ok := auditLDAPResultCode(invalidConnection.Bytes()); !ok || code != int(ldapwire.ResultObjectClassViolation) {
		t.Fatalf("schema-invalid private Add result = %d, %t", code, ok)
	}
	commitPcachePrivateEntryQuery(
		t,
		state,
		"schema-parent",
		pcachePrivateValidTestEntry(ldapBackendTestUserDN, "alice", "Alice"),
		ldapBackendTestSuffix,
		directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	)

	validDN := "uid=valid," + ldapBackendTestSuffix
	validAdd := ldapwire.AddRequest{Entry: pcachePrivateValidTestEntry(validDN, "valid", "Valid")}
	validConnection := &pcacheBindCaptureConnection{}
	if err := server.handlePcachePrivateAdd(
		context.Background(), validConnection, connectionState,
		ldapwire.Message{ID: 2, Request: validAdd, Controls: controls}, validAdd,
	); err != nil {
		t.Fatalf("valid private Add: %v", err)
	}
	if code, ok := auditLDAPResultCode(validConnection.Bytes()); !ok || code != int(ldapwire.ResultSuccess) {
		t.Fatalf("valid private Add result = %d, %t", code, ok)
	}

	invalidModify := ldapwire.ModifyRequest{
		DN: validDN,
		Changes: []ldapwire.Modification{{
			Operation: ldapwire.ModificationDelete,
			Attribute: directory.Attribute{Description: "sn"},
		}},
	}
	modifyConnection := &pcacheBindCaptureConnection{}
	if err := server.handlePcachePrivateModify(
		context.Background(), modifyConnection, connectionState,
		ldapwire.Message{ID: 3, Request: invalidModify, Controls: controls}, invalidModify,
	); err != nil {
		t.Fatalf("schema-invalid private Modify: %v", err)
	}
	if code, ok := auditLDAPResultCode(modifyConnection.Bytes()); !ok || code != int(ldapwire.ResultObjectClassViolation) {
		t.Fatalf("schema-invalid private Modify result = %d, %t", code, ok)
	}
	dn, _ := runtime.schema.NormalizeDN(validDN)
	entries, _ := state.privateEntries(runtime, database, true)
	if len(entries[dn.Key()].Values("sn")) != 1 {
		t.Fatalf("failed schema Modify changed entry: %#v", entries[dn.Key()])
	}

	invalidRename := ldapwire.ModifyDNRequest{
		DN:           validDN,
		NewRDN:       "dc=invalid",
		DeleteOldRDN: true,
	}
	renameConnection := &pcacheBindCaptureConnection{}
	if err := server.handlePcachePrivateModifyDN(
		context.Background(), renameConnection, connectionState,
		ldapwire.Message{ID: 4, Request: invalidRename, Controls: controls}, invalidRename,
	); err != nil {
		t.Fatalf("schema-invalid private ModifyDN: %v", err)
	}
	if code, ok := auditLDAPResultCode(renameConnection.Bytes()); !ok || code != int(ldapwire.ResultObjectClassViolation) {
		t.Fatalf("schema-invalid private ModifyDN result = %d, %t", code, ok)
	}
	entries, _ = state.privateEntries(runtime, database, true)
	if entries[dn.Key()].DN == "" {
		t.Fatalf("failed schema ModifyDN removed source entry: %#v", entries)
	}
}

func TestPcachePrivateRestoreRejectsCorruptEntries(t *testing.T) {
	tests := []struct {
		name      string
		entry     directory.Entry
		wantError string
	}{
		{
			name: "missing object class",
			entry: directory.Entry{
				DN: "uid=broken," + ldapBackendTestSuffix,
				Attributes: []directory.Attribute{
					{Description: "uid", Values: stringValues("broken")},
				},
			},
			wantError: "objectClass",
		},
		{
			name: "missing RDN value",
			entry: pcachePrivateValidTestEntry(
				"uid=expected,"+ldapBackendTestSuffix,
				"different",
				"Broken",
			),
			wantError: "RDN value",
		},
		{
			name: "empty attribute",
			entry: directory.Entry{
				DN: "uid=empty," + ldapBackendTestSuffix,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("empty")},
					{Description: "cn", Values: stringValues("Empty")},
					{Description: "sn"},
				},
			},
			wantError: "at least one value",
		},
		{
			name: "orphan",
			entry: pcachePrivateValidTestEntry(
				"uid=orphan,ou=missing,"+ldapBackendTestSuffix,
				"orphan",
				"Orphan",
			),
			wantError: "has no parent",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, database, _ := newPcachePrivateTestRuntime(t)
			database.pcache.maxEntries = 100
			database.pcache.maxQueries = 100
			runtime.databases[0] = database
			err := (&Server{}).restorePcacheSnapshot(
				runtime,
				&database,
				pcachePersistedSnapshot{PrivateEntries: []directory.Entry{test.entry}},
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("restore corrupt private entry error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestPcachePrivateSensitiveValuesAreCleared(t *testing.T) {
	secret := []byte("private-password")
	backup := pcacheStateBackup{private: map[string]directory.Entry{
		"private": {
			DN: "uid=private," + ldapBackendTestSuffix,
			Attributes: []directory.Attribute{{
				Description: "userPassword",
				Values:      [][]byte{secret},
			}},
		},
	}}
	clearPcacheBackup(backup)
	if !bytes.Equal(secret, make([]byte, len(secret))) || len(backup.private) != 0 {
		t.Fatalf("private backup secret was not cleared: %x, entries %d", secret, len(backup.private))
	}

	state := newPcacheState()
	oldSecret := []byte("old-private-password")
	state.private["private"] = directory.Entry{
		DN: "uid=private," + ldapBackendTestSuffix,
		Attributes: []directory.Attribute{{
			Description: "userPassword",
			Values:      [][]byte{oldSecret},
		}},
	}
	state.entries = 1
	if !state.mutate(context.Background(), func(candidate *pcacheState) (bool, bool) {
		candidate.private["private"] = directory.Entry{
			DN: "uid=private," + ldapBackendTestSuffix,
			Attributes: []directory.Attribute{{
				Description: "userPassword",
				Values:      stringValues("new-private-password"),
			}},
		}
		candidate.generation++
		return true, true
	}) {
		t.Fatal("private secret replacement failed")
	}
	if !bytes.Equal(oldSecret, make([]byte, len(oldSecret))) {
		t.Fatalf("retired private secret was not cleared: %x", oldSecret)
	}
}

func TestPcachePrivateSnapshotWaitDoesNotHoldStateLock(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	dn, _ := runtime.schema.NormalizeDN("uid=private," + ldapBackendTestSuffix)
	state.private[dn.Key()] = pcachePrivateValidTestEntry(dn.String(), "private", "Private")
	state.entries = 1

	state.privateSnapshotMu.Lock()
	readerStarted := make(chan struct{})
	readerDone := make(chan map[string]directory.Entry, 1)
	go func() {
		close(readerStarted)
		entries, _ := state.privateEntries(runtime, database, true)
		readerDone <- entries
	}()
	<-readerStarted

	lockAcquired := make(chan struct{})
	go func() {
		state.mu.Lock()
		_ = state.entries
		state.mu.Unlock()
		close(lockAcquired)
	}()
	select {
	case <-lockAcquired:
	case <-time.After(250 * time.Millisecond):
		state.privateSnapshotMu.Unlock()
		t.Fatal("private snapshot waiter held pcacheState.mu")
	}
	state.privateSnapshotMu.Unlock()
	entries := <-readerDone
	returned := entries[dn.Key()]
	returned.ReplaceValues("cn", stringValues("Detached"))
	state.mu.Lock()
	stored := state.private[dn.Key()].Clone()
	state.mu.Unlock()
	if string(stored.Values("cn")[0]) != "Private" {
		t.Fatalf("private snapshot shared mutable values: %#v", stored)
	}
}

func TestPcachePrivateWriteCancellationWhileWaitingForSerializer(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	state.persistence = &pcachePersistence{
		store: store, metadataKey: "pcache/private-write-cancel", fingerprint: "private-write-cancel", enabled: true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)
	before := readPcacheTestMetadata(t, store, state.persistence.metadataKey)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	firstDone := make(chan bool, 1)
	go func() {
		firstDone <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"serializer-owner",
			"uid=owner,"+ldapBackendTestPeopleDN,
		)
	}()
	<-blocked.started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	connection := &pcacheBindCaptureConnection{}
	instance := &Server{}
	request := ldapwire.ModifyRequest{
		DN: ldapBackendTestUserDN,
		Changes: []ldapwire.Modification{{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{Description: "cn", Values: stringValues("Canceled")},
		}},
	}
	stateConnection := &connectionState{runtime: runtime, boundDN: database.rootDN.String()}
	done := make(chan error, 1)
	go func() {
		done <- instance.handlePcachePrivateModify(
			ctx,
			connection,
			stateConnection,
			ldapwire.Message{
				ID:       2,
				Request:  request,
				Controls: []ldapwire.Control{{OID: pcachePrivateDBControl, Critical: true}},
			},
			request,
		)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled private Modify: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("canceled private Modify remained blocked on serializer")
	}
	if code, ok := auditLDAPResultCode(connection.Bytes()); !ok || code != int(ldapwire.ResultOther) {
		t.Fatalf("canceled private Modify response = %d, %t", code, ok)
	}
	close(blocked.release)
	if !<-firstDone {
		t.Fatal("serializer owner mutation failed")
	}
	dn, err := runtime.schema.NormalizeDN(ldapBackendTestUserDN)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	entry := state.privatePhysicalEntriesUnlocked(runtime, state.clock())[dn.Key()]
	state.persistence.store = store
	state.mu.Unlock()
	if len(entry.Values("cn")) != 0 {
		t.Fatalf("canceled private Modify changed memory: %#v", entry)
	}
	if after := readPcacheTestMetadata(t, store, state.persistence.metadataKey); bytes.Equal(before, after) {
		// The serializer owner committed its own query, so the snapshot must
		// change, but the canceled Modify must not appear in it.
		return
	}
	snapshot := readPcacheTestSnapshot(t, store, state.persistence.metadataKey)
	for _, query := range snapshot.Queries {
		for _, item := range query.Response.Items {
			if item.Entry != nil && len(item.Entry.Values("cn")) != 0 {
				t.Fatalf("canceled private Modify reached durable snapshot: %#v", item.Entry)
			}
		}
	}
}

func pcachePrivateValidTestEntry(dn, uid, cn string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(cn)},
			{Description: "sn", Values: stringValues(cn)},
		},
	}
}

func commitPcachePrivateEntryQuery(
	t *testing.T,
	state *pcacheState,
	key string,
	entry directory.Entry,
	baseDN string,
	filter directory.Filter,
) {
	t.Helper()
	cloned := entry.Clone()
	if !state.commit(
		key,
		pcacheSearchResponse{
			items:  []pcacheSearchItem{{entry: &cloned}},
			result: ldapwire.Result{Code: ldapwire.ResultSuccess},
		},
		ldapwire.Message{Request: ldapwire.SearchRequest{
			BaseDN:     baseDN,
			Scope:      directory.ScopeWholeSubtree,
			Filter:     filter,
			Attributes: []string{"objectClass", "uid", "cn", "sn"},
		}},
		pcacheRemoteContext{},
		state.clock(),
		pcacheRefreshPolicy{
			positiveTTL: time.Hour,
			entryLimit:  100,
			attrset:     0,
		},
		1000,
		1000,
		false,
	) {
		t.Fatalf("commit private query %q failed", key)
	}
}

func TestPcachePrivateWriteReconcilesSharedQueriesAndRollsBack(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	firstID := commitPcachePrivateTestQuery(t, state, "shared-first", ldapBackendTestUserDN)
	secondID := commitPcachePrivateTestQuery(t, state, "shared-second", ldapBackendTestUserDN)

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	configurePcachePersistenceTestRuntime(
		runtime,
		&database,
		state,
		store,
		"olcOverlay={0}pcache,olcDatabase={1}ldap,cn=config",
		"pcache/private-write-shared",
		"private-write-shared",
		true,
	)
	server := &Server{config: Config{Store: store}}
	ensurePcacheTestRuntime(t, server, store, runtime)

	dn, err := runtime.schema.NormalizeDN(ldapBackendTestUserDN)
	if err != nil {
		t.Fatal(err)
	}
	mutateCN := func(candidate *pcacheState, value string) (bool, bool) {
		physical := candidate.privatePhysicalEntriesUnlocked(runtime, candidate.clock())
		entry := physical[dn.Key()]
		entry.ReplaceValues("cn", stringValues(value))
		physical[dn.Key()] = entry
		next := candidate.generation + 1
		if failure := candidate.reconcilePrivateQueries(runtime, database, physical, next); failure != nil {
			t.Errorf("reconcile shared queries: %#v", failure)
			return false, true
		}
		candidate.generation = next
		return true, true
	}
	if !state.mutate(context.Background(), func(candidate *pcacheState) (bool, bool) {
		return mutateCN(candidate, "Shared Updated")
	}) {
		t.Fatal("shared private mutation failed")
	}
	entries, ok := state.privateEntries(runtime, database, true)
	if !ok || string(entries[dn.Key()].Values("cn")[0]) != "Shared Updated" {
		t.Fatalf("shared private entry = %#v, %t", entries[dn.Key()], ok)
	}
	ids := entries[dn.Key()].Values(pcacheQueryIDAttribute)
	if len(ids) != 2 ||
		!(bytes.Equal(ids[0], []byte(firstID)) || bytes.Equal(ids[1], []byte(firstID))) ||
		!(bytes.Equal(ids[0], []byte(secondID)) || bytes.Equal(ids[1], []byte(secondID))) {
		t.Fatalf("shared query IDs = %q", ids)
	}
	state.mu.Lock()
	for key, query := range state.queries {
		if query.entries != 1 || query.response.entryCount() != 1 || query.identifier == "" {
			state.mu.Unlock()
			t.Fatalf("query %q after shared update = %#v", key, query)
		}
	}
	beforeMemory := state.privatePhysicalEntriesUnlocked(runtime, state.clock())[dn.Key()].Clone()
	beforeSnapshot := readPcacheTestMetadata(t, store, state.persistence.metadataKey)
	state.persistence.store = pcacheFailingMetadataStore{Store: store, err: context.Canceled}
	state.mu.Unlock()

	if state.mutate(context.Background(), func(candidate *pcacheState) (bool, bool) {
		return mutateCN(candidate, "Must Roll Back")
	}) {
		t.Fatal("failed persistence mutation reported success")
	}
	state.mu.Lock()
	afterMemory := state.privatePhysicalEntriesUnlocked(runtime, state.clock())[dn.Key()].Clone()
	state.persistence.store = store
	state.mu.Unlock()
	if !beforeMemory.Equal(afterMemory) {
		t.Fatalf("failed persistence mutation changed memory: before %#v after %#v", beforeMemory, afterMemory)
	}
	if afterSnapshot := readPcacheTestMetadata(t, store, state.persistence.metadataKey); !bytes.Equal(beforeSnapshot, afterSnapshot) {
		t.Fatal("failed persistence mutation changed durable snapshot")
	}

	if !state.mutate(context.Background(), func(candidate *pcacheState) (bool, bool) {
		physical := candidate.privatePhysicalEntriesUnlocked(runtime, candidate.clock())
		delete(physical, dn.Key())
		next := candidate.generation + 1
		if failure := candidate.reconcilePrivateQueries(runtime, database, physical, next); failure != nil {
			t.Errorf("reconcile shared delete: %#v", failure)
			return false, true
		}
		candidate.generation = next
		return true, true
	}) {
		t.Fatal("shared private delete failed")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for key, query := range state.queries {
		if query.entries != 0 || query.response.entryCount() != 0 || query.identifier != "" {
			t.Fatalf("query %q after shared delete = %#v", key, query)
		}
		if url := pcacheQueryURL(query); url == "" || !bytes.Contains([]byte(url), []byte("x-uuid=")) {
			t.Fatalf("query %q URL after negative transition = %q", key, url)
		}
	}
}

func TestPcachePrivateWriteProtectedMetadataAliases(t *testing.T) {
	for _, description := range []string{
		pcacheQueryIDAttribute,
		pcacheQueryURLAttribute + ";binary",
		"pcacheNumQueries",
		"pcacheNumEntries",
		pcacheQueryIDOID,
		pcacheQueryURLOID,
		pcacheNumQueriesOID,
		pcacheNumEntriesOID,
	} {
		if !pcachePrivateProtectedAttribute(description) {
			t.Fatalf("protected metadata %q was accepted", description)
		}
	}
	if pcachePrivateProtectedAttribute("description") {
		t.Fatal("ordinary private attribute was protected")
	}
}

func TestPcachePrivateWriteOpenLDAPSourceContract(t *testing.T) {
	sources := []string{
		os.Getenv("OPENLDAP_SOURCE"),
		"/private/tmp/ldap-go-openldap-source-2.6.13",
		"/private/tmp/ldap-go-openldap-source-2.6.13-full",
	}
	for _, source := range sources {
		if source == "" {
			continue
		}
		path := filepath.Join(source, "servers", "slapd", "overlays", "pcache.c")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		assertOpenLDAPPcacheFile(t, path, openLDAPPcacheSourceSHA256, []string{
			"static int\npcache_op_privdb(",
			"if ( !be_isroot( op ) )",
			"rc = (&bi->bi_op_bind)[ type ]( &op2, rs );",
			"pcache.on_bi.bi_op_modrdn = pcache_op_privdb;",
			"pcache.on_bi.bi_op_modify = pcache_op_privdb;",
			"pcache.on_bi.bi_op_add = pcache_op_privdb;",
			"pcache.on_bi.bi_op_delete = pcache_op_privdb;",
		})
		return
	}
	t.Skip("pinned OpenLDAP pcache.c unavailable")
}
