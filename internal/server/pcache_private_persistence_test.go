package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPcacheQueryDeleteBERAndPrivateControl(t *testing.T) {
	t.Parallel()

	identifier := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	for _, test := range []struct {
		name string
		tag  byte
		dn   string
		id   string
	}{
		{name: "base and UUID", tag: pcacheQueryDeleteBaseTag, dn: ldapBackendTestSuffix, id: identifier.String()},
		{name: "entry", tag: pcacheQueryDeleteDNTag, dn: ldapBackendTestUserDN},
		{name: "entry and UUID", tag: pcacheQueryDeleteDNTag, dn: ldapBackendTestUserDN, id: identifier.String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := pcacheEncodeQueryDeleteRequest(test.tag, test.dn, test.id)
			if err != nil {
				t.Fatalf("encode queryDelete: %v", err)
			}
			decoded, err := decodePcacheQueryDeleteRequest(encoded)
			if err != nil {
				t.Fatalf("decode queryDelete: %v", err)
			}
			if decoded.tag != test.tag || string(decoded.dn) != test.dn ||
				decoded.identifier != test.id {
				t.Fatalf("decoded queryDelete = %#v", decoded)
			}
		})
	}

	valid, err := pcacheEncodeQueryDeleteRequest(
		pcacheQueryDeleteBaseTag,
		ldapBackendTestSuffix,
		identifier.String(),
	)
	if err != nil {
		t.Fatalf("encode valid queryDelete: %v", err)
	}
	badUUID := pcacheEncodeBERElement(pcacheQueryDeleteBaseTag, []byte(ldapBackendTestSuffix))
	badUUID = append(badUUID, pcacheEncodeBERElement(pcacheQueryDeleteUUIDTag, make([]byte, 15))...)
	for _, test := range []struct {
		name  string
		value []byte
	}{
		{name: "absent", value: nil},
		{name: "wrong outer tag", value: append([]byte{0x31}, valid[1:]...)},
		{name: "missing DN", value: pcacheEncodeBERElement(0x30, nil)},
		{name: "primitive DN tag", value: pcacheEncodeBERElement(0x30, pcacheEncodeBERElement(0x80, []byte(ldapBackendTestSuffix)))},
		{name: "short UUID", value: pcacheEncodeBERElement(0x30, badUUID)},
		{name: "trailing element", value: append(bytes.Clone(valid), 0x05, 0x00)},
		{name: "truncated", value: valid[:len(valid)-1]},
		{name: "non-minimal length", value: []byte{0x30, 0x81, 0x01, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodePcacheQueryDeleteRequest(test.value); err == nil {
				t.Fatal("malformed queryDelete was accepted")
			}
		})
	}

	validControl := ldapwire.Control{OID: pcachePrivateDBControl, Critical: true}
	if present, failure := parsePcachePrivateDBControl([]ldapwire.Control{validControl}); !present || failure != nil {
		t.Fatalf("valid private control = present %t, failure %#v", present, failure)
	}
	for _, test := range []struct {
		name     string
		controls []ldapwire.Control
	}{
		{name: "noncritical", controls: []ldapwire.Control{{OID: pcachePrivateDBControl}}},
		{name: "value present", controls: []ldapwire.Control{{OID: pcachePrivateDBControl, Critical: true, HasValue: true}}},
		{name: "duplicate", controls: []ldapwire.Control{validControl, validControl}},
	} {
		t.Run(test.name, func(t *testing.T) {
			present, failure := parsePcachePrivateDBControl(test.controls)
			if !present || failure == nil || failure.Code != ldapwire.ResultProtocolError {
				t.Fatalf("private control = present %t, failure %#v", present, failure)
			}
		})
	}
}

func TestPcachePrivateRootRestartAndQueryDelete(t *testing.T) {
	provider := startPcacheValidateProvider(t)
	provider.set(
		pcacheValidateProviderEntry("Cached"),
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	seedLDAPBackendProxy(t, store, provider.address())
	overlay := testPcacheOverlayForDatabase(ldapBackendTestDatabaseDN)
	overlay.Attributes = append(overlay.Attributes, directory.Attribute{
		Description: "olcPcachePersist",
		Values:      stringValues("TRUE"),
	})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(overlay, false)
	}); err != nil {
		t.Fatalf("store pcache overlay: %v", err)
	}

	firstServer, firstAddress, stopFirst := startPcacheBindWireServer(t, store)
	firstStopped := false
	defer func() {
		if !firstStopped {
			stopFirst()
		}
	}()
	root := dialLDAPBackendClient(t, firstAddress)
	if err := root.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(root): %v", err)
	}
	capabilities, err := root.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl", "supportedExtension"},
		nil,
	))
	if err != nil || len(capabilities.Entries) != 1 {
		t.Fatalf("Root DSE pcache capabilities = %#v, %v", capabilities, err)
	}
	if !stringSliceContains(
		capabilities.Entries[0].GetEqualFoldAttributeValues("supportedControl"),
		pcachePrivateDBControl,
	) || !stringSliceContains(
		capabilities.Entries[0].GetEqualFoldAttributeValues("supportedExtension"),
		pcacheQueryDeleteOID,
	) {
		t.Fatalf("Root DSE omits pcache capabilities: %#v", capabilities.Entries[0])
	}
	if result, err := root.Search(pcacheValidateSearchRequest()); err != nil || len(result.Entries) != 1 {
		t.Fatalf("populate pcache = %#v, %v", result, err)
	}
	privateDN, err := firstServer.runtime.Load().schema.NormalizeDN(ldapBackendTestUserDN)
	if err != nil {
		t.Fatal(err)
	}
	privateDatabase := databaseForDN(firstServer.runtime.Load(), privateDN)
	if privateDatabase == nil || privateDatabase.pcache == nil {
		t.Fatal("pcache runtime database is unavailable")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		privateEntries, ok := privateDatabase.pcache.state.privateEntries(
			firstServer.runtime.Load(),
			*privateDatabase,
			privateDatabase.pcache.persist,
		)
		if ok && len(privateEntries[privateDN.Key()].Values(pcacheQueryIDAttribute)) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pcache response-tail commit did not publish a private query ID")
		}
		time.Sleep(time.Millisecond)
	}

	privateControl := ldap.NewControlString(pcachePrivateDBControl, true, "")
	privateSearch := ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", pcacheQueryIDAttribute},
		[]ldap.Control{privateControl},
	)
	privateResult, err := root.Search(privateSearch)
	if err != nil || len(privateResult.Entries) != 1 {
		t.Fatalf("private root Search = %#v, %v", privateResult, err)
	}
	identifiers := privateResult.Entries[0].GetEqualFoldAttributeValues(pcacheQueryIDAttribute)
	if len(identifiers) != 1 {
		names := make([]string, 0, len(privateResult.Entries[0].Attributes))
		for _, attribute := range privateResult.Entries[0].Attributes {
			names = append(names, attribute.Name)
		}
		t.Fatalf("private query IDs = %q; attributes = %q", identifiers, names)
	}
	if _, err := uuid.Parse(identifiers[0]); err != nil {
		t.Fatalf("private query ID %q: %v", identifiers[0], err)
	}
	privateAdd := ldap.NewAddRequest(
		"uid=private-write,"+ldapBackendTestPeopleDN,
		[]ldap.Control{privateControl},
	)
	privateAdd.Attribute("objectClass", []string{"inetOrgPerson"})
	privateAdd.Attribute("uid", []string{"private-write"})
	privateAdd.Attribute("cn", []string{"Private Write"})
	privateAdd.Attribute("sn", []string{"Write"})
	if code := ldapBackendResultCode(root.Add(privateAdd)); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("private database Add result = %d", code)
	}

	urlResult, err := root.Search(ldap.NewSearchRequest(
		ldapBackendTestSuffix,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{pcacheQueryURLAttribute},
		[]ldap.Control{privateControl},
	))
	if err != nil || len(urlResult.Entries) != 1 {
		t.Fatalf("private query metadata Search = %#v, %v", urlResult, err)
	}
	urls := urlResult.Entries[0].GetEqualFoldAttributeValues(pcacheQueryURLAttribute)
	if len(urls) != 1 || !stringsContainAll(urls[0], "x-uuid="+identifiers[0], "x-attrset=0") {
		t.Fatalf("private query URLs = %q", urls)
	}

	anonymous := dialLDAPBackendClient(t, firstAddress)
	_, anonymousErr := anonymous.Search(privateSearch)
	anonymous.Close()
	if code := ldapBackendResultCode(anonymousErr); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("anonymous private Search = %d (%v)", code, anonymousErr)
	}

	raw := dialAndBindRawLDAP(
		t,
		firstAddress,
		ldapBackendTestLocalRootDN,
		ldapBackendTestLocalRootPW,
	)
	compareResponse := sendRawLDAPOperation(
		t,
		raw,
		2,
		rawDontUseCopyCompareRequest(
			ldapBackendTestUserDN,
			pcacheQueryIDAttribute,
			identifiers[0],
		),
		rawPcachePrivateControl(true, false),
	)
	assertRawLDAPResult(t, compareResponse, int64(ldap.LDAPResultCompareTrue))
	_ = raw.Close()
	root.Close()
	stopFirst()
	firstStopped = true

	provider.close()
	_, secondAddress, stopSecond := startPcacheBindWireServer(t, store)
	secondStopped := false
	defer func() {
		if !secondStopped {
			stopSecond()
		}
	}()
	restarted := dialLDAPBackendClient(t, secondAddress)
	if err := restarted.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(restarted root): %v", err)
	}
	if result, err := restarted.Search(pcacheValidateSearchRequest()); err != nil || len(result.Entries) != 1 {
		t.Fatalf("persisted cache hit = %#v, %v", result, err)
	}
	deleteValue, err := pcacheEncodeQueryDeleteRequest(
		pcacheQueryDeleteBaseTag,
		ldapBackendTestSuffix,
		identifiers[0],
	)
	if err != nil {
		t.Fatalf("encode queryDelete: %v", err)
	}
	deleteRequestValue := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		string(deleteValue),
		"requestValue",
	)
	if _, err := restarted.Extended(ldap.NewExtendedRequest(pcacheQueryDeleteOID, deleteRequestValue)); err != nil {
		t.Fatalf("queryDelete: %v", err)
	}
	restarted.Close()
	stopSecond()
	secondStopped = true

	_, thirdAddress, stopThird := startPcacheBindWireServer(t, store)
	defer stopThird()
	third := dialLDAPBackendClient(t, thirdAddress)
	defer third.Close()
	if err := third.Bind(ldapBackendTestLocalRootDN, ldapBackendTestLocalRootPW); err != nil {
		t.Fatalf("Bind(after delete): %v", err)
	}
	_, err = third.Search(pcacheValidateSearchRequest())
	if code := ldapBackendResultCode(err); code != ldap.LDAPResultUnavailable {
		t.Fatalf("deleted query survived restart = %d (%v)", code, err)
	}
}

func TestPcacheQueryDeleteCleansSharedContentAndMetadata(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		request    func(first, second string) pcacheQueryDeleteRequest
		wantFirst  bool
		wantSecond bool
	}{
		{
			name: "base UUID",
			request: func(first, _ string) pcacheQueryDeleteRequest {
				return pcacheQueryDeleteRequest{tag: pcacheQueryDeleteBaseTag, dn: []byte(ldapBackendTestSuffix), identifier: first}
			},
			wantSecond: true,
		},
		{
			name: "entry UUID",
			request: func(first, _ string) pcacheQueryDeleteRequest {
				return pcacheQueryDeleteRequest{tag: pcacheQueryDeleteDNTag, dn: []byte(ldapBackendTestUserDN), identifier: first}
			},
			wantSecond: true,
		},
		{
			name: "entry all queries",
			request: func(_, _ string) pcacheQueryDeleteRequest {
				return pcacheQueryDeleteRequest{tag: pcacheQueryDeleteDNTag, dn: []byte(ldapBackendTestUserDN)}
			},
		},
		{
			name: "entry wrong UUID",
			request: func(_, _ string) pcacheQueryDeleteRequest {
				return pcacheQueryDeleteRequest{tag: pcacheQueryDeleteDNTag, dn: []byte(ldapBackendTestUserDN), identifier: uuid.NewString()}
			},
			wantFirst:  true,
			wantSecond: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, database, state := newPcachePrivateTestRuntime(t)
			first := commitPcachePrivateTestQuery(
				t,
				state,
				"first",
				ldapBackendTestUserDN,
				"uid=bob,"+ldapBackendTestPeopleDN,
			)
			second := commitPcachePrivateTestQuery(
				t,
				state,
				"second",
				ldapBackendTestUserDN,
			)
			result := state.deleteQueryRequest(runtime, database, test.request(first, second))
			if result.Code != ldapwire.ResultSuccess {
				t.Fatalf("queryDelete result = %#v", result)
			}
			state.mu.Lock()
			_, hasFirst := state.queries["first"]
			_, hasSecond := state.queries["second"]
			state.mu.Unlock()
			if hasFirst != test.wantFirst || hasSecond != test.wantSecond {
				t.Fatalf("remaining queries first=%t second=%t", hasFirst, hasSecond)
			}
			entries, ok := state.privateEntries(runtime, database, true)
			if !ok {
				t.Fatal("privateEntries failed")
			}
			aliceDN, _ := runtime.schema.NormalizeDN(ldapBackendTestUserDN)
			bobDN, _ := runtime.schema.NormalizeDN("uid=bob," + ldapBackendTestPeopleDN)
			alice := entries[aliceDN.Key()]
			bob := entries[bobDN.Key()]
			wantAliceIDs := 0
			if test.wantFirst {
				wantAliceIDs++
			}
			if test.wantSecond {
				wantAliceIDs++
			}
			if got := len(alice.Values(pcacheQueryIDAttribute)); got != wantAliceIDs {
				t.Fatalf("Alice query IDs = %d, want %d", got, wantAliceIDs)
			}
			if _, present := entries[bobDN.Key()]; present != test.wantFirst ||
				(test.wantFirst && len(bob.Values(pcacheQueryIDAttribute)) != 1) {
				t.Fatalf("Bob private entry = %#v", bob)
			}
			suffix := database.suffixes[0]
			if got := len(entries[suffix.Key()].Values(pcacheQueryURLAttribute)); got != wantAliceIDs {
				t.Fatalf("query metadata values = %d, want %d", got, wantAliceIDs)
			}
		})
	}
}

func TestPcachePersistenceRollbackAndRetiredGeneration(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	runtime, database, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/test",
		fingerprint: "first-generation",
		enabled:     true,
	}
	identifier := commitPcachePrivateTestQuery(t, state, "first", ldapBackendTestUserDN)
	before := readPcacheTestMetadata(t, store, state.persistence.metadataKey)

	state.persistence.store = pcacheFailingMetadataStore{
		Store: store,
		err:   errors.New("injected metadata failure"),
	}
	result := state.deleteQueryRequest(
		runtime,
		database,
		pcacheQueryDeleteRequest{
			tag:        pcacheQueryDeleteBaseTag,
			dn:         []byte(ldapBackendTestSuffix),
			identifier: identifier,
		},
	)
	if result.Code != ldapwire.ResultOther {
		t.Fatalf("failed persistent delete result = %#v", result)
	}
	state.mu.Lock()
	_, retained := state.queries["first"]
	state.mu.Unlock()
	if !retained {
		t.Fatal("persistent delete failure did not roll back memory")
	}
	if after := readPcacheTestMetadata(t, store, state.persistence.metadataKey); !bytes.Equal(after, before) {
		t.Fatal("persistent delete failure changed stored metadata")
	}

	next := newPcacheState()
	next.persistence = &pcachePersistence{
		store:       store,
		metadataKey: state.persistence.metadataKey,
		fingerprint: "second-generation",
		enabled:     true,
	}
	next.mu.Lock()
	nextSnapshot, err := next.encodePersistedSnapshotLocked()
	next.mu.Unlock()
	if err != nil {
		t.Fatalf("encode next generation: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetMetadata(state.persistence.metadataKey, nextSnapshot)
	}); err != nil {
		t.Fatalf("publish next generation: %v", err)
	}
	state.persistence.store = store
	if commitPcachePrivateTestQueryIfAccepted(state, "stale", "uid=stale,"+ldapBackendTestPeopleDN) {
		t.Fatal("retired pcache generation overwrote current metadata")
	}
	state.mu.Lock()
	_, stale := state.queries["stale"]
	state.mu.Unlock()
	if stale {
		t.Fatal("retired pcache generation retained rejected mutation")
	}
	if current := readPcacheTestMetadata(t, store, state.persistence.metadataKey); !bytes.Equal(current, nextSnapshot) {
		t.Fatal("retired pcache generation changed current snapshot")
	}
}

func TestPcachePersistenceSlowStoreKeepsReadsAvailableAndSerializesMutations(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/slow-store",
		fingerprint: "slow-store",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	firstDone := make(chan bool, 1)
	go func() {
		firstDone <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"first",
			"uid=first,"+ldapBackendTestPeopleDN,
		)
	}()
	<-blocked.started

	readDone := make(chan bool, 1)
	go func() {
		_, baseFound, _ := state.lookup("base", state.clock(), false)
		_, candidateFound, _ := state.lookup("first", state.clock(), false)
		readDone <- baseFound && !candidateFound
	}()
	select {
	case valid := <-readDone:
		if !valid {
			t.Fatal("read observed an uncommitted persistence candidate")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow persistence blocked a cache read")
	}

	secondDone := make(chan bool, 1)
	go func() {
		secondDone <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"second",
			"uid=second,"+ldapBackendTestPeopleDN,
		)
	}()
	select {
	case <-secondDone:
		t.Fatal("concurrent mutation bypassed persistence serialization")
	case <-time.After(25 * time.Millisecond):
	}
	close(blocked.release)
	if !<-firstDone || !<-secondDone {
		t.Fatal("serialized persistence mutation failed")
	}

	state.mu.Lock()
	generation := state.generation
	queryCount := len(state.queries)
	state.mu.Unlock()
	if generation != 3 || queryCount != 3 {
		t.Fatalf("committed state = generation %d, %d queries", generation, queryCount)
	}
	snapshot := readPcacheTestSnapshot(t, store, state.persistence.metadataKey)
	if snapshot.Generation != generation || len(snapshot.Queries) != queryCount {
		t.Fatalf(
			"persisted state = generation %d, %d queries",
			snapshot.Generation,
			len(snapshot.Queries),
		)
	}
}

func TestPcachePersistenceFailureRollsBackBeforeNextMutation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/serialized-rollback",
		fingerprint: "serialized-rollback",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)

	injected := errors.New("injected first mutation failure")
	blocked := newPcacheBlockingMetadataStore(store, injected)
	state.persistence.store = blocked
	firstDone := make(chan bool, 1)
	go func() {
		firstDone <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"rejected",
			"uid=rejected,"+ldapBackendTestPeopleDN,
		)
	}()
	<-blocked.started
	secondDone := make(chan bool, 1)
	go func() {
		secondDone <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"accepted",
			"uid=accepted,"+ldapBackendTestPeopleDN,
		)
	}()
	close(blocked.release)
	if <-firstDone {
		t.Fatal("failed persistence mutation reported success")
	}
	if !<-secondDone {
		t.Fatal("mutation following a rollback failed")
	}

	state.mu.Lock()
	_, rejected := state.queries["rejected"]
	_, accepted := state.queries["accepted"]
	generation := state.generation
	state.mu.Unlock()
	if rejected || !accepted || generation != 2 {
		t.Fatalf(
			"rollback state = rejected %t, accepted %t, generation %d",
			rejected,
			accepted,
			generation,
		)
	}
	snapshot := readPcacheTestSnapshot(t, store, state.persistence.metadataKey)
	if snapshot.Generation != 2 || len(snapshot.Queries) != 2 {
		t.Fatalf("persisted rollback state = %#v", snapshot)
	}
}

func TestPcachePersistenceCancellationRollsBackAndReleasesSerializer(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/cancel",
		fingerprint: "cancel",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)
	before := readPcacheTestMetadata(t, store, state.persistence.metadataKey)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		done <- commitPcachePrivateTestQueryWithContext(
			ctx,
			state,
			"canceled",
			"uid=canceled,"+ldapBackendTestPeopleDN,
		)
	}()
	<-blocked.started
	cancel()
	if <-done {
		t.Fatal("canceled persistence mutation reported success")
	}

	state.mu.Lock()
	_, retained := state.queries["canceled"]
	generation := state.generation
	state.mu.Unlock()
	if retained || generation != 1 {
		t.Fatalf("canceled mutation state = retained %t, generation %d", retained, generation)
	}
	if after := readPcacheTestMetadata(t, store, state.persistence.metadataKey); !bytes.Equal(after, before) {
		t.Fatal("canceled mutation changed persisted metadata")
	}

	state.persistence.store = store
	if !commitPcachePrivateTestQueryWithContext(
		context.Background(),
		state,
		"after-cancel",
		"uid=after-cancel,"+ldapBackendTestPeopleDN,
	) {
		t.Fatal("cancellation did not release the persistence serializer")
	}
}

func TestPcachePersistenceCancellationWhileWaitingForSerializer(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/cancel-wait",
		fingerprint: "cancel-wait",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	firstDone := make(chan bool, 1)
	go func() {
		firstDone <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"first",
			"uid=first,"+ldapBackendTestPeopleDN,
		)
	}()
	<-blocked.started

	waitCtx, cancelWait := context.WithCancel(context.Background())
	secondDone := make(chan bool, 1)
	go func() {
		secondDone <- commitPcachePrivateTestQueryWithContext(
			waitCtx,
			state,
			"canceled-waiter",
			"uid=canceled-waiter,"+ldapBackendTestPeopleDN,
		)
	}()
	cancelWait()
	select {
	case accepted := <-secondDone:
		if accepted {
			t.Fatal("canceled serializer waiter reported success")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("canceled mutation remained blocked on the serializer")
	}
	close(blocked.release)
	if !<-firstDone {
		t.Fatal("active persistence mutation failed")
	}
	state.mu.Lock()
	_, retained := state.queries["canceled-waiter"]
	state.mu.Unlock()
	if retained {
		t.Fatal("canceled serializer waiter changed memory")
	}
}

func TestPcachePersistenceGenerationCASRejectsStaleCandidate(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/generation-cas",
		fingerprint: "generation-cas",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	done := make(chan bool, 1)
	go func() {
		done <- commitPcachePrivateTestQueryWithContext(
			context.Background(),
			state,
			"stale",
			"uid=stale,"+ldapBackendTestPeopleDN,
		)
	}()
	<-blocked.started

	newer := readPcacheTestSnapshot(t, store, state.persistence.metadataKey)
	newer.Generation += 100
	newerEncoded, err := json.Marshal(newer)
	if err != nil {
		t.Fatalf("encode newer generation: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.SetMetadata(state.persistence.metadataKey, newerEncoded)
	}); err != nil {
		t.Fatalf("publish newer generation: %v", err)
	}
	close(blocked.release)
	if <-done {
		t.Fatal("stale generation CAS reported success")
	}
	if !state.persistence.retired.Load() {
		t.Fatal("stale generation did not retire the persistence serializer")
	}

	state.mu.Lock()
	_, stale := state.queries["stale"]
	generation := state.generation
	state.mu.Unlock()
	if stale || generation != 1 {
		t.Fatalf("stale candidate state = retained %t, generation %d", stale, generation)
	}
	if current := readPcacheTestMetadata(t, store, state.persistence.metadataKey); !bytes.Equal(current, newerEncoded) {
		t.Fatal("stale candidate overwrote the newer persisted generation")
	}
}

func TestPcachePersistenceDisableAndReenableRetiresBlockedWriter(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	server := &Server{config: Config{Store: store}}
	const (
		configDN            = "cn=pcache-disable-race"
		enabledFingerprint  = "enabled-fingerprint"
		disabledFingerprint = "disabled-fingerprint"
	)
	metadataKey := pcachePersistenceMetadataKey(configDN)

	oldRuntime, oldDatabase, oldState := newPcachePrivateTestRuntime(t)
	configurePcachePersistenceTestRuntime(
		oldRuntime,
		&oldDatabase,
		oldState,
		store,
		configDN,
		metadataKey,
		enabledFingerprint,
		true,
	)
	ensurePcacheTestRuntime(t, server, store, oldRuntime)
	oldEpoch := oldState.persistence.epoch

	blocked := newPcacheBlockingMetadataStore(store, nil)
	oldState.persistence.store = blocked
	oldDone := make(chan bool, 1)
	go func() {
		oldDone <- oldState.mutate(
			context.Background(),
			func(candidate *pcacheState) (bool, bool) {
				candidate.generation++
				candidate.sequence++
				candidate.queries["stale-query"] = pcacheCachedQuery{
					response: pcacheSearchResponse{
						result: ldapwire.Result{Code: ldapwire.ResultSuccess},
					},
					replay: ldapwire.Message{Request: ldapwire.SearchRequest{
						BaseDN: ldapBackendTestSuffix,
						Scope:  directory.ScopeWholeSubtree,
						Filter: directory.Filter{
							Kind:      directory.FilterPresent,
							Attribute: "objectClass",
						},
					}},
					purgeAt:    time.Now().Add(time.Hour),
					lastUsed:   candidate.sequence,
					generation: candidate.generation,
				}
				candidate.binds["stale-bind"] = pcacheCachedBind{
					passwordHash: []byte("stale-password-hash"),
					purgeAt:      time.Now().Add(time.Hour),
					lastUsed:     candidate.sequence,
					generation:   candidate.generation,
				}
				candidate.entries++
				return true, true
			},
		)
	}()
	<-blocked.started

	disabledRuntime, disabledDatabase, disabledState := newPcachePrivateTestRuntime(t)
	configurePcachePersistenceTestRuntime(
		disabledRuntime,
		&disabledDatabase,
		disabledState,
		store,
		configDN,
		metadataKey,
		disabledFingerprint,
		false,
	)
	ensurePcacheTestRuntime(t, server, store, disabledRuntime)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		if _, err := reader.Metadata(metadataKey); !errors.Is(err, storage.ErrMetadataNotFound) {
			return fmt.Errorf("disabled snapshot lookup = %v", err)
		}
		guardRaw, err := reader.Metadata(pcachePersistenceGuardKey(metadataKey))
		if err != nil {
			return err
		}
		guard, err := decodePcachePersistenceGuard(guardRaw)
		if err != nil {
			return err
		}
		if !guard.Retired || guard.Epoch == oldEpoch {
			return fmt.Errorf("disabled persistence guard = %#v", guard)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	reenabledRuntime, reenabledDatabase, reenabledState := newPcachePrivateTestRuntime(t)
	configurePcachePersistenceTestRuntime(
		reenabledRuntime,
		&reenabledDatabase,
		reenabledState,
		store,
		configDN,
		metadataKey,
		enabledFingerprint,
		true,
	)
	ensurePcacheTestRuntime(t, server, store, reenabledRuntime)
	newEpoch := reenabledState.persistence.epoch
	if newEpoch == oldEpoch {
		t.Fatal("re-enabled persistence reused the retired epoch")
	}

	close(blocked.release)
	if <-oldDone {
		t.Fatal("blocked writer revived a retired persistence incarnation")
	}
	if !oldState.persistence.retired.Load() {
		t.Fatal("stale persistence serializer was not retired")
	}
	snapshot := readPcacheTestSnapshot(t, store, metadataKey)
	if snapshot.PersistenceEpoch != newEpoch || snapshot.Generation != 0 ||
		len(snapshot.Queries) != 0 || len(snapshot.Binds) != 0 {
		t.Fatalf("re-enabled persistence snapshot = %#v", snapshot)
	}

	restartedRuntime, restartedDatabase, restartedState := newPcachePrivateTestRuntime(t)
	restartedDatabase.pcache.configDNKey = configDN
	restartedDatabase.pcache.fingerprint = enabledFingerprint
	restartedDatabase.pcache.persist = true
	restartedRuntime.databases[0] = restartedDatabase
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		return server.preparePcachePersistence(reader, restartedRuntime)
	}); err != nil {
		t.Fatalf("restart persistence: %v", err)
	}
	restartedState.mu.Lock()
	restartedQueries := len(restartedState.queries)
	restartedBinds := len(restartedState.binds)
	restartedEpoch := restartedState.persistence.epoch
	restartedState.mu.Unlock()
	if restartedQueries != 0 || restartedBinds != 0 || restartedEpoch != newEpoch {
		t.Fatalf(
			"restarted state = %d queries, %d binds, epoch %q",
			restartedQueries,
			restartedBinds,
			restartedEpoch,
		)
	}
}

func TestPcachePersistenceDetachedMutationDoesNotHoldStateLock(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/detached-cow",
		fingerprint: "detached-cow",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "base", ldapBackendTestUserDN)

	mutationStarted := make(chan struct{})
	releaseMutation := make(chan struct{})
	mutationDone := make(chan bool, 1)
	go func() {
		mutationDone <- state.mutate(
			context.Background(),
			func(candidate *pcacheState) (bool, bool) {
				close(mutationStarted)
				<-releaseMutation
				candidate.generation++
				return true, true
			},
		)
	}()
	<-mutationStarted

	readDone := make(chan bool, 1)
	go func() {
		_, found, _ := state.lookup("base", state.clock(), false)
		readDone <- found
	}()
	select {
	case found := <-readDone:
		if !found {
			t.Fatal("detached mutation changed the committed read view")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("detached mutation callback held pcacheState.mu")
	}
	close(releaseMutation)
	if !<-mutationDone {
		t.Fatal("detached persistence mutation failed")
	}
}

func TestPcachePersistentValidationInvalidationDoesNotBlockRead(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	_, _, state := newPcachePrivateTestRuntime(t)
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/async-invalidation",
		fingerprint: "async-invalidation",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "invalid", ldapBackendTestUserDN)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		if _, found, refresh := state.lookupValidatedContext(
			context.Background(),
			"invalid",
			state.clock(),
			false,
			func(pcacheSearchResponse) bool { return false },
		); found || refresh != nil {
			t.Errorf("invalid persistent query remained visible: found=%t", found)
		}
	}()
	select {
	case <-readDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("persistent validation invalidation blocked its read")
	}
	<-blocked.started
	state.mu.Lock()
	_, retainedBeforeCommit := state.queries["invalid"]
	state.mu.Unlock()
	if !retainedBeforeCommit {
		t.Fatal("uncommitted validation invalidation became visible")
	}
	close(blocked.release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		state.mu.Lock()
		_, retained := state.queries["invalid"]
		pending := len(state.invalidationPending)
		state.mu.Unlock()
		if !retained && pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("persistent validation invalidation did not commit")
		}
		time.Sleep(time.Millisecond)
	}
	snapshot := readPcacheTestSnapshot(t, store, state.persistence.metadataKey)
	if snapshot.Generation != 2 || len(snapshot.Queries) != 0 {
		t.Fatalf("persisted invalidation state = %#v", snapshot)
	}
}

func TestPcachePrivatePersistentReadHidesExpiredQueriesWithoutStorage(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	runtime, database, state := newPcachePrivateTestRuntime(t)
	state.clock = func() time.Time { return now }
	state.epoch = now
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/private-expired",
		fingerprint: "private-expired",
		enabled:     true,
	}
	commitPcachePrivateTestQuery(t, state, "expired", ldapBackendTestUserDN)
	now = now.Add(2 * time.Hour)

	blocked := newPcacheBlockingMetadataStore(store, nil)
	state.persistence.store = blocked
	entries, ok := state.privateEntries(runtime, database, true)
	if !ok || len(entries) != 0 {
		t.Fatalf("expired private entries = %#v, available %t", entries, ok)
	}
	select {
	case <-blocked.started:
		t.Fatal("private read attempted persistent cleanup")
	default:
	}
}

func TestPcacheRefreshMaintainsPersistentQueryIdentifier(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	defer func() { _ = store.Close() }()
	now := time.Unix(1_700_000_000, 0)
	state := newPcacheStateWithClock(func() time.Time { return now })
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: "pcache/refresh-identifier",
		fingerprint: "refresh-identifier",
		enabled:     true,
	}
	policy := pcacheRefreshPolicy{
		positiveTTL: time.Hour,
		negativeTTL: time.Hour,
		ttr:         time.Minute,
		entryLimit:  10,
	}
	replay := ldapwire.Message{Request: ldapwire.SearchRequest{
		BaseDN: ldapBackendTestSuffix,
		Scope:  directory.ScopeWholeSubtree,
		Filter: directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
	}}
	if !state.commit(
		"refresh",
		pcacheSearchResponse{result: ldapwire.Result{Code: ldapwire.ResultSuccess}},
		replay,
		pcacheRemoteContext{},
		now,
		policy,
		100,
		100,
		false,
	) {
		t.Fatal("commit negative query failed")
	}

	refresh := beginPcacheIdentifierRefresh(t, state, "refresh", policy)
	positive := pcacheSearchResponse{
		items: []pcacheSearchItem{{entry: &directory.Entry{
			DN: ldapBackendTestUserDN,
			Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      stringValues("inetOrgPerson"),
			}},
		}}},
		result: ldapwire.Result{Code: ldapwire.ResultSuccess},
	}
	if !state.completeRefresh(refresh, positive, now.Add(time.Minute)) {
		t.Fatal("negative-to-positive refresh failed")
	}
	identifier := persistedPcacheIdentifier(t, store, state.persistence.metadataKey)
	if _, err := uuid.Parse(identifier); err != nil {
		t.Fatalf("positive refresh identifier %q: %v", identifier, err)
	}

	refresh = beginPcacheIdentifierRefresh(t, state, "refresh", policy)
	negative := pcacheSearchResponse{result: ldapwire.Result{Code: ldapwire.ResultSuccess}}
	if !state.completeRefresh(refresh, negative, now.Add(2*time.Minute)) {
		t.Fatal("positive-to-negative refresh failed")
	}
	if identifier := persistedPcacheIdentifier(t, store, state.persistence.metadataKey); identifier != "" {
		t.Fatalf("negative refresh retained identifier %q", identifier)
	}
}

func beginPcacheIdentifierRefresh(
	t *testing.T,
	state *pcacheState,
	key string,
	policy pcacheRefreshPolicy,
) pcacheRefreshLease {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	query, ok := state.queries[key]
	if !ok {
		t.Fatalf("pcache query %q is missing", key)
	}
	query.refreshing = true
	state.queries[key] = query
	return pcacheRefreshLease{key: key, generation: query.generation, policy: policy}
}

func persistedPcacheIdentifier(
	t *testing.T,
	store storage.Store,
	key string,
) string {
	t.Helper()
	raw := readPcacheTestMetadata(t, store, key)
	var snapshot pcachePersistedSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode persisted pcache snapshot: %v", err)
	}
	if len(snapshot.Queries) != 1 {
		t.Fatalf("persisted pcache queries = %d, want 1", len(snapshot.Queries))
	}
	return snapshot.Queries[0].Identifier
}

func TestPcachePrivateConcurrentReadAndDelete(t *testing.T) {
	runtime, database, state := newPcachePrivateTestRuntime(t)
	identifiers := make([]string, 64)
	for index := range identifiers {
		identifiers[index] = commitPcachePrivateTestQuery(
			t,
			state,
			fmt.Sprintf("query-%d", index),
			fmt.Sprintf("uid=user-%d,%s", index, ldapBackendTestPeopleDN),
		)
	}

	start := make(chan struct{})
	errors := make(chan string, 8)
	var wait sync.WaitGroup
	for reader := 0; reader < 4; reader++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				if _, ok := state.privateEntries(runtime, database, true); !ok {
					errors <- "privateEntries failed"
					return
				}
			}
		}()
	}
	for worker := 0; worker < 4; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for index := worker; index < len(identifiers); index += 4 {
				result := state.deleteQueryRequest(runtime, database, pcacheQueryDeleteRequest{
					tag:        pcacheQueryDeleteBaseTag,
					dn:         []byte(ldapBackendTestSuffix),
					identifier: identifiers[index],
				})
				if result.Code != ldapwire.ResultSuccess {
					errors <- fmt.Sprintf("queryDelete result %d", result.Code)
					return
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for message := range errors {
		t.Error(message)
	}
	state.mu.Lock()
	remaining := len(state.queries)
	state.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("concurrent queryDelete left %d queries", remaining)
	}
}

func newPcachePrivateTestRuntime(
	t *testing.T,
) (*runtimeState, runtimeDatabase, *pcacheState) {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	suffix, err := registry.NormalizeDN(ldapBackendTestSuffix)
	if err != nil {
		t.Fatalf("NormalizeDN(suffix): %v", err)
	}
	root, err := registry.NormalizeDN(ldapBackendTestLocalRootDN)
	if err != nil {
		t.Fatalf("NormalizeDN(root): %v", err)
	}
	state := newPcacheState()
	database := runtimeDatabase{
		name:         "pcache-test",
		suffixes:     []directory.DN{suffix},
		dnNormalizer: registry,
		rootDN:       &root,
		pcache: &pcacheRuntimeConfiguration{
			persist: true,
			state:   state,
		},
	}
	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{database},
	}
	return runtime, database, state
}

func configurePcachePersistenceTestRuntime(
	runtime *runtimeState,
	database *runtimeDatabase,
	state *pcacheState,
	store storage.Store,
	configDN string,
	metadataKey string,
	fingerprint string,
	enabled bool,
) {
	database.pcache.configDNKey = configDN
	database.pcache.fingerprint = fingerprint
	database.pcache.persist = enabled
	state.persistence = &pcachePersistence{
		store:       store,
		metadataKey: metadataKey,
		fingerprint: fingerprint,
		enabled:     enabled,
	}
	runtime.databases[0] = *database
}

func ensurePcacheTestRuntime(
	t *testing.T,
	server *Server,
	store storage.Store,
	runtime *runtimeState,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return server.ensurePcachePersistence(writer, runtime)
	}); err != nil {
		t.Fatalf("ensure pcache persistence: %v", err)
	}
}

func commitPcachePrivateTestQuery(
	t *testing.T,
	state *pcacheState,
	key string,
	dns ...string,
) string {
	t.Helper()
	if !commitPcachePrivateTestQueryIfAccepted(state, key, dns...) {
		t.Fatalf("commit pcache query %q was rejected", key)
	}
	state.mu.Lock()
	identifier := state.queries[key].identifier
	state.mu.Unlock()
	if _, err := uuid.Parse(identifier); err != nil {
		t.Fatalf("query %q identifier %q: %v", key, identifier, err)
	}
	return identifier
}

func commitPcachePrivateTestQueryIfAccepted(
	state *pcacheState,
	key string,
	dns ...string,
) bool {
	return commitPcachePrivateTestQueryWithContext(
		context.Background(),
		state,
		key,
		dns...,
	)
}

func commitPcachePrivateTestQueryWithContext(
	ctx context.Context,
	state *pcacheState,
	key string,
	dns ...string,
) bool {
	items := make([]pcacheSearchItem, 0, len(dns))
	for _, dn := range dns {
		entry := directory.Entry{
			DN: dn,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top")},
				{Description: "uid", Values: stringValues("cached")},
			},
		}
		items = append(items, pcacheSearchItem{entry: &entry})
	}
	request := ldapwire.SearchRequest{
		BaseDN:     ldapBackendTestSuffix,
		Scope:      directory.ScopeWholeSubtree,
		Filter:     directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
		Attributes: []string{"uid"},
	}
	return state.commitContext(
		ctx,
		key,
		pcacheSearchResponse{
			items:  items,
			result: ldapwire.Result{Code: ldapwire.ResultSuccess},
		},
		ldapwire.Message{Request: request},
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
	)
}

func rawPcachePrivateControl(critical, hasValue bool) *ber.Packet {
	control := ber.NewSequence("pcache private database control")
	control.AppendChild(rawOctetString([]byte(pcachePrivateDBControl)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if hasValue {
		control.AppendChild(rawOctetString(nil))
	}
	return control
}

func stringsContainAll(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !bytes.Contains([]byte(value), []byte(fragment)) {
			return false
		}
	}
	return true
}

func stringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type pcacheFailingMetadataStore struct {
	storage.Store
	err error
}

type pcacheBlockingMetadataStore struct {
	storage.Store
	started chan struct{}
	release chan struct{}
	fail    error

	mu    sync.Mutex
	calls int
}

func newPcacheBlockingMetadataStore(
	store storage.Store,
	fail error,
) *pcacheBlockingMetadataStore {
	return &pcacheBlockingMetadataStore{
		Store:   store,
		started: make(chan struct{}),
		release: make(chan struct{}),
		fail:    fail,
	}
}

func (store *pcacheBlockingMetadataStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	store.mu.Lock()
	store.calls++
	call := store.calls
	if call == 1 {
		close(store.started)
	}
	store.mu.Unlock()
	if call == 1 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-store.release:
		}
		if store.fail != nil {
			return store.fail
		}
	}
	return store.Store.Update(ctx, update)
}

func (store pcacheFailingMetadataStore) Update(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return update(pcacheFailingMetadataWriter{Writer: writer, err: store.err})
	})
}

type pcacheFailingMetadataWriter struct {
	storage.Writer
	err error
}

func (writer pcacheFailingMetadataWriter) SetMetadata(string, []byte) error {
	return writer.err
}

func readPcacheTestMetadata(
	t *testing.T,
	store storage.Store,
	key string,
) []byte {
	t.Helper()
	var value []byte
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		value, err = reader.Metadata(key)
		return err
	}); err != nil {
		t.Fatalf("read metadata %q: %v", key, err)
	}
	return value
}

func readPcacheTestSnapshot(
	t *testing.T,
	store storage.Store,
	key string,
) pcachePersistedSnapshot {
	t.Helper()
	raw := readPcacheTestMetadata(t, store, key)
	var snapshot pcachePersistedSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode persisted pcache snapshot: %v", err)
	}
	return snapshot
}
