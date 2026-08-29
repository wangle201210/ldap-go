package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	seqmodFrontendDatabaseDN = "olcDatabase={-1}frontend,cn=config"
	seqmodFrontendOverlayDN  = "olcOverlay={0}seqmod," + seqmodFrontendDatabaseDN
	seqmodDatabaseOverlayDN  = "olcOverlay={0}seqmod,olcDatabase={1}mdb,cn=config"
)

func TestSeqmodRuntimeConfigurationParsing(t *testing.T) {
	t.Parallel()

	valid := seqmodOverlayEntry(seqmodDatabaseOverlayDN, "{0}seqmod")
	entryDN, err := directory.ParseDN(valid.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	configuration, err := loadSeqmodRuntimeConfiguration(valid, entryDN)
	if err != nil {
		t.Fatalf("loadSeqmodRuntimeConfiguration(): %v", err)
	}
	if configuration.configDNKey != entryDN.Key() || configuration.disabled ||
		configuration.coordinator == nil {
		t.Fatalf("configuration = %#v", configuration)
	}

	disabled := valid.Clone()
	disabled.ReplaceValues("olcDisabled", stringValues("TRUE"))
	configuration, err = loadSeqmodRuntimeConfiguration(disabled, entryDN)
	if err != nil || !configuration.disabled {
		t.Fatalf("disabled configuration = %#v, error = %v", configuration, err)
	}

	tests := []struct {
		name  string
		entry directory.Entry
		code  ldapwire.ResultCode
	}{
		{
			name:  "unordered attribute value",
			entry: seqmodOverlayEntry(seqmodDatabaseOverlayDN, "seqmod"),
			code:  ldapwire.ResultConstraintViolation,
		},
		{
			name: "unordered RDN",
			entry: seqmodOverlayEntry(
				"olcOverlay=seqmod,olcDatabase={1}mdb,cn=config",
				"{0}seqmod",
			),
			code: ldapwire.ResultNamingViolation,
		},
		{
			name:  "ordering mismatch",
			entry: seqmodOverlayEntry(seqmodDatabaseOverlayDN, "{1}seqmod"),
			code:  ldapwire.ResultNamingViolation,
		},
		{
			name: "private attribute",
			entry: func() directory.Entry {
				candidate := valid.Clone()
				candidate.ReplaceValues("olcSeqmodQueueLimit", stringValues("1"))
				return candidate
			}(),
			code: ldapwire.ResultUndefinedAttributeType,
		},
		{
			name: "invalid disabled",
			entry: func() directory.Entry {
				candidate := valid.Clone()
				candidate.ReplaceValues("olcDisabled", stringValues("sometimes"))
				return candidate
			}(),
			code: ldapwire.ResultConstraintViolation,
		},
		{
			name: "multiple disabled values",
			entry: func() directory.Entry {
				candidate := valid.Clone()
				candidate.ReplaceValues("olcDisabled", stringValues("TRUE", "FALSE"))
				return candidate
			}(),
			code: ldapwire.ResultConstraintViolation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dn, parseErr := directory.ParseDN(test.entry.DN)
			if parseErr != nil {
				t.Fatalf("ParseDN(): %v", parseErr)
			}
			_, loadErr := loadSeqmodRuntimeConfiguration(test.entry, dn)
			result, ok := seqmodConfigurationResult(loadErr)
			if !ok || result.Code != test.code {
				t.Fatalf("configuration error = %v, result = %#v", loadErr, result)
			}
		})
	}
}

func TestSeqmodRuntimeInstancesAndCoordinatorReuse(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSeqmodDirectory(t, store, true, true, false)
	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	frontend := seqmodRuntimeDatabase(t, databases, "frontend")
	data := seqmodRuntimeDatabase(t, databases, "mdb")
	if frontend.seqmod == nil || data.seqmod == nil {
		t.Fatalf("seqmod configurations: frontend=%#v data=%#v", frontend.seqmod, data.seqmod)
	}
	if frontend.seqmod.coordinator == data.seqmod.coordinator {
		t.Fatal("frontend and database overlays share a coordinator")
	}

	previous := &runtimeState{databases: databases}
	nextDatabases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("reload runtime databases: %v", err)
	}
	next := &runtimeState{databases: nextDatabases}
	reuseSeqmodCoordinators(previous, next)
	nextFrontend := seqmodRuntimeDatabase(t, next.databases, "frontend")
	nextData := seqmodRuntimeDatabase(t, next.databases, "mdb")
	if nextFrontend.seqmod.coordinator != frontend.seqmod.coordinator ||
		nextData.seqmod.coordinator != data.seqmod.coordinator {
		t.Fatal("configuration reload replaced a live seqmod coordinator")
	}
}

func TestSeqmodOnlineLifecycleRollbackAndRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	putSeqmodFrontendDatabase(t, store)

	instance, address, stop := startSeqmodServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	configClient := bindUniqueClient(t, address, "cn=config", "config-secret")

	if err := configClient.Add(seqmodLDAPAddRequest(seqmodDatabaseOverlayDN)); err != nil {
		t.Fatalf("Add(database seqmod): %v", err)
	}
	first := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod
	if first == nil || first.disabled {
		t.Fatalf("online database seqmod = %#v", first)
	}

	duplicateDN := "olcOverlay={1}seqmod,olcDatabase={1}mdb,cn=config"
	assertLDAPResultCode(
		t,
		configClient.Add(seqmodLDAPAddRequest(duplicateDN)),
		ldap.LDAPResultOther,
	)
	if seqmodStoredEntryExists(t, store, duplicateDN) {
		t.Fatal("duplicate seqmod overlay survived rollback")
	}

	invalid := ldap.NewModifyRequest(seqmodDatabaseOverlayDN, nil)
	invalid.Add("olcSeqmodQueueLimit", []string{"1"})
	assertLDAPResultCode(t, configClient.Modify(invalid), ldap.LDAPResultUndefinedAttributeType)
	if readStoredEntry(t, store, seqmodDatabaseOverlayDN).HasAttribute("olcSeqmodQueueLimit") {
		t.Fatal("invalid seqmod attribute survived rollback")
	}

	disable := ldap.NewModifyRequest(seqmodDatabaseOverlayDN, nil)
	disable.Replace("olcDisabled", []string{"TRUE"})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable seqmod: %v", err)
	}
	disabled := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod
	if disabled == nil || !disabled.disabled || disabled.coordinator != first.coordinator {
		t.Fatalf("disabled seqmod = %#v", disabled)
	}
	alice, _ := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	release, err := first.coordinator.acquire(context.Background(), alice.Key())
	if err != nil {
		t.Fatalf("pre-acquire disabled database coordinator: %v", err)
	}
	client := dialLDAPRoot(t, address)
	modifyWhileDisabled := ldap.NewModifyRequest(alice.String(), nil)
	modifyWhileDisabled.Replace("description", []string{"disabled bypass"})
	assertSeqmodOperationCompletes(t, func() error {
		return client.Modify(modifyWhileDisabled)
	})
	client.Close()
	if got := seqmodQueueLength(first.coordinator, alice.Key()); got != 1 {
		t.Fatalf("disabled database queue length = %d, want held item only", got)
	}
	release()

	enable := ldap.NewModifyRequest(seqmodDatabaseOverlayDN, nil)
	enable.Replace("olcDisabled", []string{"FALSE"})
	if err := configClient.Modify(enable); err != nil {
		t.Fatalf("enable seqmod: %v", err)
	}
	enabled := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod
	if enabled == nil || enabled.disabled || enabled.coordinator != first.coordinator {
		t.Fatalf("re-enabled seqmod = %#v", enabled)
	}

	if err := configClient.Add(seqmodLDAPAddRequest(seqmodFrontendOverlayDN)); err != nil {
		t.Fatalf("Add(frontend seqmod): %v", err)
	}
	if seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "frontend").seqmod == nil {
		t.Fatal("online frontend seqmod was not activated")
	}

	if err := configClient.Del(ldap.NewDelRequest(seqmodDatabaseOverlayDN, nil)); err != nil {
		t.Fatalf("Delete(database seqmod): %v", err)
	}
	if seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod != nil {
		t.Fatal("deleted database seqmod remains active")
	}
	if err := configClient.Add(seqmodLDAPAddRequest(seqmodDatabaseOverlayDN)); err != nil {
		t.Fatalf("re-add database seqmod: %v", err)
	}

	configClient.Close()
	stop()
	instance, address, stop = startSeqmodServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	if seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "frontend").seqmod == nil ||
		seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod == nil {
		t.Fatal("seqmod configuration was not restored after restart")
	}
	client = dialLDAPRoot(t, address)
	defer client.Close()
	modify := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=com", nil)
	modify.Replace("description", []string{"after restart"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify after seqmod restart: %v", err)
	}
}

func TestSeqmodOperationBoundaries(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSeqmodDirectory(t, store, true, true, true)
	instance, address, stop := startSeqmodServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	frontend := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "frontend").seqmod
	data := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod
	if frontend == nil || data == nil {
		t.Fatal("seqmod overlays were not loaded")
	}
	alice, _ := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")

	t.Run("Modify waits on database and normalizes DN", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		release, err := data.coordinator.acquire(context.Background(), alice.Key())
		if err != nil {
			t.Fatalf("pre-acquire database seqmod: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			request := ldap.NewModifyRequest(
				"UID=Alice,OU=People,DC=Example,DC=Com",
				nil,
			)
			request.Replace("description", []string{"serialized"})
			done <- client.Modify(request)
		}()
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 2)
		assertSeqmodStillWaiting(t, done)
		release()
		assertSeqmodCompletes(t, done)
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 0)
	})

	t.Run("Modify waits on frontend before database", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		release, err := frontend.coordinator.acquire(context.Background(), alice.Key())
		if err != nil {
			t.Fatalf("pre-acquire frontend seqmod: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			request := ldap.NewModifyRequest(alice.String(), nil)
			request.Replace("description", []string{"global serialized"})
			done <- client.Modify(request)
		}()
		waitForSeqmodQueueLength(t, frontend.coordinator, alice.Key(), 2)
		if got := seqmodQueueLength(data.coordinator, alice.Key()); got != 0 {
			t.Fatalf("database queue length = %d before frontend release", got)
		}
		release()
		assertSeqmodCompletes(t, done)
	})

	t.Run("Add and Delete bypass both instances", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		target, _ := directory.ParseDN("uid=seqmod-bypass,ou=people,dc=example,dc=com")
		releaseFrontend, err := frontend.coordinator.acquire(context.Background(), target.Key())
		if err != nil {
			t.Fatalf("pre-acquire frontend: %v", err)
		}
		defer releaseFrontend()
		releaseDatabase, err := data.coordinator.acquire(context.Background(), target.Key())
		if err != nil {
			t.Fatalf("pre-acquire database: %v", err)
		}
		defer releaseDatabase()

		assertSeqmodOperationCompletes(t, func() error {
			return client.Add(newPersonAddRequest("seqmod-bypass"))
		})
		assertSeqmodOperationCompletes(t, func() error {
			return client.Del(ldap.NewDelRequest(target.String(), nil))
		})
		if got := seqmodQueueLength(frontend.coordinator, target.Key()); got != 1 {
			t.Fatalf("frontend queue length = %d, want held item only", got)
		}
		if got := seqmodQueueLength(data.coordinator, target.Key()); got != 1 {
			t.Fatalf("database queue length = %d, want held item only", got)
		}
	})

	t.Run("ModifyDN keys only the old DN", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		if err := client.Add(newPersonAddRequest("seqmod-rename")); err != nil {
			t.Fatalf("Add(rename source): %v", err)
		}
		oldDN, _ := directory.ParseDN("uid=seqmod-rename,ou=people,dc=example,dc=com")
		newDN, _ := directory.ParseDN("uid=seqmod-renamed,ou=people,dc=example,dc=com")
		releaseFrontend, _ := frontend.coordinator.acquire(context.Background(), newDN.Key())
		releaseDatabase, _ := data.coordinator.acquire(context.Background(), newDN.Key())
		assertSeqmodOperationCompletes(t, func() error {
			return client.ModifyDN(ldap.NewModifyDNRequest(
				oldDN.String(),
				"uid=seqmod-renamed",
				true,
				"",
			))
		})
		releaseDatabase()
		releaseFrontend()

		releaseOld, err := data.coordinator.acquire(context.Background(), newDN.Key())
		if err != nil {
			t.Fatalf("pre-acquire old DN: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			done <- client.ModifyDN(ldap.NewModifyDNRequest(
				newDN.String(),
				"uid=seqmod-rename",
				true,
				"",
			))
		}()
		waitForSeqmodQueueLength(t, data.coordinator, newDN.Key(), 2)
		assertSeqmodStillWaiting(t, done)
		releaseOld()
		assertSeqmodCompletes(t, done)
	})

	t.Run("Password Modify is database-only", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		releaseFrontend, _ := frontend.coordinator.acquire(context.Background(), alice.Key())
		assertSeqmodOperationCompletes(t, func() error {
			_, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
				alice.String(),
				"",
				"seqmod-password-one",
			))
			return err
		})
		releaseFrontend()

		releaseDatabase, _ := data.coordinator.acquire(context.Background(), alice.Key())
		done := make(chan error, 1)
		go func() {
			_, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
				alice.String(),
				"",
				"seqmod-password-two",
			))
			done <- err
		}()
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 2)
		assertSeqmodStillWaiting(t, done)
		releaseDatabase()
		assertSeqmodCompletes(t, done)
	})

	t.Run("Dynamic Refresh is database-only", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		dynamicDN := "cn=seqmod-refresh,ou=people,dc=example,dc=com"
		if err := client.Add(newDynamicRoleAddRequest(dynamicDN, "seqmod-refresh")); err != nil {
			t.Fatalf("Add(dynamic object): %v", err)
		}
		dynamic, _ := directory.ParseDN(dynamicDN)
		releaseFrontend, _ := frontend.coordinator.acquire(context.Background(), dynamic.Key())
		assertSeqmodOperationCompletes(t, func() error {
			_, err := requestDynamicRefresh(client, dynamicDN, 60)
			return err
		})
		releaseFrontend()

		releaseDatabase, _ := data.coordinator.acquire(context.Background(), dynamic.Key())
		done := make(chan error, 1)
		go func() {
			_, err := requestDynamicRefresh(client, dynamicDN, 120)
			done <- err
		}()
		waitForSeqmodQueueLength(t, data.coordinator, dynamic.Key(), 2)
		assertSeqmodStillWaiting(t, done)
		releaseDatabase()
		assertSeqmodCompletes(t, done)
	})

	t.Run("connection cancellation removes waiter", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		release, _ := data.coordinator.acquire(context.Background(), alice.Key())
		done := make(chan error, 1)
		go func() {
			request := ldap.NewModifyRequest(alice.String(), nil)
			request.Replace("description", []string{"canceled waiter"})
			done <- client.Modify(request)
		}()
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 2)
		client.Close()
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 1)
		release()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled Modify unexpectedly succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("canceled Modify did not return")
		}
	})

	t.Run("explicit Abandon removes active update waiter", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			syncTestRootDN,
			syncTestRootPassword,
		)
		defer connection.Close()
		release, _ := data.coordinator.acquire(context.Background(), alice.Key())
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawModifyReplaceRequest(
				alice.String(),
				"description",
				"explicitly abandoned update",
			),
			nil,
		)
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 2)
		writeRawLDAPRequest(t, connection, 3, rawAbandonRequest(2), nil)
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 1)
		assertLDAPConnectionHasNoResponse(t, connection)
		release()
		entry := readStoredEntry(t, store, alice.String())
		for _, value := range entry.Values("description") {
			if string(value) == "explicitly abandoned update" {
				t.Fatal("abandoned Modify was committed")
			}
		}
	})

	t.Run("RFC 3909 Cancel removes active update waiter", func(t *testing.T) {
		connection := dialAndBindRawLDAP(
			t,
			address,
			syncTestRootDN,
			syncTestRootPassword,
		)
		defer connection.Close()
		release, _ := data.coordinator.acquire(context.Background(), alice.Key())
		writeRawLDAPRequest(
			t,
			connection,
			2,
			rawModifyReplaceRequest(
				alice.String(),
				"description",
				"RFC 3909 canceled update",
			),
			nil,
		)
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 2)
		writeRawLDAPRequest(
			t,
			connection,
			3,
			rawExtendedRequest(
				cancelOID,
				ldapwire.EncodeCancelRequestValue(2),
				true,
			),
			nil,
		)
		updateResponse := readRawLDAPPacket(t, connection)
		assertRawLDAPEnvelope(
			t,
			updateResponse,
			2,
			ldapwire.ApplicationModifyResponse,
			int64(ldap.LDAPResultCanceled),
		)
		cancelResponse := readRawLDAPPacket(t, connection)
		assertRawLDAPEnvelope(
			t,
			cancelResponse,
			3,
			ldapwire.ApplicationExtendedResponse,
			int64(ldap.LDAPResultSuccess),
		)
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 1)
		release()
		entry := readStoredEntry(t, store, alice.String())
		for _, value := range entry.Values("description") {
			if string(value) == "RFC 3909 canceled update" {
				t.Fatal("canceled Modify was committed")
			}
		}
	})

	t.Run("downstream failure releases both instances", func(t *testing.T) {
		client := dialLDAPRoot(t, address)
		defer client.Close()
		request := ldap.NewModifyRequest(alice.String(), nil)
		request.Delete("description", []string{"value-that-does-not-exist"})
		assertLDAPResultCode(t, client.Modify(request), ldap.LDAPResultNoSuchAttribute)
		waitForSeqmodQueueLength(t, frontend.coordinator, alice.Key(), 0)
		waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 0)
	})

}

func TestLDAPTransactionSeqmodLockOrderDoesNotInvertStorageLock(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSeqmodDirectory(t, store, true, true, false)
	instance, address, stop := startSeqmodServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	frontend := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "frontend").seqmod
	data := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "mdb").seqmod
	alice, _ := directory.ParseDN(aliceDN)

	transactionConnection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer transactionConnection.Close()
	identifier := startRawLDAPTransaction(t, transactionConnection, 2)
	queued := sendRawLDAPOperation(
		t,
		transactionConnection,
		3,
		rawModifyReplaceRequest(aliceDN, "description", "transaction update"),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, queued, int64(ldap.LDAPResultSuccess))

	storageLocked := make(chan struct{})
	releaseStorage := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseStorage) }) }
	defer release()
	storageDone := make(chan error, 1)
	go func() {
		storageDone <- store.Update(context.Background(), func(storage.Writer) error {
			close(storageLocked)
			<-releaseStorage
			return nil
		})
	}()
	select {
	case <-storageLocked:
	case <-time.After(time.Second):
		t.Fatal("test storage lock was not acquired")
	}

	commitDone := make(chan *ber.Packet, 1)
	go func() {
		commitDone <- endRawLDAPTransaction(
			t,
			transactionConnection,
			4,
			true,
			identifier,
		)
	}()
	waitForSeqmodQueueLength(t, frontend.coordinator, alice.Key(), 1)
	waitForSeqmodQueueLength(t, data.coordinator, alice.Key(), 1)

	ordinary := dialLDAPRoot(t, address)
	defer ordinary.Close()
	ordinaryDone := make(chan error, 1)
	go func() {
		request := ldap.NewModifyRequest(aliceDN, nil)
		request.Replace("description", []string{"ordinary update"})
		ordinaryDone <- ordinary.Modify(request)
	}()
	waitForSeqmodQueueLength(t, frontend.coordinator, alice.Key(), 2)
	release()

	select {
	case err := <-storageDone:
		if err != nil {
			t.Fatalf("release test storage lock: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("test storage lock did not release")
	}
	select {
	case response := <-commitDone:
		assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	case <-time.After(2 * time.Second):
		t.Fatal("transaction commit deadlocked with ordinary seqmod write")
	}
	select {
	case err := <-ordinaryDone:
		if err != nil {
			t.Fatalf("ordinary Modify after transaction: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary seqmod write did not complete after transaction")
	}
}

func TestLDAPTransactionSeqmodUnknownNamingContextPreservesResult(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSeqmodDirectory(t, store, true, true, false)
	instance, _, stop := startSeqmodServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	frontend := seqmodRuntimeDatabase(t, instance.runtime.Load().databases, "frontend").seqmod

	unknownDN := "uid=outside,dc=outside"
	target, _ := directory.ParseDN(unknownDN)
	ctx, release, err := acquireLDAPTransactionSeqmods(
		context.Background(),
		instance.runtime.Load(),
		[]ldapTransactionOperation{{
			message: ldapwire.Message{
				ID:      3,
				Request: ldapwire.ModifyRequest{DN: unknownDN},
			},
		}},
	)
	if err != nil {
		t.Fatalf("acquireLDAPTransactionSeqmods(): %v", err)
	}
	held, ok := ctx.Value(seqmodHeldContextKey{}).(map[seqmodHeldLock]struct{})
	wantLock := seqmodHeldLock{
		coordinator: frontend.coordinator,
		targetKey:   target.Key(),
	}
	if !ok {
		t.Fatal("transaction seqmod context has no held-lock set")
	}
	if _, ok := held[wantLock]; !ok || len(held) != 1 {
		t.Fatalf("transaction seqmod locks = %#v, want only frontend lock", held)
	}
	waitForSeqmodQueueLength(t, frontend.coordinator, target.Key(), 1)
	release()
	waitForSeqmodQueueLength(t, frontend.coordinator, target.Key(), 0)
}

func seqmodOverlayEntry(dn, value string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
			{Description: "olcOverlay", Values: stringValues(value)},
		},
	}
}

func seqmodLDAPAddRequest(dn string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"olcOverlayConfig"})
	rdn, _ := directory.ParseDN(dn)
	request.Attribute("olcOverlay", []string{string(rdn.RDNValues()[0].Value)})
	return request
}

func seedSeqmodDirectory(
	t *testing.T,
	store storage.Store,
	frontend,
	database,
	dds bool,
) {
	t.Helper()
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if frontend {
			if err := writer.Put(directory.Entry{
				DN: seqmodFrontendDatabaseDN,
				Attributes: []directory.Attribute{{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				}},
			}, false); err != nil {
				return err
			}
			if err := writer.Put(
				seqmodOverlayEntry(seqmodFrontendOverlayDN, "{0}seqmod"),
				false,
			); err != nil {
				return err
			}
		}
		if database {
			if err := writer.Put(
				seqmodOverlayEntry(seqmodDatabaseOverlayDN, "{0}seqmod"),
				false,
			); err != nil {
				return err
			}
		}
		if dds {
			return writer.Put(directory.Entry{
				DN: "olcOverlay={1}dds,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
					{Description: "olcOverlay", Values: stringValues("{1}dds")},
					{Description: "olcDDSmaxTtl", Values: stringValues("1d")},
				},
			}, false)
		}
		return nil
	}); err != nil {
		t.Fatalf("seed seqmod configuration: %v", err)
	}
}

func putSeqmodFrontendDatabase(t *testing.T, store storage.Store) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: seqmodFrontendDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed frontend database: %v", err)
	}
}

func seqmodRuntimeDatabase(
	t *testing.T,
	databases []runtimeDatabase,
	typeName string,
) runtimeDatabase {
	t.Helper()
	for _, database := range databases {
		if databaseType(database.name) == typeName {
			return database
		}
	}
	t.Fatalf("runtime database %q not found", typeName)
	return runtimeDatabase{}
}

func seqmodStoredEntryExists(t *testing.T, store storage.Store, rawDN string) bool {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	found := false
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		if err == nil {
			found = true
			return nil
		}
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatalf("read %q: %v", rawDN, err)
	}
	return found
}

func startSeqmodServer(
	t *testing.T,
	store storage.Store,
	config Config,
) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	config.Store = store
	instance, err := New(config)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("seqmod server did not stop")
		}
	}
	return instance, fmt.Sprint(listener.Addr()), stop
}

func assertSeqmodOperationCompletes(t *testing.T, operation func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- operation() }()
	assertSeqmodCompletes(t, done)
}

func assertSeqmodCompletes(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("LDAP operation failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LDAP operation did not complete")
	}
}

func assertSeqmodStillWaiting(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("LDAP operation completed while seqmod was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func seqmodQueueLength(coordinator *seqmodCoordinator, key string) int {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return len(coordinator.queues[key])
}
