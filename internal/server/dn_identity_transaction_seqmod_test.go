package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentitySeqmodSerialization(t *testing.T) {
	runtime, database, frontend := newDNIdentitySeqmodRuntime(t)

	upper := mustDNIdentitySeqmodDN(t, "exactName=Alice,dc=example,dc=com")
	lower := mustDNIdentitySeqmodDN(t, "exactName=alice,dc=example,dc=com")
	upperRelease, err := acquireDatabaseSeqmod(context.Background(), *database, upper)
	if err != nil {
		t.Fatalf("acquire upper caseExact lock: %v", err)
	}
	lowerRelease, err := acquireDatabaseSeqmod(context.Background(), *database, lower)
	if err != nil {
		upperRelease()
		t.Fatalf("caseExact sibling shared upper lock: %v", err)
	}
	if len(database.seqmod.coordinator.queues) != 2 {
		t.Fatalf("caseExact queue identities = %d, want 2", len(database.seqmod.coordinator.queues))
	}
	lowerRelease()
	upperRelease()

	folded := mustDNIdentitySeqmodDN(t, "foldName=Alice Smith,dc=example,dc=com")
	equivalent := mustDNIdentitySeqmodDN(
		t,
		"foldName=\\20ALICE\\20\\20SMITH\\20,DC=EXAMPLE,DC=COM",
	)
	firstRelease, err := acquireDatabaseSeqmod(context.Background(), *database, folded)
	if err != nil {
		t.Fatalf("acquire caseIgnore lock: %v", err)
	}
	type acquisition struct {
		release func()
		err     error
	}
	done := make(chan acquisition, 1)
	go func() {
		release, acquireErr := acquireDatabaseSeqmod(
			context.Background(),
			*database,
			equivalent,
		)
		done <- acquisition{release: release, err: acquireErr}
	}()
	waitForSeqmodQueueLength(
		t,
		database.seqmod.coordinator,
		mustNormalizeSeqmodKey(t, runtime.schema, folded),
		2,
	)
	select {
	case result := <-done:
		if result.release != nil {
			result.release()
		}
		firstRelease()
		t.Fatalf("caseIgnore-equivalent lock did not wait: %v", result.err)
	case <-time.After(25 * time.Millisecond):
	}
	firstRelease()
	result := <-done
	if result.err != nil {
		t.Fatalf("acquire equivalent caseIgnore lock: %v", result.err)
	}
	result.release()

	operations := []ldapTransactionOperation{
		{message: ldapwire.Message{Request: ldapwire.ModifyRequest{DN: upper.String()}}},
		{message: ldapwire.Message{Request: ldapwire.ModifyRequest{DN: lower.String()}}},
	}
	ctx, release, err := acquireLDAPTransactionSeqmods(
		context.Background(),
		runtime,
		operations,
	)
	if err != nil {
		t.Fatalf("acquire caseExact transaction locks: %v", err)
	}
	assertDNIdentityHeldSeqmodLocks(t, ctx, 4)
	release()

	operations = []ldapTransactionOperation{
		{message: ldapwire.Message{Request: ldapwire.ModifyRequest{DN: folded.String()}}},
		{message: ldapwire.Message{Request: ldapwire.ModifyRequest{DN: equivalent.String()}}},
	}
	ctx, release, err = acquireLDAPTransactionSeqmods(
		context.Background(),
		runtime,
		operations,
	)
	if err != nil {
		t.Fatalf("acquire caseIgnore transaction locks: %v", err)
	}
	assertDNIdentityHeldSeqmodLocks(t, ctx, 2)
	release()

	ctx, release, err = acquireLDAPTransactionSeqmods(
		context.Background(),
		runtime,
		[]ldapTransactionOperation{{message: ldapwire.Message{
			Request: ldapwire.ModifyDNRequest{
				DN:           upper.String(),
				NewRDN:       "exactName=Renamed",
				DeleteOldRDN: true,
			},
		}}},
	)
	if err != nil {
		t.Fatalf("acquire ModifyDN transaction locks: %v", err)
	}
	assertDNIdentityHeldSeqmodLocks(t, ctx, 4)
	release()

	_ = frontend
}

func TestDNIdentityLDAPTransactionAtomicity(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	}
	for _, backend := range backends {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			t.Run("commit preserves caseExact siblings", func(t *testing.T) {
				store, address := startDNIdentityTransactionServer(t, backend.open)
				connection := dialAndBindRawLDAP(
					t, address, "cn=admin,dc=example,dc=com", "admin-secret",
				)
				defer connection.Close()
				identifier := startRawLDAPTransaction(t, connection, 2)
				assertRawLDAPResult(t, sendRawLDAPOperation(
					t, connection, 3,
					rawModifyDNRequest(
						"exactName=Alice,dc=example,dc=com",
						"exactName=Renamed",
						true,
					),
					rawTransactionSpecificationControl(identifier, true, true),
				), int64(ldapwire.ResultSuccess))
				assertRawLDAPResult(t, sendRawLDAPOperation(
					t, connection, 4,
					rawModifyReplaceRequest(
						"exactName=alice,dc=example,dc=com",
						"cn",
						"Exact Lower Committed",
					),
					rawTransactionSpecificationControl(identifier, true, true),
				), int64(ldapwire.ResultSuccess))
				assertRawLDAPResult(
					t,
					endRawLDAPTransaction(t, connection, 5, true, identifier),
					int64(ldapwire.ResultSuccess),
				)
				assertDNIdentityTransactionEntry(
					t, store, "exactName=Renamed,dc=example,dc=com", "Exact Upper",
				)
				assertDNIdentityTransactionEntry(
					t, store, "exactName=alice,dc=example,dc=com", "Exact Lower Committed",
				)
			})

			t.Run("failure rolls back caseExact sibling update", func(t *testing.T) {
				store, address := startDNIdentityTransactionServer(t, backend.open)
				connection := dialAndBindRawLDAP(
					t, address, "cn=admin,dc=example,dc=com", "admin-secret",
				)
				defer connection.Close()
				identifier := startRawLDAPTransaction(t, connection, 2)
				assertRawLDAPResult(t, sendRawLDAPOperation(
					t, connection, 3,
					rawModifyReplaceRequest(
						"exactName=alice,dc=example,dc=com",
						"cn",
						"Must Roll Back",
					),
					rawTransactionSpecificationControl(identifier, true, true),
				), int64(ldapwire.ResultSuccess))
				assertRawLDAPResult(t, sendRawLDAPOperation(
					t, connection, 4,
					rawModifyDNRequest(
						"exactName=Alice,dc=example,dc=com",
						"exactName=alice",
						true,
					),
					rawTransactionSpecificationControl(identifier, true, true),
				), int64(ldapwire.ResultSuccess))
				assertRawLDAPResult(
					t,
					endRawLDAPTransaction(t, connection, 5, true, identifier),
					int64(ldapwire.ResultEntryAlreadyExists),
				)
				assertDNIdentityTransactionEntry(
					t, store, "exactName=Alice,dc=example,dc=com", "Exact Upper",
				)
				assertDNIdentityTransactionEntry(
					t, store, "exactName=alice,dc=example,dc=com", "Exact Lower",
				)
			})
		})
	}
}

func newDNIdentitySeqmodRuntime(
	t *testing.T,
) (*runtimeState, *runtimeDatabase, *seqmodRuntimeConfiguration) {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.924.1 NAME 'exactName' EQUALITY caseExactMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.924.2 NAME 'foldName' EQUALITY caseIgnoreMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register DN attribute: %v", err)
		}
	}
	suffix, err := registry.NormalizeDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("normalize suffix: %v", err)
	}
	frontend := &seqmodRuntimeConfiguration{
		configDNKey: "frontend",
		coordinator: newSeqmodCoordinator(),
	}
	runtime := &runtimeState{
		schema: registry,
		databases: []runtimeDatabase{
			{name: "{-1}frontend", seqmod: frontend},
			{
				name:         "{1}mdb",
				partition:    "dn-identity-transaction",
				suffixes:     []directory.DN{suffix},
				dnNormalizer: registry,
				seqmod: &seqmodRuntimeConfiguration{
					configDNKey: "database",
					coordinator: newSeqmodCoordinator(),
				},
			},
		},
	}
	return runtime, &runtime.databases[1], frontend
}

func mustDNIdentitySeqmodDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}

func mustNormalizeSeqmodKey(
	t *testing.T,
	registry *schema.Registry,
	dn directory.DN,
) string {
	t.Helper()
	normalized, err := registry.NormalizeDN(dn.String())
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", dn.String(), err)
	}
	return normalized.NormalizedString()
}

func assertDNIdentityHeldSeqmodLocks(t *testing.T, ctx context.Context, want int) {
	t.Helper()
	held, ok := ctx.Value(seqmodHeldContextKey{}).(map[seqmodHeldLock]struct{})
	if !ok || len(held) != want {
		t.Fatalf("held seqmod locks = %d, %t; want %d", len(held), ok, want)
	}
}

func startDNIdentityTransactionServer(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) (storage.Store, string) {
	t.Helper()
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	config := dnIdentityRuntimeConfigLDIF + `
dn: olcOverlay={0}seqmod,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
olcOverlay: {0}seqmod

`
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(config),
		migration.ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(cn=config): %v", err)
	}
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(dnIdentityRuntimeContentLDIF),
		migration.ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(content): %v", err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return store, address
}

func assertDNIdentityTransactionEntry(
	t *testing.T,
	store storage.Store,
	rawDN string,
	wantCN string,
) {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.914.1 NAME 'exactName' EQUALITY caseExactMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.914.2 NAME 'foldName' EQUALITY caseIgnoreMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register DN attribute: %v", err)
		}
	}
	dn, err := registry.NormalizeDN(rawDN)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", rawDN, err)
	}
	var entry directory.Entry
	err = store.View(context.Background(), func(reader storage.Reader) error {
		reader = storage.ReaderInPartitionWithNormalizer(
			reader,
			configuredDatabasePartition("{1}mdb"),
			registry,
		)
		var readErr error
		entry, readErr = reader.Get(dn)
		return readErr
	})
	if err != nil {
		t.Fatalf("read transaction entry %q: %v", rawDN, err)
	}
	if got := string(entry.Values("cn")[0]); got != wantCN {
		t.Fatalf("%s cn = %q, want %q", rawDN, got, wantCN)
	}
}
