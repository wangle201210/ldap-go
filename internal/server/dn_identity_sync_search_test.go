package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncSearchExactOID = "1.3.6.1.4.1.99999.922.1"
	syncSearchFoldOID  = "1.3.6.1.4.1.99999.922.2"
	syncSearchBaseDN   = "dc=example,dc=com"
	syncSearchPeopleDN = "ou=People," + syncSearchBaseDN
)

func TestDNIdentitySyncSearchRFC4533(t *testing.T) {
	backends := []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			t.Helper()
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
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			instance, runtime := newDNIdentitySyncSearchServer(t, store)

			t.Run("base_change", func(t *testing.T) {
				testDNIdentitySyncSearchBaseChange(t, runtime)
			})
			t.Run("scope", func(t *testing.T) {
				testDNIdentitySyncSearchScope(t, runtime)
			})
			t.Run("present_delete", func(t *testing.T) {
				testDNIdentitySyncSearchPresentDelete(t, instance, runtime, store)
			})
		})
	}
}

func testDNIdentitySyncSearchBaseChange(t *testing.T, runtime *runtimeState) {
	multiBase := "syncExactName=Alice+syncFoldName=Research," + syncSearchPeopleDN
	multiEquivalent := syncSearchFoldOID + "= RESEARCH +syncExactAlias=Alice,OU=PEOPLE,DC=EXAMPLE,DC=COM"

	tests := []struct {
		name       string
		base       string
		before     string
		after      string
		hasAfter   bool
		wantChange bool
	}{
		{
			name:       "caseExact base deletion",
			base:       "syncExactName=Alice," + syncSearchPeopleDN,
			before:     "syncExactAlias=Alice," + syncSearchPeopleDN,
			wantChange: true,
		},
		{
			name:       "caseExact sibling deletion",
			base:       "syncExactName=Alice," + syncSearchPeopleDN,
			before:     "syncExactAlias=alice," + syncSearchPeopleDN,
			wantChange: false,
		},
		{
			name:       "caseIgnore equivalent base deletion",
			base:       "syncFoldName=Alice Smith," + syncSearchPeopleDN,
			before:     "syncFoldAlias= ALICE  SMITH ,OU=PEOPLE,DC=EXAMPLE,DC=COM",
			wantChange: true,
		},
		{
			name:       "attribute alias OID and multiAVA retain base",
			base:       multiBase,
			before:     multiEquivalent,
			after:      "syncExactName=Alice+syncFoldAlias=research," + syncSearchPeopleDN,
			hasAfter:   true,
			wantChange: false,
		},
		{
			name:       "multiAVA equivalent base deletion",
			base:       multiBase,
			before:     multiEquivalent,
			wantChange: true,
		},
		{
			name:       "ancestor deletion changes base",
			base:       multiBase,
			before:     syncSearchPeopleDN,
			wantChange: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			syncSearch := &syncSearchContext{routes: []syncSearchRoute{{
				partition: "sync-search",
				base:      mustLegacyDNIdentitySyncSearchDN(t, test.base),
				scope:     directory.ScopeWholeSubtree,
			}}}
			change := syncChange{
				partition: "sync-search",
				before:    dnIdentitySyncSearchEntry(test.before, 1),
				hasBefore: true,
				hasAfter:  test.hasAfter,
			}
			if test.hasAfter {
				change.after = dnIdentitySyncSearchEntry(test.after, 1)
			}
			changed, err := syncSearchBaseChanged(runtime, syncSearch, change)
			if err != nil {
				t.Fatalf("syncSearchBaseChanged(): %v", err)
			}
			if changed != test.wantChange {
				t.Fatalf("syncSearchBaseChanged() = %t, want %t", changed, test.wantChange)
			}
		})
	}
}

func testDNIdentitySyncSearchScope(t *testing.T, runtime *runtimeState) {
	multiBase := "syncExactName=Alice+syncFoldName=Research," + syncSearchPeopleDN
	multiEquivalent := syncSearchFoldOID + "=research+syncExactAlias=Alice,OU=PEOPLE,DC=EXAMPLE,DC=COM"

	tests := []struct {
		name    string
		base    string
		scope   directory.Scope
		entryDN string
		want    bool
	}{
		{
			name:    "caseExact alias exact value",
			base:    "syncExactName=Alice," + syncSearchPeopleDN,
			scope:   directory.ScopeBase,
			entryDN: "syncExactAlias=Alice," + syncSearchPeopleDN,
			want:    true,
		},
		{
			name:    "caseExact different value",
			base:    "syncExactName=Alice," + syncSearchPeopleDN,
			scope:   directory.ScopeBase,
			entryDN: "syncExactAlias=alice," + syncSearchPeopleDN,
			want:    false,
		},
		{
			name:    "caseIgnore equivalent value",
			base:    "syncFoldName=Alice Smith," + syncSearchPeopleDN,
			scope:   directory.ScopeBase,
			entryDN: "syncFoldAlias= ALICE  SMITH ,OU=PEOPLE,DC=EXAMPLE,DC=COM",
			want:    true,
		},
		{
			name:    "attribute alias OID and multiAVA",
			base:    multiBase,
			scope:   directory.ScopeBase,
			entryDN: multiEquivalent,
			want:    true,
		},
		{
			name:    "one level equivalent multiAVA parent",
			base:    multiBase,
			scope:   directory.ScopeSingleLevel,
			entryDN: "cn=Child," + multiEquivalent,
			want:    true,
		},
		{
			name:    "one level rejects grandchild",
			base:    multiBase,
			scope:   directory.ScopeSingleLevel,
			entryDN: "uid=Grandchild,cn=Child," + multiEquivalent,
			want:    false,
		},
		{
			name:    "subtree accepts grandchild",
			base:    multiBase,
			scope:   directory.ScopeWholeSubtree,
			entryDN: "uid=Grandchild,cn=Child," + multiEquivalent,
			want:    true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			syncSearch := &syncSearchContext{routes: []syncSearchRoute{{
				partition:     "sync-search",
				databaseIndex: 0,
				base:          mustLegacyDNIdentitySyncSearchDN(t, test.base),
				scope:         test.scope,
			}}}
			index, err := syncSearchDatabaseIndexForEntry(
				runtime,
				syncSearch,
				"sync-search",
				test.entryDN,
			)
			if err != nil {
				t.Fatalf("syncSearchDatabaseIndexForEntry(): %v", err)
			}
			if got := index == 0; got != test.want {
				t.Fatalf("route matched = %t, want %t (index %d)", got, test.want, index)
			}
		})
	}
}

func testDNIdentitySyncSearchPresentDelete(
	t *testing.T,
	server *Server,
	runtime *runtimeState,
	store storage.Store,
) {
	entries := []directory.Entry{
		dnIdentitySyncSearchEntry(
			"syncExactAlias=Alice+syncFoldAlias=Research,"+syncSearchPeopleDN,
			1,
		),
		dnIdentitySyncSearchEntry(
			"syncExactAlias=alice+syncFoldAlias=Research,"+syncSearchPeopleDN,
			2,
		),
		dnIdentitySyncSearchEntry(
			"cn=Fold Child,syncFoldAlias=Alice Smith,"+syncSearchPeopleDN,
			3,
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, runtime.databases[0])
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed Sync search entries: %v", err)
	}

	request := ldapwire.SearchRequest{
		Scope:      directory.ScopeWholeSubtree,
		Filter:     directory.Filter{Kind: directory.FilterPresent, Attribute: "objectClass"},
		Attributes: []string{"cn"},
	}
	multiBase := "syncExactName=Alice+syncFoldName=Research," + syncSearchPeopleDN
	multiEquivalent := syncSearchFoldOID + "= RESEARCH +" + syncSearchExactOID + "=Alice,OU=PEOPLE,DC=EXAMPLE,DC=COM"

	t.Run("present uses aliases OIDs and multiAVA identity", func(t *testing.T) {
		syncSearch := dnIdentitySyncSearchContext(t, multiBase, directory.ScopeBase)
		entry := readDNIdentitySyncSearchEntry(t, store, runtime, multiEquivalent)
		var (
			uuid    ldapwire.SyncUUID
			matched bool
		)
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			var err error
			_, uuid, matched, err = server.syncEventEntry(
				runtime,
				"",
				request,
				syncSearch,
				reader,
				"sync-search",
				entry,
			)
			if err != nil {
				return err
			}
			return err
		}); err != nil {
			t.Fatalf("syncEventEntry(present): %v", err)
		}
		if !matched || uuid != dnIdentitySyncSearchUUID(1) {
			t.Fatalf("present route = matched %t, UUID %x", matched, uuid)
		}
	})

	t.Run("present keeps caseExact sibling outside base scope", func(t *testing.T) {
		syncSearch := dnIdentitySyncSearchContext(t, multiBase, directory.ScopeBase)
		entry := readDNIdentitySyncSearchEntry(
			t,
			store,
			runtime,
			"syncExactName=alice+syncFoldName=research,"+syncSearchPeopleDN,
		)
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			_, _, matched, err := server.syncEventEntry(
				runtime,
				"",
				request,
				syncSearch,
				reader,
				"sync-search",
				entry,
			)
			if err == nil && matched {
				t.Fatal("caseExact sibling entered present route")
			}
			return err
		}); err != nil {
			t.Fatalf("syncEventEntry(caseExact sibling): %v", err)
		}
	})

	t.Run("delete uses caseIgnore equivalent parent", func(t *testing.T) {
		syncSearch := dnIdentitySyncSearchContext(
			t,
			"syncFoldName= ALICE  SMITH ,"+syncSearchPeopleDN,
			directory.ScopeWholeSubtree,
		)
		before := readDNIdentitySyncSearchEntry(
			t,
			store,
			runtime,
			"cn=Fold Child,"+syncSearchFoldOID+"=alice smith,OU=PEOPLE,DC=EXAMPLE,DC=COM",
		)
		entry, state, uuid, emitted, err := server.syncChangeResponse(
			context.Background(),
			&connectionState{runtime: runtime},
			request,
			syncSearch,
			syncChange{
				partition: "sync-search",
				before:    before,
				hasBefore: true,
			},
		)
		if err != nil {
			t.Fatalf("syncChangeResponse(delete): %v", err)
		}
		if !emitted || state != ldapwire.SyncStateDelete ||
			uuid != dnIdentitySyncSearchUUID(3) || entry.DN != before.DN {
			t.Fatalf(
				"delete route = entry %q, state %d, UUID %x, emitted %t",
				entry.DN,
				state,
				uuid,
				emitted,
			)
		}
	})

	t.Run("delete excludes caseExact sibling", func(t *testing.T) {
		syncSearch := dnIdentitySyncSearchContext(t, multiBase, directory.ScopeWholeSubtree)
		before := readDNIdentitySyncSearchEntry(
			t,
			store,
			runtime,
			"syncExactName=alice+syncFoldName=research,"+syncSearchPeopleDN,
		)
		_, _, _, emitted, err := server.syncChangeResponse(
			context.Background(),
			&connectionState{runtime: runtime},
			request,
			syncSearch,
			syncChange{
				partition: "sync-search",
				before:    before,
				hasBefore: true,
			},
		)
		if err != nil {
			t.Fatalf("syncChangeResponse(caseExact sibling): %v", err)
		}
		if emitted {
			t.Fatal("caseExact sibling emitted a delete event")
		}
	})
}

func newDNIdentitySyncSearchServer(
	t *testing.T,
	store storage.Store,
) (*Server, *runtimeState) {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, description := range []string{
		"( " + syncSearchExactOID + " NAME ( 'syncExactName' 'syncExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( " + syncSearchFoldOID + " NAME ( 'syncFoldName' 'syncFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	} {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(): %v", err)
		}
	}
	suffix := mustDNIdentitySyncSearchDN(t, registry, syncSearchBaseDN)
	runtime := &runtimeState{
		schema: registry,
		access: acl.DefaultPolicy(),
		databases: []runtimeDatabase{{
			name:         "mdb",
			partition:    "sync-search",
			suffixes:     []directory.DN{suffix},
			dnNormalizer: registry,
			syncProvider: true,
		}},
	}
	server := &Server{config: Config{Store: store}}
	server.runtime.Store(runtime)
	return server, runtime
}

func dnIdentitySyncSearchContext(
	t *testing.T,
	base string,
	scope directory.Scope,
) *syncSearchContext {
	t.Helper()
	return &syncSearchContext{
		manageDsaIT: true,
		routes: []syncSearchRoute{{
			partition:     "sync-search",
			databaseIndex: 0,
			base:          mustLegacyDNIdentitySyncSearchDN(t, base),
			scope:         scope,
		}},
	}
}

func dnIdentitySyncSearchEntry(dn string, id byte) directory.Entry {
	return directory.Entry{DN: dn, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues("top")},
		{Description: "cn", Values: stringValues("Sync Entry")},
		{Description: "entryUUID", Values: stringValues(dnIdentitySyncSearchUUIDString(id))},
	}}
}

func readDNIdentitySyncSearchEntry(
	t *testing.T,
	store storage.Store,
	runtime *runtimeState,
	rawDN string,
) directory.Entry {
	t.Helper()
	dn := mustDNIdentitySyncSearchDN(t, runtime.schema, rawDN)
	var entry directory.Entry
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		entry, err = readerForDatabase(reader, runtime.databases[0]).Get(dn)
		return err
	}); err != nil {
		t.Fatalf("read Sync search entry %q: %v", rawDN, err)
	}
	return entry
}

func dnIdentitySyncSearchUUID(id byte) ldapwire.SyncUUID {
	var value ldapwire.SyncUUID
	value[len(value)-1] = id
	return value
}

func dnIdentitySyncSearchUUIDString(id byte) string {
	const digits = "0123456789abcdef"
	return "00000000-0000-0000-0000-0000000000" +
		string([]byte{digits[id>>4], digits[id&0x0f]})
}

func mustDNIdentitySyncSearchDN(
	t *testing.T,
	normalizer directory.DNAttributeNormalizer,
	rawDN string,
) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(rawDN, normalizer)
	if err != nil {
		t.Fatalf("ParseDNWithNormalizer(%q): %v", rawDN, err)
	}
	return dn
}

func mustLegacyDNIdentitySyncSearchDN(t *testing.T, rawDN string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	return dn
}
