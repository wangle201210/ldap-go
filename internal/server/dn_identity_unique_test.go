package server

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityUniqueExactOID = "1.3.6.1.4.1.99999.940.1"
	dnIdentityUniqueFoldOID  = "1.3.6.1.4.1.99999.940.2"
	dnIdentityUniqueSuffix   = "dc=example,dc=com"
	dnIdentityUniqueBase     = "uniqueExactName=Tenant+uniqueFoldName=People," +
		dnIdentityUniqueSuffix
	dnIdentityUniqueBaseEquivalent = dnIdentityUniqueFoldOID +
		"=PEOPLE+uniqueExactAlias=Tenant,DC=EXAMPLE,DC=COM"
)

func TestDNIdentityUniqueOverlay(t *testing.T) {
	for _, backend := range dnIdentityUniqueBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			instance, runtime, database := newDNIdentityUniqueRuntime(t, store)

			t.Run("URI base alias OID and multiAVA", func(t *testing.T) {
				uriBase := database.unique.domains[0].uris[0].base
				if uriBase == nil {
					t.Fatal("unique URI has no base")
				}
				canonical := mustDNIdentityUniqueDN(t, runtime.schema, dnIdentityUniqueBase)
				if !uriBase.Equal(canonical) {
					t.Fatalf("unique URI base = %q, want identity %q", uriBase, canonical)
				}
				if database.unique.domains[0].serializeMu == nil {
					t.Fatal("serialize domain has no runtime mutex")
				}
			})

			t.Run("Add duplicate and caseExact base isolation", func(t *testing.T) {
				candidate := dnIdentityUniqueEntry(
					"uniqueExactAlias=Carol,"+dnIdentityUniqueBaseEquivalent,
					"Carol",
					"shared value",
				)
				err := viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueAdd(
						runtime, reader, "", database, candidate, false,
					)
				})
				assertDNIdentityUniqueConstraint(t, err)

				outsideExactBase := dnIdentityUniqueEntry(
					"uniqueExactName=Carol,uniqueExactName=tenant+"+
						"uniqueFoldAlias=PEOPLE,"+dnIdentityUniqueSuffix,
					"Carol",
					"shared value",
				)
				err = viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueAdd(
						runtime, reader, "", database, outsideExactBase, false,
					)
				})
				if err != nil {
					t.Fatalf("Add under caseExact-different base: %v", err)
				}

				exactCaseVariant := dnIdentityUniqueEntry(
					"uniqueExactName=ALICE,"+dnIdentityUniqueBase,
					"ALICE",
					"Fresh Value",
				)
				err = viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueAdd(
						runtime, reader, "", database, exactCaseVariant, false,
					)
				})
				if err != nil {
					t.Fatalf("Add caseExact value variant: %v", err)
				}
			})

			t.Run("Modify self and caseExact sibling", func(t *testing.T) {
				upperEquivalent := dnIdentityUniqueExactOID +
					"=Alice," + dnIdentityUniqueBaseEquivalent
				self := dnIdentityUniqueEntry(upperEquivalent, "Alice", "Shared Value")
				selfChange := []ldapwire.Modification{{
					Operation: ldapwire.ModificationReplace,
					Attribute: directory.Attribute{
						Description: dnIdentityUniqueFoldOID,
						Values:      stringValues("  SHARED   VALUE  "),
					},
				}}
				err := viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueModify(
						runtime, reader, "", database, self, selfChange, false,
					)
				})
				if err != nil {
					t.Fatalf("Modify schema-equivalent self: %v", err)
				}

				lower := dnIdentityUniqueEntry(
					"uniqueExactName=alice,"+dnIdentityUniqueBase,
					"alice",
					"Sibling Value",
				)
				duplicateChange := []ldapwire.Modification{{
					Operation: ldapwire.ModificationReplace,
					Attribute: directory.Attribute{
						Description: "uniqueFoldAlias",
						Values:      stringValues("shared value"),
					},
				}}
				err = viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueModify(
						runtime, reader, "", database, lower, duplicateChange, false,
					)
				})
				assertDNIdentityUniqueConstraint(t, err)
			})

			t.Run("ModifyDN self and caseExact sibling", func(t *testing.T) {
				upperEquivalent := dnIdentityUniqueExactOID +
					"=Alice," + dnIdentityUniqueBaseEquivalent
				upper := dnIdentityUniqueEntry(upperEquivalent, "Alice", "Shared Value")
				selfRDN := []directory.Attribute{
					{Description: dnIdentityUniqueExactOID, Values: stringValues("Alice")},
					{Description: "uniqueFoldAlias", Values: stringValues("shared value")},
				}
				err := viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueModifyDN(
						runtime, reader, "", database, upper, nil, selfRDN, false,
					)
				})
				if err != nil {
					t.Fatalf("ModifyDN schema-equivalent multiAVA self: %v", err)
				}

				lower := dnIdentityUniqueEntry(
					"uniqueExactName=alice,"+dnIdentityUniqueBase,
					"alice",
					"Sibling Value",
				)
				err = viewDNIdentityUnique(t, store, func(reader storage.Reader) error {
					return instance.validateUniqueModifyDN(
						runtime,
						reader,
						"",
						database,
						lower,
						nil,
						[]directory.Attribute{{
							Description: "uniqueExactAlias",
							Values:      stringValues("Alice"),
						}},
						false,
					)
				})
				assertDNIdentityUniqueConstraint(t, err)
			})
		})
	}
}

func TestDNIdentityUniqueSerializeConcurrent(t *testing.T) {
	for _, backend := range dnIdentityUniqueBackends() {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			store := backend.open(t)
			t.Cleanup(func() { _ = store.Close() })
			instance, runtime, database := newDNIdentityUniqueRuntime(t, store)

			const workers = 12
			start := make(chan struct{})
			results := make(chan error, workers)
			var wait sync.WaitGroup
			for index := 0; index < workers; index++ {
				index := index
				wait.Add(1)
				go func() {
					defer wait.Done()
					<-start
					parent := dnIdentityUniqueBase
					namingAttribute := "uniqueExactName"
					sharedValue := " Serialized Shared "
					if index%2 != 0 {
						parent = dnIdentityUniqueBaseEquivalent
						namingAttribute = dnIdentityUniqueExactOID
						sharedValue = "SERIALIZED   SHARED"
					}
					entry := dnIdentityUniqueEntry(
						fmt.Sprintf("%s=Concurrent-%d,%s", namingAttribute, index, parent),
						fmt.Sprintf("Concurrent-%d", index),
						sharedValue,
					)
					if index%2 != 0 {
						entry.Attributes[1].Description = "uniqueFoldAlias"
					}
					results <- store.Update(context.Background(), func(writer storage.Writer) error {
						if err := instance.validateUniqueAdd(
							runtime, writer, "", database, entry, false,
						); err != nil {
							return err
						}
						return writerForDatabase(writer, database).Put(entry, false)
					})
				}()
			}
			close(start)
			wait.Wait()
			close(results)

			successes := 0
			constraints := 0
			for err := range results {
				switch failure := asOperationFailure(err); {
				case err == nil:
					successes++
				case failure != nil && failure.result.Code == ldapwire.ResultConstraintViolation:
					constraints++
				default:
					t.Fatalf("concurrent unique Add: %v", err)
				}
			}
			if successes != 1 || constraints != workers-1 {
				t.Fatalf(
					"concurrent unique results: success=%d constraint=%d",
					successes,
					constraints,
				)
			}
		})
	}
}

type dnIdentityUniqueBackend struct {
	name string
	open func(*testing.T) storage.Store
}

func dnIdentityUniqueBackends() []dnIdentityUniqueBackend {
	return []dnIdentityUniqueBackend{
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
}

func newDNIdentityUniqueRuntime(
	t *testing.T,
	store storage.Store,
) (*Server, *runtimeState, runtimeDatabase) {
	t.Helper()
	registry := dnIdentityUniqueRegistry(t)
	suffix := mustDNIdentityUniqueDN(t, registry, dnIdentityUniqueSuffix)
	database := runtimeDatabase{
		name:         "{1}mdb",
		partition:    "dn-identity-unique",
		suffixes:     []directory.DN{suffix},
		dnNormalizer: registry,
	}
	domain, err := parseUniqueDomain(
		"serialize ldap:///"+dnIdentityUniqueBaseEquivalent+"?"+
			dnIdentityUniqueExactOID+","+dnIdentityUniqueFoldOID+"?one",
		database,
	)
	if err != nil {
		t.Fatalf("parseUniqueDomain(): %v", err)
	}
	database.unique = &uniqueRuntimeConfiguration{domains: []uniqueDomain{domain}}
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
	instance := &Server{config: Config{Store: store}}

	entries := []directory.Entry{
		dnIdentityUniqueEntry(
			"uniqueExactName=Alice,"+dnIdentityUniqueBase,
			"Alice",
			"Shared Value",
		),
		dnIdentityUniqueEntry(
			"uniqueExactName=alice,"+dnIdentityUniqueBase,
			"alice",
			"Sibling Value",
		),
		dnIdentityUniqueEntry(
			"uniqueExactName=Bob,"+dnIdentityUniqueBase,
			"Bob",
			"Rename Target",
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		writer = writerForDatabase(writer, database)
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed unique entries: %v", err)
	}
	return instance, runtime, database
}

func dnIdentityUniqueRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + dnIdentityUniqueExactOID +
			" NAME ( 'uniqueExactName' 'uniqueExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + dnIdentityUniqueFoldOID +
			" NAME ( 'uniqueFoldName' 'uniqueFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityUniqueEntry(dn, exact, fold string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "uniqueExactAlias", Values: stringValues(exact)},
			{Description: dnIdentityUniqueFoldOID, Values: stringValues(fold)},
			{Description: "cn", Values: stringValues(exact)},
		},
	}
}

func mustDNIdentityUniqueDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	return dn
}

func viewDNIdentityUnique(
	t *testing.T,
	store storage.Store,
	fn func(storage.Reader) error,
) error {
	t.Helper()
	var result error
	err := store.View(context.Background(), func(reader storage.Reader) error {
		result = fn(reader)
		return nil
	})
	if err != nil {
		t.Fatalf("store.View(): %v", err)
	}
	return result
}

func assertDNIdentityUniqueConstraint(t *testing.T, err error) {
	t.Helper()
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultConstraintViolation {
		t.Fatalf("unique result = %v, want constraintViolation", err)
	}
}
