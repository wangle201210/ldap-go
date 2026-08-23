package migration

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestImportLDIFContinueRetainsIndependentEntries(t *testing.T) {
	t.Parallel()

	for _, factory := range continueImportStoreFactories() {
		factory := factory
		t.Run(factory.name, func(t *testing.T) {
			t.Parallel()
			store := factory.open(t)
			seedImportDatabaseConfig(t, store)

			input := `version: 1

dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Example

dn: malformed,dc=example,dc=com
objectClass inetOrgPerson
cn: malformed

dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people

dn: uid=invalid,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
uid: invalid
cn: Invalid
sn: Entry
undefinedAttribute: rejected

dn: uid=orphan,ou=missing,dc=example,dc=com
objectClass: inetOrgPerson
uid: orphan
cn: Orphan
sn: Entry

`
			result, err := ImportLDIFContinue(
				context.Background(),
				store,
				strings.NewReader(input),
				ImportOptions{
					Database:                      "1",
					Replace:                       true,
					RequireObjectClass:            true,
					GenerateOperationalAttributes: true,
				},
			)
			if err != nil {
				t.Fatalf("ImportLDIFContinue(): %v", err)
			}
			if result.Entries != 3 {
				t.Fatalf("imported entries = %d, want 3", result.Entries)
			}
			if len(result.Failures) != 3 {
				t.Fatalf("failures = %#v, want 3", result.Failures)
			}
			for index := 1; index < len(result.Failures); index++ {
				if result.Failures[index-1].Line > result.Failures[index].Line {
					t.Fatalf("failures are not in source order: %#v", result.Failures)
				}
			}
			joined := continueFailureText(result.Failures)
			for _, fragment := range []string{
				"parse LDIF",
				"undefined attribute type",
				"parent entry",
			} {
				if !strings.Contains(joined, fragment) {
					t.Errorf("diagnostics %q do not contain %q", joined, fragment)
				}
			}

			assertContinuedImportDNs(t, store, []string{
				"dc=example,dc=com",
				"ou=people,dc=example,dc=com",
				"uid=alice,ou=people,dc=example,dc=com",
			})
			assertContinuedImportMissingDNs(t, store, []string{
				"uid=invalid,ou=people,dc=example,dc=com",
				"uid=orphan,ou=missing,dc=example,dc=com",
			})
		})
	}
}

func TestImportLDIFContinueSharesEntryCSNStateAcrossRetries(t *testing.T) {
	t.Parallel()

	for _, factory := range continueImportStoreFactories() {
		factory := factory
		t.Run(factory.name, func(t *testing.T) {
			t.Parallel()
			store := factory.open(t)
			seedImportDatabaseConfig(t, store)

			csns := &importCSNGenerator{
				last: time.Date(2100, 1, 2, 3, 4, 5, 0, time.UTC),
			}
			result, err := importLDIFContinue(
				context.Background(),
				store,
				strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

dn: ou=one,dc=example,dc=com
objectClass: organizationalUnit
ou: one

dn: ou=invalid,dc=example,dc=com
objectClass: organizationalUnit
ou: invalid
undefinedAttribute: rejected

dn: ou=two,dc=example,dc=com
objectClass: organizationalUnit
ou: two

`),
				ImportOptions{
					Database:                      "1",
					Replace:                       true,
					RequireObjectClass:            true,
					GenerateOperationalAttributes: true,
					CSNServerID:                   0x123,
				},
				csns,
			)
			if err != nil {
				t.Fatalf("importLDIFContinue(): %v", err)
			}
			if result.Entries != 3 || len(result.Failures) != 1 {
				t.Fatalf("result = %#v, want 3 entries and 1 failure", result)
			}

			seen := make(map[string]string)
			err = store.View(context.Background(), func(reader storage.Reader) error {
				registry, err := importedSchemaRegistry(reader, nil)
				if err != nil {
					return err
				}
				target, err := resolveDatabaseTarget(reader, "1")
				if err != nil {
					return err
				}
				for _, rawDN := range []string{
					"dc=example,dc=com",
					"ou=one,dc=example,dc=com",
					"ou=two,dc=example,dc=com",
				} {
					dn, err := registry.NormalizeDN(rawDN)
					if err != nil {
						return err
					}
					entry, err := reader.GetIn(target.partition, dn)
					if err != nil {
						return err
					}
					values := entry.Values("entryCSN")
					if len(values) != 1 {
						return fmt.Errorf("%q entryCSN values = %q", rawDN, values)
					}
					csn := string(values[0])
					if previous, duplicate := seen[csn]; duplicate {
						return fmt.Errorf(
							"%q and %q share entryCSN %q",
							previous,
							rawDN,
							csn,
						)
					}
					seen[csn] = rawDN
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImportLDIFContinueUsesPreexistingConfigurationSchema(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedImportDatabaseConfig(t, store)
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

dn: cn={9}continue,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: {9}continue
olcAttributeTypes: ( 1.3.6.1.4.1.99999.970.1 NAME 'continueCode' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.99999.970.2 NAME 'continuePerson' SUP top STRUCTURAL MUST ( cn $ continueCode ) )

`),
		ImportOptions{
			Database:                     "0",
			SkipSchemaValidation:         true,
			ValidateConfigurationEntries: true,
		},
	); err != nil {
		t.Fatalf("seed continued-import schema: %v", err)
	}

	result, err := ImportLDIFContinue(
		context.Background(),
		store,
		strings.NewReader(`dn: cn=custom,dc=example,dc=com
objectClass: continuePerson
cn: custom
continueCode: C-100

dn: dc=example,dc=com
objectClass: domain
dc: example

`),
		ImportOptions{Database: "1", RequireObjectClass: true},
	)
	if err != nil {
		t.Fatalf("ImportLDIFContinue(custom schema): %v", err)
	}
	if result.Entries != 2 || len(result.Failures) != 0 {
		t.Fatalf("result = %#v, want 2 entries without failures", result)
	}
	assertContinuedImportDNs(t, store, []string{
		"dc=example,dc=com",
		"cn=custom,dc=example,dc=com",
	})
}

func TestImportLDIFContinueRejectsConfigurationBeforeReplacement(t *testing.T) {
	t.Parallel()

	for _, factory := range continueImportStoreFactories() {
		factory := factory
		t.Run(factory.name, func(t *testing.T) {
			t.Parallel()
			store := factory.open(t)
			seedImportDatabaseConfig(t, store)

			_, err := ImportLDIFContinue(
				context.Background(),
				store,
				strings.NewReader(`dn: cn=config
objectClass: olcGlobal
cn: config

`),
				ImportOptions{Database: "0", Replace: true},
			)
			if err == nil || !strings.Contains(err.Error(), "does not support cn=config") {
				t.Fatalf("configuration continue error = %v", err)
			}
			if err := store.View(context.Background(), func(reader storage.Reader) error {
				target, err := resolveDatabaseTarget(reader, "1")
				if err != nil {
					return err
				}
				if len(target.suffixes) != 1 ||
					target.suffixes[0].String() != "dc=example,dc=com" {
					return fmt.Errorf("content target changed: %#v", target)
				}
				return nil
			}); err != nil {
				t.Fatalf("configuration changed before rejection: %v", err)
			}
		})
	}
}

func TestImportLDIFContinueDoesNotHideStorageIntegrityFailures(t *testing.T) {
	t.Parallel()

	base := storage.NewMemory()
	t.Cleanup(func() { _ = base.Close() })
	store := &continueCorruptStore{Store: base}
	result, err := ImportLDIFContinue(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

`),
		ImportOptions{
			SkipSchemaValidation: true,
			SkipValueValidation:  true,
		},
	)
	if err != nil {
		t.Fatalf("ImportLDIFContinue(): %v", err)
	}
	if result.Entries != 0 || len(result.Failures) != 1 ||
		!errors.Is(result.Failures[0].Err, errContinueCorruptStore) {
		t.Fatalf("result = %#v, want one storage integrity failure", result)
	}
	if err := base.View(context.Background(), func(reader storage.Reader) error {
		count := 0
		if err := reader.ForEach(func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("failed integrity check retained %d entries", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestImportLDIFDefaultRemainsAtomicBesideContinueMode(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(`dn: dc=example,dc=com
objectClass: domain
dc: example

dn: uid=invalid,dc=example,dc=com
objectClass: inetOrgPerson
uid: invalid
cn: Invalid
sn: Entry
undefinedAttribute: rejected

`),
		ImportOptions{RequireObjectClass: true},
	)
	if err == nil {
		t.Fatal("atomic ImportLDIF accepted an invalid record")
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		count := 0
		if err := reader.ForEach(func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("atomic import retained %d entries", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type continueImportStoreFactory struct {
	name string
	open func(*testing.T) storage.Store
}

func continueImportStoreFactories() []continueImportStoreFactory {
	return []continueImportStoreFactory{
		{
			name: "memory",
			open: func(t *testing.T) storage.Store {
				store := storage.NewMemory()
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) storage.Store {
				store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				t.Cleanup(func() { _ = store.Close() })
				return store
			},
		},
	}
}

func continueFailureText(failures []ContinueImportFailure) string {
	var text strings.Builder
	for _, failure := range failures {
		fmt.Fprintf(&text, "line %d dn=%q: %v\n", failure.Line, failure.DN, failure.Err)
	}
	return text.String()
}

func assertContinuedImportDNs(
	t *testing.T,
	store storage.Store,
	rawDNs []string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		registry, err := importedSchemaRegistry(reader, nil)
		if err != nil {
			return err
		}
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		for _, rawDN := range rawDNs {
			dn, err := registry.NormalizeDN(rawDN)
			if err != nil {
				return err
			}
			if _, err := reader.GetIn(target.partition, dn); err != nil {
				return fmt.Errorf("get %q: %w", rawDN, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertContinuedImportMissingDNs(
	t *testing.T,
	store storage.Store,
	rawDNs []string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		registry, err := importedSchemaRegistry(reader, nil)
		if err != nil {
			return err
		}
		target, err := resolveDatabaseTarget(reader, "1")
		if err != nil {
			return err
		}
		for _, rawDN := range rawDNs {
			dn, err := registry.NormalizeDN(rawDN)
			if err != nil {
				return err
			}
			_, err = reader.GetIn(target.partition, dn)
			if !errors.Is(err, storage.ErrEntryNotFound) {
				return fmt.Errorf("get absent %q: %v", rawDN, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

var errContinueCorruptStore = errors.New("simulated storage integrity failure")

type continueCorruptStore struct {
	storage.Store
}

func (store *continueCorruptStore) Update(
	ctx context.Context,
	fn func(storage.Writer) error,
) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		return fn(&continueCorruptWriter{Writer: writer})
	})
}

type continueCorruptWriter struct {
	storage.Writer
}

func (writer *continueCorruptWriter) ForEachPartition(
	func(string, directory.Entry) error,
) error {
	return errContinueCorruptStore
}
