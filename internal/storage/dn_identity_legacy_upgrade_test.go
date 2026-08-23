package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

const legacyUpgradePartition = "legacy-upgrade"

type legacyUpgradeFixture struct {
	store Store
	bolt  *Bolt
	path  string
}

func TestLegacyV1SchemaAwareUpgrade(t *testing.T) {
	t.Parallel()

	for _, backend := range []string{"memory", "bolt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Parallel()
			fixture := openLegacyUpgradeFixture(t, backend)
			defer fixture.close(t)

			exactUpper := legacyUpgradeEntry(
				"exactName=Alice,dc=example,dc=com",
				"exact-upper-v1",
			)
			caseIgnore := legacyUpgradeEntry(
				"uid=Alice,dc=example,dc=com",
				"case-ignore-v1",
			)
			multiAVA := legacyUpgradeEntry(
				"userid=Platform+1.3.6.1.4.1.99999.900=Carol,"+
					"domainComponent=example,dc=com",
				"multi-ava-v1",
			)
			seedLegacyV1Entry(t, fixture, legacyUpgradePartition, exactUpper, false)
			seedLegacyV1Entry(t, fixture, legacyUpgradePartition, caseIgnore, false)
			seedLegacyV1Entry(t, fixture, legacyUpgradePartition, multiAVA, false)

			assertLegacyEntriesReadable(t, fixture.store)

			ctx := context.Background()
			normalizer := testCanonicalDNNormalizer{}
			caseIgnoreV2 := legacyUpgradeEntry(
				"0.9.2342.19200300.100.1.1=ALICE,"+
					"domainComponent=EXAMPLE,dc=COM",
				"case-ignore-v2",
			)
			multiAVAV2 := legacyUpgradeEntry(
				"exactName=Carol+0.9.2342.19200300.100.1.1=Platform,"+
					"dc=example,domainComponent=com",
				"multi-ava-v2",
			)
			exactUpperV2 := legacyUpgradeEntry(
				"1.3.6.1.4.1.99999.900=Alice,dc=example,dc=com",
				"exact-upper-v2",
			)
			exactLowerV2 := legacyUpgradeEntry(
				"exactName=alice,dc=example,dc=com",
				"exact-lower-v2",
			)
			if err := fixture.store.Update(ctx, func(writer Writer) error {
				scoped := WriterInPartitionWithNormalizer(
					writer,
					legacyUpgradePartition,
					normalizer,
				)
				for _, entry := range []directory.Entry{
					caseIgnoreV2,
					multiAVAV2,
					exactUpperV2,
				} {
					if err := scoped.Put(entry, true); err != nil {
						return err
					}
				}
				return scoped.Put(exactLowerV2, false)
			}); err != nil {
				t.Fatalf("upgrade legacy entries: %v", err)
			}

			if err := fixture.store.Update(ctx, func(writer Writer) error {
				scoped := WriterInPartitionWithNormalizer(
					writer,
					legacyUpgradePartition,
					normalizer,
				)
				return scoped.Put(caseIgnoreV2, false)
			}); !errors.Is(err, ErrEntryExists) {
				t.Fatalf("Put(equivalent, replace=false) error = %v, want ErrEntryExists", err)
			}

			assertUpgradedEntries(t, fixture.store, 4)
			assertOnlyV2PhysicalKeys(t, fixture, legacyUpgradePartition, 4)

			if err := fixture.store.Update(ctx, func(writer Writer) error {
				scoped := WriterInPartitionWithNormalizer(
					writer,
					legacyUpgradePartition,
					normalizer,
				)
				return scoped.Delete(mustLegacyUpgradeDN(t, exactLowerV2.DN))
			}); err != nil {
				t.Fatalf("Delete(caseExact lower): %v", err)
			}
			assertUpgradedEntries(t, fixture.store, 3)
			assertOnlyV2PhysicalKeys(t, fixture, legacyUpgradePartition, 3)
		})
	}
}

func TestLegacyV1SchemaAwareAmbiguityIsFailClosed(t *testing.T) {
	t.Parallel()

	for _, backend := range []string{"memory", "bolt"} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			t.Run("case-ignore-duplicate", func(t *testing.T) {
				fixture := openLegacyUpgradeFixture(t, backend)
				defer fixture.close(t)
				legacy := legacyUpgradeEntry(
					"uid=Alice,dc=example,dc=com",
					"legacy",
				)
				duplicate := legacyUpgradeEntry(
					"userid=ALICE,domainComponent=EXAMPLE,dc=COM",
					"v2",
				)
				seedLegacyV1Entry(t, fixture, legacyUpgradePartition, legacy, false)
				putSchemaAwareDirect(t, fixture.store, legacyUpgradePartition, duplicate)

				ctx := context.Background()
				normalizer := testCanonicalDNNormalizer{}
				lookup := mustLegacyUpgradeDN(t,
					"0.9.2342.19200300.100.1.1=alice,dc=example,dc=com",
				)
				if err := fixture.store.View(ctx, func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(
						reader,
						legacyUpgradePartition,
						normalizer,
					)
					if _, err := scoped.Get(lookup); !errors.Is(err, ErrEntryAmbiguous) {
						t.Fatalf("Get() error = %v, want ErrEntryAmbiguous", err)
					}
					count := 0
					if err := scoped.ForEach(func(directory.Entry) error {
						count++
						return nil
					}); err != nil {
						return err
					}
					if count != 2 {
						t.Fatalf("ForEach() count = %d, want 2", count)
					}
					return nil
				}); err != nil {
					t.Fatalf("inspect ambiguous entries: %v", err)
				}

				replacement := legacyUpgradeEntry(duplicate.DN, "replacement")
				if err := fixture.store.Update(ctx, func(writer Writer) error {
					return WriterInPartitionWithNormalizer(
						writer,
						legacyUpgradePartition,
						normalizer,
					).Put(replacement, true)
				}); !errors.Is(err, ErrEntryAmbiguous) {
					t.Fatalf("Put(replace) error = %v, want ErrEntryAmbiguous", err)
				}
				if err := fixture.store.Update(ctx, func(writer Writer) error {
					return WriterInPartitionWithNormalizer(
						writer,
						legacyUpgradePartition,
						normalizer,
					).Delete(lookup)
				}); !errors.Is(err, ErrEntryAmbiguous) {
					t.Fatalf("Delete() error = %v, want ErrEntryAmbiguous", err)
				}

				if fixture.path != "" {
					fixture.close(t)
					if _, err := CheckBolt(ctx, fixture.path); err != nil {
						t.Fatalf("CheckBolt() rejected structurally valid mixed data: %v", err)
					}
					if _, err := CheckBoltWithNormalizer(
						ctx,
						fixture.path,
						normalizer,
					); err == nil || !strings.Contains(err.Error(), "identify the same") {
						t.Fatalf("CheckBoltWithNormalizer() error = %v, want duplicate identity", err)
					}
				}
			})

			t.Run("case-exact-shared-legacy-key", func(t *testing.T) {
				fixture := openLegacyUpgradeFixture(t, backend)
				defer fixture.close(t)
				upper := legacyUpgradeEntry(
					"exactName=Alice,dc=example,dc=com",
					"upper-legacy",
				)
				lower := legacyUpgradeEntry(
					"exactName=alice,dc=example,dc=com",
					"lower-v2",
				)
				upperLegacyDN := mustLegacyUpgradeDN(t, upper.DN)
				lowerLegacyDN := mustLegacyUpgradeDN(t, lower.DN)
				if upperLegacyDN.Key() != lowerLegacyDN.Key() {
					t.Fatal("caseExact fixture does not share a legacy folded key")
				}
				seedLegacyV1Entry(t, fixture, legacyUpgradePartition, upper, false)
				putSchemaAwareDirect(t, fixture.store, legacyUpgradePartition, lower)

				ctx := context.Background()
				normalizer := testCanonicalDNNormalizer{}
				if err := fixture.store.View(ctx, func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(
						reader,
						legacyUpgradePartition,
						normalizer,
					)
					gotUpper, err := scoped.Get(upperLegacyDN)
					if err != nil {
						return err
					}
					gotLower, err := scoped.Get(lowerLegacyDN)
					if err != nil {
						return err
					}
					if description(gotUpper) != "upper-legacy" ||
						description(gotLower) != "lower-v2" {
						t.Fatalf("caseExact results = %q, %q", description(gotUpper), description(gotLower))
					}
					return nil
				}); err != nil {
					t.Fatalf("read caseExact siblings: %v", err)
				}
				upperReplacement := legacyUpgradeEntry(upper.DN, "upper-v2")
				if err := fixture.store.Update(ctx, func(writer Writer) error {
					return WriterInPartitionWithNormalizer(
						writer,
						legacyUpgradePartition,
						normalizer,
					).Put(upperReplacement, true)
				}); err != nil {
					t.Fatalf("upgrade caseExact upper: %v", err)
				}
				if err := fixture.store.Update(ctx, func(writer Writer) error {
					return WriterInPartitionWithNormalizer(
						writer,
						legacyUpgradePartition,
						normalizer,
					).Delete(upperLegacyDN)
				}); err != nil {
					t.Fatalf("delete upgraded caseExact upper: %v", err)
				}
				if err := fixture.store.View(ctx, func(reader Reader) error {
					scoped := ReaderInPartitionWithNormalizer(
						reader,
						legacyUpgradePartition,
						normalizer,
					)
					if _, err := scoped.Get(upperLegacyDN); !errors.Is(err, ErrEntryNotFound) {
						t.Fatalf("deleted upper lookup error = %v", err)
					}
					entry, err := scoped.Get(lowerLegacyDN)
					if err != nil {
						return err
					}
					if description(entry) != "lower-v2" {
						t.Fatalf("remaining lower description = %q", description(entry))
					}
					return nil
				}); err != nil {
					t.Fatalf("verify caseExact delete isolation: %v", err)
				}
				if fixture.path != "" {
					fixture.close(t)
					if _, err := CheckBoltWithNormalizer(ctx, fixture.path, normalizer); err != nil {
						t.Fatalf("CheckBoltWithNormalizer() merged caseExact siblings: %v", err)
					}
				}
			})
		})
	}
}

func TestLegacyV1BoltMaintenancePreservesSchemaIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	directoryPath := t.TempDir()
	sourcePath := filepath.Join(directoryPath, "source.db")
	backupPath := filepath.Join(directoryPath, "backup.db")
	restoredPath := filepath.Join(directoryPath, "restored.db")
	fixture := openLegacyUpgradeBoltFixture(t, sourcePath)
	seedLegacyV1Entry(t, fixture, OpenLDAPConfigPartition, legacyUpgradeEntry(
		"olcDatabase={1}mdb,cn=config",
		"config-v1",
	), false)
	seedLegacyV1Entry(t, fixture, "", legacyUpgradeEntry(
		"uid=Root,dc=example,dc=com",
		"raw-unpartitioned-v1",
	), true)
	seedLegacyV1Entry(t, fixture, legacyUpgradePartition, legacyUpgradeEntry(
		"exactName=Alice,dc=example,dc=com",
		"exact-upper-v1",
	), false)
	seedLegacyV1Entry(t, fixture, legacyUpgradePartition, legacyUpgradeEntry(
		"userid=Platform+1.3.6.1.4.1.99999.900=Carol,"+
			"domainComponent=example,dc=com",
		"multi-ava-v1",
	), false)
	putSchemaAwareDirect(t, fixture.store, legacyUpgradePartition, legacyUpgradeEntry(
		"exactName=alice,dc=example,dc=com",
		"exact-lower-v2",
	))
	if err := fixture.store.Update(ctx, func(writer Writer) error {
		if err := writer.SetNamingContexts([]string{"dc=example,dc=com"}); err != nil {
			return err
		}
		return writer.SetMetadata("legacy-upgrade", []byte("preserve-me"))
	}); err != nil {
		t.Fatalf("seed metadata: %v", err)
	}
	fixture.close(t)

	want := readBoltKeyValues(t, sourcePath)
	if report, err := CheckBoltWithNormalizer(
		ctx,
		sourcePath,
		testCanonicalDNNormalizer{},
	); err != nil {
		t.Fatalf("CheckBoltWithNormalizer(source): %v", err)
	} else if report.Entries != 5 {
		t.Fatalf("source entry count = %d, want 5", report.Entries)
	}

	if _, err := BackupBolt(ctx, sourcePath, backupPath, false); err != nil {
		t.Fatalf("BackupBolt(): %v", err)
	}
	assertBoltKeyValues(t, backupPath, want)
	assertMaintainedLegacyIdentity(t, backupPath)

	if _, err := RestoreBolt(ctx, backupPath, restoredPath, false); err != nil {
		t.Fatalf("RestoreBolt(): %v", err)
	}
	assertBoltKeyValues(t, restoredPath, want)
	assertMaintainedLegacyIdentity(t, restoredPath)

	if _, err := RebuildBolt(ctx, restoredPath); err != nil {
		t.Fatalf("RebuildBolt(): %v", err)
	}
	assertBoltKeyValues(t, restoredPath, want)
	assertMaintainedLegacyIdentity(t, restoredPath)
}

func openLegacyUpgradeFixture(t *testing.T, backend string) *legacyUpgradeFixture {
	t.Helper()
	if backend == "memory" {
		store := NewMemory()
		return &legacyUpgradeFixture{store: store}
	}
	return openLegacyUpgradeBoltFixture(t, filepath.Join(t.TempDir(), "legacy-upgrade.db"))
}

func openLegacyUpgradeBoltFixture(t *testing.T, path string) *legacyUpgradeFixture {
	t.Helper()
	store, err := OpenBolt(path)
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	return &legacyUpgradeFixture{store: store, bolt: store, path: path}
}

func (fixture *legacyUpgradeFixture) close(t *testing.T) {
	t.Helper()
	if fixture.store == nil {
		return
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	fixture.store = nil
}

func seedLegacyV1Entry(
	t *testing.T,
	fixture *legacyUpgradeFixture,
	partition string,
	entry directory.Entry,
	rawUnpartitioned bool,
) {
	t.Helper()
	dn := mustLegacyUpgradeDN(t, entry.DN)
	key := partitionedEntryKey(partition, dn.Key())
	if rawUnpartitioned {
		if partition != "" {
			t.Fatal("raw unpartitioned key requires the default partition")
		}
		key = dn.Key()
	}
	value, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal legacy entry: %v", err)
	}
	switch store := fixture.store.(type) {
	case *Memory:
		store.mu.Lock()
		store.entries[key] = entry.Clone()
		delete(store.dnIdentities, key)
		delete(store.dnSources, key)
		store.mu.Unlock()
	case *Bolt:
		if err := store.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(entriesBucket).Put([]byte(key), value)
		}); err != nil {
			t.Fatalf("seed legacy Bolt entry: %v", err)
		}
	default:
		t.Fatalf("unsupported legacy fixture %T", fixture.store)
	}
}

func putSchemaAwareDirect(
	t *testing.T,
	store Store,
	partition string,
	entry directory.Entry,
) {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(entry.DN, testCanonicalDNNormalizer{})
	if err != nil {
		t.Fatalf("normalize %q: %v", entry.DN, err)
	}
	if err := store.Update(context.Background(), func(writer Writer) error {
		return PutInWithDN(writer, partition, entry, dn, false)
	}); err != nil {
		t.Fatalf("PutInWithDN(%q): %v", entry.DN, err)
	}
}

func assertLegacyEntriesReadable(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	if err := store.View(ctx, func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(
			reader,
			legacyUpgradePartition,
			testCanonicalDNNormalizer{},
		)
		checks := []struct {
			dn   string
			want string
		}{
			{
				dn:   "1.3.6.1.4.1.99999.900=Alice,DC=EXAMPLE,DC=COM",
				want: "exact-upper-v1",
			},
			{
				dn: "0.9.2342.19200300.100.1.1=ALICE," +
					"domainComponent=EXAMPLE,dc=COM",
				want: "case-ignore-v1",
			},
			{
				dn: "exactName=Carol+0.9.2342.19200300.100.1.1=PLATFORM," +
					"dc=EXAMPLE,domainComponent=COM",
				want: "multi-ava-v1",
			},
		}
		for _, check := range checks {
			entry, err := scoped.Get(mustLegacyUpgradeDN(t, check.dn))
			if err != nil {
				return err
			}
			if got := description(entry); got != check.want {
				t.Fatalf("Get(%q) description = %q, want %q", check.dn, got, check.want)
			}
		}
		if _, err := scoped.Get(mustLegacyUpgradeDN(t,
			"exactName=alice,dc=example,dc=com",
		)); !errors.Is(err, ErrEntryNotFound) {
			t.Fatalf("caseExact sibling lookup error = %v, want ErrEntryNotFound", err)
		}
		count := 0
		if err := scoped.ForEach(func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 3 {
			t.Fatalf("legacy ForEach() count = %d, want 3", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("read legacy entries: %v", err)
	}
}

func assertUpgradedEntries(t *testing.T, store Store, wantCount int) {
	t.Helper()
	ctx := context.Background()
	if err := store.View(ctx, func(reader Reader) error {
		scoped := ReaderInPartitionWithNormalizer(
			reader,
			legacyUpgradePartition,
			testCanonicalDNNormalizer{},
		)
		checks := []struct {
			dn   string
			want string
		}{
			{"exactName=Alice,dc=example,dc=com", "exact-upper-v2"},
			{"uid=ALICE,dc=EXAMPLE,dc=COM", "case-ignore-v2"},
			{
				"userid=Platform+exactName=Carol,dc=example,dc=com",
				"multi-ava-v2",
			},
		}
		if wantCount == 4 {
			checks = append(checks, struct {
				dn   string
				want string
			}{"exactName=alice,dc=example,dc=com", "exact-lower-v2"})
		}
		for _, check := range checks {
			entry, err := scoped.Get(mustLegacyUpgradeDN(t, check.dn))
			if err != nil {
				return err
			}
			if got := description(entry); got != check.want {
				t.Fatalf("Get(%q) description = %q, want %q", check.dn, got, check.want)
			}
		}
		if wantCount == 3 {
			if _, err := scoped.Get(mustLegacyUpgradeDN(t,
				"exactName=alice,dc=example,dc=com",
			)); !errors.Is(err, ErrEntryNotFound) {
				t.Fatalf("deleted caseExact lookup error = %v", err)
			}
		}
		count := 0
		if err := scoped.ForEach(func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != wantCount {
			t.Fatalf("upgraded ForEach() count = %d, want %d", count, wantCount)
		}
		return nil
	}); err != nil {
		t.Fatalf("read upgraded entries: %v", err)
	}
}

func assertOnlyV2PhysicalKeys(
	t *testing.T,
	fixture *legacyUpgradeFixture,
	partition string,
	want int,
) {
	t.Helper()
	keys := make([]string, 0)
	switch store := fixture.store.(type) {
	case *Memory:
		store.mu.RLock()
		for key := range store.entries {
			entryPartition, physicalKey := splitPartitionedEntryKey(key)
			if entryPartition == partition {
				keys = append(keys, physicalKey)
			}
		}
		store.mu.RUnlock()
	case *Bolt:
		if err := store.db.View(func(tx *bolt.Tx) error {
			return tx.Bucket(entriesBucket).ForEach(func(key, _ []byte) error {
				entryPartition, physicalKey := splitPartitionedEntryKey(string(key))
				if entryPartition == partition {
					keys = append(keys, physicalKey)
				}
				return nil
			})
		}); err != nil {
			t.Fatalf("inspect Bolt keys: %v", err)
		}
	}
	if len(keys) != want {
		t.Fatalf("physical key count = %d, want %d", len(keys), want)
	}
	for _, key := range keys {
		if !isSchemaAwareDNKey(key) {
			t.Fatalf("legacy physical key remained after upgrade: %q", key)
		}
	}
}

func assertMaintainedLegacyIdentity(t *testing.T, path string) {
	t.Helper()
	if _, err := CheckBoltWithNormalizer(
		context.Background(),
		path,
		testCanonicalDNNormalizer{},
	); err != nil {
		t.Fatalf("CheckBoltWithNormalizer(%q): %v", path, err)
	}
	store, err := OpenBoltReadOnly(path)
	if err != nil {
		t.Fatalf("OpenBoltReadOnly(%q): %v", path, err)
	}
	defer store.Close()
	if err := store.View(context.Background(), func(reader Reader) error {
		defaultReader := ReaderInPartitionWithNormalizer(
			reader,
			"",
			testCanonicalDNNormalizer{},
		)
		root, err := defaultReader.Get(mustLegacyUpgradeDN(t,
			"userid=ROOT,domainComponent=EXAMPLE,dc=COM",
		))
		if err != nil {
			return err
		}
		if description(root) != "raw-unpartitioned-v1" {
			t.Fatalf("restored raw entry description = %q", description(root))
		}

		scoped := ReaderInPartitionWithNormalizer(
			reader,
			legacyUpgradePartition,
			testCanonicalDNNormalizer{},
		)
		checks := map[string]string{
			"exactName=Alice,dc=example,dc=com":              "exact-upper-v1",
			"exactName=alice,dc=example,dc=com":              "exact-lower-v2",
			"exactName=Carol+uid=PLATFORM,dc=EXAMPLE,dc=COM": "multi-ava-v1",
		}
		for value, want := range checks {
			entry, err := scoped.Get(mustLegacyUpgradeDN(t, value))
			if err != nil {
				return err
			}
			if got := description(entry); got != want {
				t.Fatalf("maintained Get(%q) = %q, want %q", value, got, want)
			}
		}
		count := 0
		if err := scoped.ForEach(func(directory.Entry) error {
			count++
			return nil
		}); err != nil {
			return err
		}
		if count != 3 {
			t.Fatalf("maintained partition count = %d, want 3", count)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify maintained database %q: %v", path, err)
	}
}

func readBoltKeyValues(t *testing.T, path string) map[string][]byte {
	t.Helper()
	database, err := openBoltReadOnly(path)
	if err != nil {
		t.Fatalf("open Bolt snapshot: %v", err)
	}
	defer database.Close()
	result := make(map[string][]byte)
	if err := database.View(func(tx *bolt.Tx) error {
		for _, bucketName := range [][]byte{entriesBucket, metaBucket} {
			bucket := tx.Bucket(bucketName)
			if err := bucket.ForEach(func(key, value []byte) error {
				result[string(bucketName)+"\x00"+string(key)] = bytes.Clone(value)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read Bolt snapshot: %v", err)
	}
	return result
}

func assertBoltKeyValues(t *testing.T, path string, want map[string][]byte) {
	t.Helper()
	got := readBoltKeyValues(t, path)
	if !reflect.DeepEqual(got, want) {
		gotKeys := make([]string, 0, len(got))
		wantKeys := make([]string, 0, len(want))
		for key := range got {
			gotKeys = append(gotKeys, key)
		}
		for key := range want {
			wantKeys = append(wantKeys, key)
		}
		sort.Strings(gotKeys)
		sort.Strings(wantKeys)
		t.Fatalf("Bolt records changed: got keys %q, want %q", gotKeys, wantKeys)
	}
}

func legacyUpgradeEntry(dn, value string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "description", Values: [][]byte{[]byte(value)}},
		},
	}
}

func description(entry directory.Entry) string {
	values := entry.Values("description")
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}

func mustLegacyUpgradeDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
