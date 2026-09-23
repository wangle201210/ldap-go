package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

// Each value describes immutable naming semantics and explicitly opts into caching.
type incrementalNamingNormalizer struct {
	foldExact bool
	newKind   bool
}

func (n incrementalNamingNormalizer) NamingContextCacheFingerprint() ([32]byte, bool) {
	fingerprint := [32]byte{1}
	if n.foldExact {
		fingerprint[1] = 1
	}
	if n.newKind {
		fingerprint[2] = 1
	}
	return fingerprint, true
}

func (n incrementalNamingNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	switch strings.ToLower(attribute) {
	case "cn", "2.5.4.3":
		return "2.5.4.3", bytes.ToLower(value), nil
	case "ou", "2.5.4.11":
		return "2.5.4.11", bytes.ToLower(value), nil
	case "newkind":
		if n.newKind {
			return "1.3.6.1.4.1.99999.901", bytes.ToLower(value), nil
		}
	}
	canonical, normalized, err := (testDNNormalizer{}).NormalizeDNAttribute(attribute, value)
	if n.foldExact {
		normalized = bytes.ToLower(normalized)
	}
	return canonical, normalized, err
}

func (n incrementalNamingNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	switch strings.ToLower(attribute) {
	case "cn", "2.5.4.3":
		return "cn", nil
	case "ou", "2.5.4.11":
		return "ou", nil
	case "newkind":
		if n.newKind {
			return "newKind", nil
		}
	}
	return (testCanonicalDNNormalizer{}).CanonicalDNAttributeName(attribute)
}

func newIncrementalNamingStore(t *testing.T) *Bolt {
	t.Helper()
	store, err := OpenBolt(filepath.Join(t.TempDir(), "incremental.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func updateIncrementalNamingStore(t *testing.T, store *Bolt, visit func(*boltTx)) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer Writer) error {
		visit(writer.(*boltTx))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func incrementalNamingDN(t *testing.T, raw string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDNWithNormalizer(raw, incrementalNamingNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	return dn
}

func putIncrementalNamingEntry(t *testing.T, writer Writer, partition, raw string, replace bool) {
	t.Helper()
	if err := PutInWithDN(writer, partition, directory.Entry{DN: raw}, incrementalNamingDN(t, raw), replace); err != nil {
		t.Fatal(err)
	}
}

func deleteIncrementalNamingEntry(t *testing.T, writer Writer, partition, raw string) {
	t.Helper()
	if err := writer.DeleteIn(partition, incrementalNamingDN(t, raw)); err != nil {
		t.Fatal(err)
	}
}

func incrementalNamingParity(t *testing.T, reader Reader, normalizer directory.DNAttributeNormalizer) ([]string, error) {
	t.Helper()
	want, wantErr := InferNamingContextsWithNormalizer(reader, normalizer)
	got, gotErr := InferNamingContextsIncremental(reader, normalizer)
	if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
		t.Fatalf("incremental = %q, %v; reference = %q, %v", got, gotErr, want, wantErr)
	}
	return got, gotErr
}

func requireIncrementalNamingContexts(t *testing.T, reader Reader, normalizer directory.DNAttributeNormalizer, want ...string) []string {
	t.Helper()
	got, err := incrementalNamingParity(t, reader, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	actual, expected := slices.Clone(got), slices.Clone(want)
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		t.Fatalf("contexts = %q, want members %q", got, want)
	}
	return got
}

func warmIncrementalNamingStore(t *testing.T, store *Bolt) {
	t.Helper()
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "data", "dc=base", false)
		contexts := requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		if err := tx.SetNamingContexts(contexts); err != nil {
			t.Fatal(err)
		}
	})
	if store.namingIndex == nil {
		t.Fatal("trusted normalizer did not retain a warm naming-context index")
	}
}

func TestNamingContextIncrementalDuplicateWinner(t *testing.T) {
	store := newIncrementalNamingStore(t)
	normalizer := incrementalNamingNormalizer{}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		// Reverse insertion order makes the physical-order winner observable.
		putIncrementalNamingEntry(t, tx, "z", "uid=shared,dc=missing", false)
		putIncrementalNamingEntry(t, tx, "a", "uid=SHARED,dc=missing", false)
		putIncrementalNamingEntry(t, tx, "children", "cn=leaf,uid=shared,dc=missing", false)
		requireIncrementalNamingContexts(t, tx, normalizer, "uid=shared,dc=missing")
	})
	if store.namingIndex == nil {
		t.Fatal("duplicate fixture did not warm the index")
	}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		deleteIncrementalNamingEntry(t, tx, "a", "uid=shared,dc=missing")
		requireIncrementalNamingContexts(t, tx, normalizer, "uid=shared,dc=missing")
		putIncrementalNamingEntry(t, tx, "a", "uid=SHARED,dc=missing", false)
		deleteIncrementalNamingEntry(t, tx, "z", "uid=shared,dc=missing")
		requireIncrementalNamingContexts(t, tx, normalizer, "uid=SHARED,dc=missing")
		putIncrementalNamingEntry(t, tx, "a", "UID=Shared,DC=missing", true)
		requireIncrementalNamingContexts(t, tx, normalizer, "UID=Shared,DC=missing")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		deleteIncrementalNamingEntry(t, tx, "a", "uid=shared,dc=missing")
		requireIncrementalNamingContexts(t, tx, normalizer, "cn=leaf,uid=shared,dc=missing")
	})
}

func TestNamingContextIncrementalPartitionParentsAndOrphans(t *testing.T) {
	store := newIncrementalNamingStore(t)
	normalizer := incrementalNamingNormalizer{}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "superior", "dc=example", false)
		putIncrementalNamingEntry(t, tx, "subordinate", "ou=People,dc=example", false)
		putIncrementalNamingEntry(t, tx, "orphan", "uid=leaf,ou=missing,dc=example", false)
		if err := tx.PutIn("root", directory.Entry{DN: ""}, false); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, normalizer, "dc=example", "uid=leaf,ou=missing,dc=example")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "another-partition", "ou=missing,dc=example", false)
		requireIncrementalNamingContexts(t, tx, normalizer, "dc=example")
		putIncrementalNamingEntry(t, tx, "duplicate-parent", "dc=EXAMPLE", false)
		deleteIncrementalNamingEntry(t, tx, "superior", "dc=example")
		requireIncrementalNamingContexts(t, tx, normalizer, "dc=EXAMPLE")
		deleteIncrementalNamingEntry(t, tx, "duplicate-parent", "dc=example")
		requireIncrementalNamingContexts(t, tx, normalizer, "ou=People,dc=example", "ou=missing,dc=example")
		deleteIncrementalNamingEntry(t, tx, "another-partition", "ou=missing,dc=example")
		requireIncrementalNamingContexts(t, tx, normalizer, "ou=People,dc=example", "uid=leaf,ou=missing,dc=example")
	})
}

func TestNamingContextIncrementalConfigExceptions(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		for _, row := range []struct{ partition, raw string }{
			{OpenLDAPConfigPartition, "cn=CONFIG"},
			{OpenLDAPConfigPartition, "undefinedName=OutsideConfig"},
			{OpenLDAPConfigPartition, "dc=base"},
			{"pending", "olcDatabase={0}config,cn=config"},
			{"pending", "undefinedName=Allowed,cn=config"},
		} {
			if err := tx.PutIn(row.partition, directory.Entry{DN: row.raw}, false); err != nil {
				t.Fatal(err)
			}
		}
		putIncrementalNamingEntry(t, tx, "oid", "2.5.4.3=config", false)
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{},
			"cn=CONFIG", "undefinedName=OutsideConfig", "dc=base", "dc=base", "2.5.4.3=config")
		if err := tx.DeleteIn(OpenLDAPConfigPartition, mustDN(t, "cn=config")); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{},
			"undefinedName=OutsideConfig", "dc=base", "dc=base", "2.5.4.3=config",
			"olcDatabase={0}config,cn=config", "undefinedName=Allowed,cn=config")
	})
}

func TestNamingContextIncrementalMultiAVAAndOwnership(t *testing.T) {
	store := newIncrementalNamingStore(t)
	normalizer := incrementalNamingNormalizer{}
	const first = `cn=A\,B+uid=ALICE,dc=missing`
	const winner = `userid=alice+2.5.4.3=a\,b,dc=missing`
	var retained []string
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "z", winner, false)
		putIncrementalNamingEntry(t, tx, "a", first, false)
		putIncrementalNamingEntry(t, tx, "child", "ou=child,"+first, false)
		retained = requireIncrementalNamingContexts(t, tx, normalizer, winner)
		returned := requireIncrementalNamingContexts(t, tx, normalizer, winner)
		returned[0] = "caller mutation"
		requireIncrementalNamingContexts(t, tx, normalizer, winner)
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		deleteIncrementalNamingEntry(t, tx, "z", winner)
		requireIncrementalNamingContexts(t, tx, normalizer, first)
	})
	if !slices.Equal(retained, []string{winner}) {
		t.Fatalf("retained result changed across transactions: %q", retained)
	}
}

func TestNamingContextIncrementalFingerprintChanges(t *testing.T) {
	store := newIncrementalNamingStore(t)
	exact := incrementalNamingNormalizer{}
	folded := incrementalNamingNormalizer{foldExact: true}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "a", "exactName=Root", false)
		putIncrementalNamingEntry(t, tx, "z", "exactName=root", false)
		putIncrementalNamingEntry(t, tx, "child", "uid=child,exactName=ROOT", false)
		requireIncrementalNamingContexts(t, tx, exact, "exactName=Root", "exactName=root", "uid=child,exactName=ROOT")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, folded, "exactName=root")
		requireIncrementalNamingContexts(t, tx, exact, "exactName=Root", "exactName=root", "uid=child,exactName=ROOT")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if err := tx.PutIn("new", directory.Entry{DN: "newKind=Fresh"}, false); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{foldExact: true, newKind: true},
			"exactName=root", "newKind=Fresh")
		if _, err := incrementalNamingParity(t, tx, folded); err == nil {
			t.Fatal("old fingerprint accepted the new naming attribute")
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{foldExact: true, newKind: true},
			"exactName=root", "newKind=Fresh")
	})
}

func TestNamingContextIncrementalRollbackAfterRefresh(t *testing.T) {
	for _, clearFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("clear-%v", clearFirst), func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			rollback := errors.New("rollback after naming refresh")
			err := store.Update(t.Context(), func(writer Writer) error {
				if clearFirst {
					if err := writer.Clear(); err != nil {
						return err
					}
				} else {
					deleteIncrementalNamingEntry(t, writer, "data", "dc=base")
				}
				putIncrementalNamingEntry(t, writer, "data", "dc=rolledback", false)
				contexts := requireIncrementalNamingContexts(t, writer, incrementalNamingNormalizer{}, "dc=rolledback")
				if err := writer.SetNamingContexts(contexts); err != nil {
					return err
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("rollback error = %v", err)
			}
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
				contexts, err := tx.NamingContexts()
				if err != nil || !slices.Equal(contexts, []string{"dc=base"}) {
					t.Fatalf("persisted contexts after rollback = %q, %v", contexts, err)
				}
			})
		})
	}
}

func TestNamingContextIncrementalPanicRollbackAfterRefresh(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	const aborted = "abort after naming refresh"
	func() {
		defer func() {
			if got := recover(); got != aborted {
				t.Fatalf("recovered panic = %v, want %q", got, aborted)
			}
		}()
		_ = store.Update(t.Context(), func(writer Writer) error {
			deleteIncrementalNamingEntry(t, writer, "data", "dc=base")
			putIncrementalNamingEntry(t, writer, "data", "dc=aborted", false)
			requireIncrementalNamingContexts(t, writer, incrementalNamingNormalizer{}, "dc=aborted")
			panic(aborted)
		})
	}()
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
	})
}

func TestNamingContextIncrementalWriterDetachesOnExit(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			var retained *boltTx
			var returned error
			var recovered any
			abort := errors.New("abort tracked writer")
			func() {
				defer func() { recovered = recover() }()
				returned = store.Update(t.Context(), func(writer Writer) error {
					retained = writer.(*boltTx)
					putIncrementalNamingEntry(t, writer, "data", "dc=refreshed", false)
					requireIncrementalNamingContexts(t, writer, incrementalNamingNormalizer{}, "dc=base", "dc=refreshed")
					putIncrementalNamingEntry(t, writer, "data", "dc=pending", false)
					if retained.namingStore != store || len(retained.namingDirty) == 0 {
						t.Fatal("fixture did not retain an attached writer with dirty keys")
					}
					switch outcome {
					case "error":
						return abort
					case "panic":
						panic(abort)
					default:
						return nil
					}
				})
			}()
			if outcome == "panic" {
				if recovered != abort {
					t.Fatalf("recovered = %v, want %v", recovered, abort)
				}
			} else if recovered != nil {
				t.Fatalf("unexpected panic: %v", recovered)
			}
			if outcome == "error" && !errors.Is(returned, abort) || outcome == "success" && returned != nil {
				t.Fatalf("returned error = %v for %s", returned, outcome)
			}
			// Inspect fields only; all operations on an expired transaction are unsupported.
			if retained == nil || retained.namingStore != nil || len(retained.namingDirty) != 0 {
				t.Fatalf("writer retained naming-cache access after %s", outcome)
			}
		})
	}
}

func TestNamingContextIncrementalMutationsAfterRefreshAndWithoutRefresh(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "data", "uid=child,dc=base", false)
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		deleteIncrementalNamingEntry(t, tx, "data", "dc=base")
		putIncrementalNamingEntry(t, tx, "other", "dc=after", false)
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "uid=child,dc=base", "dc=after")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		entry := directory.Entry{DN: "DC=AFTER", Attributes: []directory.Attribute{
			{Description: "description", Values: [][]byte{[]byte("ordinary modify without refresh")}},
		}}
		if err := PutInWithDN(tx, "other", entry, incrementalNamingDN(t, entry.DN), true); err != nil {
			t.Fatal(err)
		}
		deleteIncrementalNamingEntry(t, tx, "data", "uid=child,dc=base")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "DC=AFTER")
		contexts, err := tx.NamingContexts()
		if err != nil || !slices.Equal(contexts, []string{"dc=base"}) {
			t.Fatalf("inference silently changed explicit naming-context metadata: %q, %v", contexts, err)
		}
	})
}

func TestNamingContextIncrementalSameCountReplacement(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	const raw = "uid=child,dc=base"
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "data", raw, false)
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		entry, err := tx.GetIn("data", incrementalNamingDN(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		entry.ReplaceValues("description", [][]byte{[]byte("changed attributes, unchanged DN")})
		if err := PutInWithDN(tx, "data", entry, incrementalNamingDN(t, raw), true); err != nil {
			t.Fatal(err)
		}
		// No inference here: ordinary Modify relies on the end-of-commit update.
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		entry, err := tx.GetIn("data", incrementalNamingDN(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(entry.Values("description"), [][]byte{[]byte("changed attributes, unchanged DN")}) {
			t.Fatalf("ordinary Modify lost attributes: %#v", entry)
		}
		key := []byte(partitionedEntryKey("data", incrementalNamingDN(t, raw).Key()))
		valid := bytes.Clone(tx.entries.Get(key))
		if err := tx.putEntry(key, valid[:len(valid)-1]); err != nil {
			t.Fatalf("tracked replacement rejected corruption before inference: %v", err)
		}
		if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err == nil {
			t.Fatal("unchanged DN hid corrupt attributes in a non-root row")
		}
		if err := tx.putEntry(key, valid); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		count, err := tx.PartitionEntryCount("data")
		if err != nil || count != 2 {
			t.Fatalf("replacement changed entry count: %d, %v", count, err)
		}
	})
}

func TestNamingContextIncrementalLegacyReplacementChangesIdentity(t *testing.T) {
	store := newIncrementalNamingStore(t)
	normalizer := incrementalNamingNormalizer{}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if err := tx.PutIn("legacy", directory.Entry{DN: "exactName=Root"}, false); err != nil {
			t.Fatal(err)
		}
		putIncrementalNamingEntry(t, tx, "z", "EXACTNAME=Root", false)
		putIncrementalNamingEntry(t, tx, "children", "uid=upper,exactName=Root", false)
		putIncrementalNamingEntry(t, tx, "children", "uid=lower,exactName=root", false)
		requireIncrementalNamingContexts(t, tx, normalizer, "EXACTNAME=Root", "uid=lower,exactName=root")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		// Legacy keys fold case even though the inference schema is case-exact.
		if err := tx.PutIn("legacy", directory.Entry{DN: "exactName=root"}, true); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, normalizer, "EXACTNAME=Root", "exactName=root")
		deleteIncrementalNamingEntry(t, tx, "z", "EXACTNAME=Root")
		requireIncrementalNamingContexts(t, tx, normalizer, "uid=upper,exactName=Root", "exactName=root")
		if err := tx.PutIn("legacy", directory.Entry{DN: "exactName=Root"}, true); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, normalizer, "exactName=Root", "uid=lower,exactName=root")
	})
}

func TestNamingContextIncrementalClearRepopulate(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if err := tx.Clear(); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{})
		contexts, err := tx.NamingContexts()
		if err != nil || contexts != nil {
			t.Fatalf("Clear retained naming contexts: %q, %v", contexts, err)
		}
		putIncrementalNamingEntry(t, tx, "fresh", "dc=fresh", false)
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=fresh")
		if err := tx.Clear(); err != nil {
			t.Fatal(err)
		}
		putIncrementalNamingEntry(t, tx, "last", "dc=last", false)
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=last")
	})
}

func TestNamingContextIncrementalMigration(t *testing.T) {
	store := newIncrementalNamingStore(t)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		for _, raw := range []string{"dc=base", "uid=child,dc=base"} {
			if err := tx.PutIn("legacy", directory.Entry{DN: raw}, false); err != nil {
				t.Fatal(err)
			}
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
	})
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if _, err := MigrateSchemaAwareDNIdentities(tx, "legacy", incrementalNamingNormalizer{}); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		deleteIncrementalNamingEntry(t, tx, "legacy", "dc=base")
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "uid=child,dc=base")
	})
}

func TestNamingContextIncrementalRejectedAndTransientMutations(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if err := PutInWithDN(tx, "data", directory.Entry{DN: "DC=BASE"}, incrementalNamingDN(t, "DC=BASE"), false); !errors.Is(err, ErrEntryExists) {
			t.Fatalf("duplicate put = %v", err)
		}
		if err := tx.DeleteIn("data", incrementalNamingDN(t, "dc=absent")); !errors.Is(err, ErrEntryNotFound) {
			t.Fatalf("absent delete = %v", err)
		}
		if err := tx.PutIn("transient", directory.Entry{DN: "undefinedName=temporary"}, false); err != nil {
			t.Fatalf("mutation introduced an eager schema error: %v", err)
		}
		if err := tx.DeleteIn("transient", mustDN(t, "undefinedName=temporary")); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
	})
}

func TestNamingContextIncrementalExternalRevisionGap(t *testing.T) {
	store := newIncrementalNamingStore(t)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if err := tx.PutIn("data", directory.Entry{DN: "dc=base"}, false); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
	})
	if store.namingIndex == nil {
		t.Fatal("external revision fixture did not warm the index")
	}
	key := []byte(partitionedEntryKey("data", "dc=base"))
	for _, raw := range []string{"DC=BASE", "corrupt", "dc=BASE"} {
		t.Run(raw, func(t *testing.T) {
			encoded := []byte("malformed external entry")
			if raw != "corrupt" {
				var err error
				encoded, err = encodeEntry(directory.Entry{DN: raw}, "", "")
				if err != nil {
					t.Fatal(err)
				}
			}
			// External bbolt commits bypass Store.Update and retain the same row count.
			if err := store.db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(entriesBucket).Put(key, encoded)
			}); err != nil {
				t.Fatal(err)
			}
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if raw == "corrupt" {
					if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err == nil {
						t.Fatal("external corruption was hidden by the warm index")
					}
					return
				}
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, raw)
			})
		})
	}
}

func TestNamingContextIncrementalColdCodecValidation(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		for _, corrupt := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/corrupt-%v", format, corrupt), func(t *testing.T) {
				store := newIncrementalNamingStore(t)
				entry := directory.Entry{DN: "uid=alice,dc=missing", Attributes: []directory.Attribute{
					{Description: "description", Values: [][]byte{[]byte("payload")}, RawNormalized: true},
				}}
				dn := incrementalNamingDN(t, entry.DN)
				encoded := encodeCandidateTestEntry(t, entry, dn.Key(), format)
				if corrupt {
					encoded = encoded[:len(encoded)-1]
				}
				if err := store.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(entriesBucket).Put([]byte(partitionedEntryKey("raw", dn.Key())), encoded)
				}); err != nil {
					t.Fatal(err)
				}
				updateIncrementalNamingStore(t, store, func(tx *boltTx) {
					got, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{})
					if corrupt && err == nil {
						t.Fatal("cold scan accepted truncated attributes")
					}
					if !corrupt && (err != nil || !slices.Equal(got, []string{entry.DN})) {
						t.Fatalf("cold codec inference = %q, %v", got, err)
					}
				})
			})
		}
	}

	// Direct tx.entries.Put after a managed cache has warmed bypasses the supported
	// mutation hooks without a revision gap. Detecting arbitrary private-field
	// writes inside that transaction would require another authoritative scan.
}

func TestNamingContextIncrementalTrackedErrorOrder(t *testing.T) {
	for _, first := range []string{"schema", "codec", "nil", "empty", "binding", "dn", "attributes"} {
		t.Run(first, func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			rollback := errors.New("discard corrupt fixture")
			err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				entry := directory.Entry{DN: "undefinedName=value"}
				encoded, err := encodeEntry(entry, "", "")
				if err != nil {
					return err
				}
				key := partitionedEntryKey("a", "undefinedname=value")
				switch first {
				case "codec":
					encoded = []byte("first malformed entry")
				case "nil":
					encoded = nil
				case "empty":
					encoded = []byte{}
				case "binding":
					key = partitionedEntryKey("a", "dn:v2:invalid")
				case "dn":
					encoded = []byte(`{"dn":"invalid-DN","attributes":[]}`)
				case "attributes":
					entry = directory.Entry{DN: "uid=child,dc=base", Attributes: []directory.Attribute{
						{Description: "description", Values: [][]byte{[]byte("truncated payload")}},
					}}
					dn := incrementalNamingDN(t, entry.DN)
					key = partitionedEntryKey("a", dn.Key())
					encoded = encodeCandidateTestEntry(t, entry, dn.Key(), "v3")
					encoded = encoded[:len(encoded)-1]
				}
				if err := tx.putEntry([]byte(key), encoded); err != nil {
					t.Fatalf("tracked write moved inference validation earlier: %v", err)
				}
				last := []byte(partitionedEntryKey("z", "cn=broken"))
				if err := tx.putEntry(last, []byte("second malformed entry")); err != nil {
					return err
				}
				if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err == nil {
					t.Fatal("warm inference ignored the first corrupt row")
				}
				if first == "nil" {
					return rollback
				}
				if err := tx.deleteEntry([]byte(key)); err != nil {
					return err
				}
				if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err == nil {
					t.Fatal("warm inference ignored the remaining corrupt row")
				}
				if err := tx.deleteEntry(last); err != nil {
					return err
				}
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("corrupt fixture rollback = %v", err)
			}
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
			})
		})
	}
}

func TestNamingContextIncrementalCommitValidationFailure(t *testing.T) {
	for _, failure := range []string{"schema", "attributes"} {
		t.Run(failure, func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			var key []byte
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if failure == "schema" {
					if err := tx.PutIn("bad", directory.Entry{DN: "undefinedName=value"}, false); err != nil {
						t.Fatalf("write introduced eager schema validation: %v", err)
					}
					key = []byte(partitionedEntryKey("bad", "undefinedname=value"))
				} else {
					entry := directory.Entry{DN: "uid=child,dc=base", Attributes: []directory.Attribute{
						{Description: "description", Values: [][]byte{[]byte("truncated payload")}},
					}}
					dn := incrementalNamingDN(t, entry.DN)
					key = []byte(partitionedEntryKey("bad", dn.Key()))
					encoded := encodeCandidateTestEntry(t, entry, dn.Key(), "v3")
					if err := tx.putEntry(key, encoded[:len(encoded)-1]); err != nil {
						t.Fatal(err)
					}
				}
				// Derived validation at commit must invalidate, not reject this write.
			})
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err == nil {
					t.Fatal("commit validation failure left a usable stale index")
				}
				if err := tx.deleteEntry(key); err != nil {
					t.Fatal(err)
				}
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
			})
		})
	}
}

func TestNamingContextIncrementalEmptyDNValidation(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		if err := tx.Clear(); err != nil {
			t.Fatal(err)
		}
		if err := tx.PutIn("root", directory.Entry{DN: ""}, false); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{})
		original := tx.ctx
		ctx, cancel := context.WithCancel(original)
		cancel()
		tx.ctx = ctx
		_, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{})
		tx.ctx = original
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("depth-zero row lost its cancellation checkpoint: %v", err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{})
		key := []byte(partitionedEntryKey("root", ""))
		if err := tx.putEntry(key, []byte("corrupt empty DN entry")); err != nil {
			t.Fatal(err)
		}
		if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err == nil {
			t.Fatal("depth-zero row escaped validation")
		}
		if err := tx.deleteEntry(key); err != nil {
			t.Fatal(err)
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{})
	})
}

func TestNamingContextIncrementalCancellation(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty-%v", empty), func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if empty {
					if err := tx.Clear(); err != nil {
						t.Fatal(err)
					}
					requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{})
				}
				original := tx.ctx
				ctx, cancel := context.WithCancel(original)
				cancel()
				tx.ctx = ctx
				defer func() { tx.ctx = original }()
				_, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{})
				if !empty && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			})
		})
	}
	t.Run("empty after deleting last row", func(t *testing.T) {
		store := newIncrementalNamingStore(t)
		warmIncrementalNamingStore(t, store)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		err := store.Update(ctx, func(writer Writer) error {
			deleteIncrementalNamingEntry(t, writer, "data", "dc=base")
			cancel()
			requireIncrementalNamingContexts(t, writer, incrementalNamingNormalizer{})
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled commit = %v", err)
		}
		updateIncrementalNamingStore(t, store, func(tx *boltTx) {
			requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		})
	})
	t.Run("canceled commit after refresh", func(t *testing.T) {
		store := newIncrementalNamingStore(t)
		warmIncrementalNamingStore(t, store)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		err := store.Update(ctx, func(writer Writer) error {
			deleteIncrementalNamingEntry(t, writer, "data", "dc=base")
			putIncrementalNamingEntry(t, writer, "data", "dc=aborted", false)
			requireIncrementalNamingContexts(t, writer, incrementalNamingNormalizer{}, "dc=aborted")
			cancel()
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled commit = %v", err)
		}
		updateIncrementalNamingStore(t, store, func(tx *boltTx) {
			requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		})
	})
}

type incrementalNamingOptOut struct{ *namingContextParsedNormalizer }

func (incrementalNamingOptOut) NamingContextCacheFingerprint() ([32]byte, bool) {
	return [32]byte{1}, false
}

func TestNamingContextIncrementalCustomNormalizerFallback(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "data", "uid=child,dc=base", false)
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
		injected := errors.New("custom normalizer failure")
		for _, optOut := range []bool{false, true} {
			for failAt := 0; failAt <= 6; failAt++ {
				wantNormalizer := &namingContextParsedNormalizer{failAt: failAt, err: injected}
				gotNormalizer := &namingContextParsedNormalizer{failAt: failAt, err: injected}
				var normalizer directory.DNAttributeNormalizer = gotNormalizer
				if optOut {
					normalizer = incrementalNamingOptOut{gotNormalizer}
				}
				want, wantErr := InferNamingContextsWithNormalizer(tx, wantNormalizer)
				got, gotErr := InferNamingContextsIncremental(tx, normalizer)
				if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
					reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || !reflect.DeepEqual(gotNormalizer.calls, wantNormalizer.calls) {
					t.Fatalf("optOut=%v failAt=%d: got %q/%v/%q; want %q/%v/%q", optOut, failAt,
						got, gotErr, gotNormalizer.calls, want, wantErr, wantNormalizer.calls)
				}
				if failAt > 0 && !errors.Is(gotErr, injected) {
					t.Fatalf("custom error lost: %v", gotErr)
				}
			}
		}
	})
}

func TestNamingContextIncrementalNilNormalizerFallback(t *testing.T) {
	for _, raw := range []string{"no rows", "cn=config", "", "dc=base"} {
		t.Run(raw, func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if raw != "no rows" {
					if err := tx.PutIn("data", directory.Entry{DN: raw}, false); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err != nil {
					t.Fatal(err)
				}
				_, err := incrementalNamingParity(t, tx, nil)
				wantError := raw == "" || raw == "dc=base"
				if (err != nil) != wantError {
					t.Fatalf("nil normalizer error = %v, want error %v", err, wantError)
				}
			})
		})
	}
}

func TestNamingContextIncrementalReaderFallback(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		injected := errors.New("custom reader iteration failure")
		wrapped := namingContextFailureReader{Reader: tx, err: injected}
		if _, err := incrementalNamingParity(t, wrapped, incrementalNamingNormalizer{}); !errors.Is(err, injected) {
			t.Fatalf("custom maintenance reader bypassed: %v", err)
		}
	})
	if err := store.View(t.Context(), func(reader Reader) error {
		requireIncrementalNamingContexts(t, reader, incrementalNamingNormalizer{}, "dc=base")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		requireIncrementalNamingContexts(t, newBoltTx(t.Context(), tx), incrementalNamingNormalizer{}, "dc=base")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	memory := NewMemory()
	t.Cleanup(func() { _ = memory.Close() })
	if err := memory.Update(t.Context(), func(writer Writer) error {
		putIncrementalNamingEntry(t, writer, "data", "dc=memory", false)
		requireIncrementalNamingContexts(t, writer, incrementalNamingNormalizer{}, "dc=memory")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNamingContextIncrementalCapacityFallback(t *testing.T) {
	for _, mode := range []string{"refresh", "commit", "later corruption"} {
		t.Run(mode, func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				// Inject only the estimated budget to avoid allocating a 256 MiB fixture.
				store.namingIndex.bytes = maxNamingContextIndexBytes
				putIncrementalNamingEntry(t, tx, "a", "uid=child,dc=base", false)
				if mode == "commit" {
					return
				}
				if mode == "later corruption" {
					key := []byte(partitionedEntryKey("z", "cn=broken"))
					if err := tx.putEntry(key, []byte("late malformed entry")); err != nil {
						t.Fatal(err)
					}
					_, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{})
					if err == nil || errors.Is(err, errNamingContextIndexCapacity) {
						t.Fatalf("capacity fallback lost authoritative corruption error: %v", err)
					}
					if err := tx.deleteEntry(key); err != nil {
						t.Fatal(err)
					}
				} else {
					requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
				}
				if store.namingIndex != nil {
					t.Fatal("over-budget index was retained after refresh")
				}
			})
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if store.namingIndex != nil {
					t.Fatal("over-budget index survived commit")
				}
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
				if store.namingIndex == nil || store.namingIndex.bytes > maxNamingContextIndexBytes {
					t.Fatal("small directory did not rebuild within the estimated budget")
				}
			})
		})
	}
}

func TestNamingContextIncrementalPrunesDeletedMetadata(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	for cycle := range 8 {
		updateIncrementalNamingStore(t, store, func(tx *boltTx) {
			index := store.namingIndex
			baseline := index.bytes
			parent := fmt.Sprintf("ou=branch%d,dc=base", cycle)
			child := "uid=leaf," + parent
			for _, partition := range []string{"a", "m", "z"} {
				putIncrementalNamingEntry(t, tx, partition, child, false)
			}
			putIncrementalNamingEntry(t, tx, "parent", parent, false)
			if err := tx.PutIn("root", directory.Entry{DN: ""}, false); err != nil {
				t.Fatal(err)
			}
			requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
			if index.bytes <= baseline {
				t.Fatal("estimated size did not include added rows")
			}
			deleteIncrementalNamingEntry(t, tx, "parent", parent)
			requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base", child)
			for _, partition := range []string{"z", "a", "m"} {
				deleteIncrementalNamingEntry(t, tx, partition, child)
				if _, err := incrementalNamingParity(t, tx, incrementalNamingNormalizer{}); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.DeleteIn("root", mustDN(t, "")); err != nil {
				t.Fatal(err)
			}
			requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base")
			if store.namingIndex != index {
				t.Fatal("pruning fixture unexpectedly rebuilt the index")
			}
			if index.bytes != baseline || len(index.rows) != 1 || len(index.nodes) != 1 || len(index.roots) != 1 || len(index.children) != 0 {
				t.Fatalf("cycle %d retained metadata: bytes=%d baseline=%d rows=%d nodes=%d roots=%d children=%d",
					cycle, index.bytes, baseline, len(index.rows), len(index.nodes), len(index.roots), len(index.children))
			}
		})
	}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		deleteIncrementalNamingEntry(t, tx, "data", "dc=base")
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{})
		index := store.namingIndex
		if index.bytes != 0 || len(index.rows)+len(index.nodes)+len(index.roots)+len(index.children) != 0 {
			t.Fatalf("empty directory retained derived metadata: %#v", index)
		}
	})
}

func TestNamingContextIncrementalRandomizedMutations(t *testing.T) {
	type fixture struct{ key, value []byte }
	var fixtures []fixture
	for _, partition := range []string{"", "a", "m", "z", OpenLDAPConfigPartition, "pending"} {
		for _, raw := range []string{
			"", "dc=example", "DC=EXAMPLE", "ou=parent,dc=example", "OU=Parent,DC=EXAMPLE",
			"uid=leaf,ou=parent,dc=example", "uid=orphan,ou=missing,dc=example", "ou=missing,dc=example",
			"exactName=Root", "exactName=root", "uid=child,exactName=Root", "uid=child,exactName=ROOT",
			"cn=config", "CN=CONFIG", "olcDatabase={0}config,cn=config", "undefinedName=value,cn=config",
			"2.5.4.3=config", `cn=A\,B+uid=alice,dc=missing`, `userid=ALICE+2.5.4.3=a\,b,dc=missing`,
		} {
			entry := directory.Entry{DN: raw}
			encoded, err := encodeEntry(entry, "", "")
			if err != nil {
				t.Fatal(err)
			}
			fixtures = append(fixtures, fixture{[]byte(partitionedEntryKey(partition, mustDN(t, raw).Key())), encoded})
			dn, err := directory.ParseDNWithNormalizer(raw, incrementalNamingNormalizer{})
			if err != nil || raw == "" {
				continue
			}
			encoded, err = encodeEntry(entry, dn.Key(), raw)
			if err != nil {
				t.Fatal(err)
			}
			fixtures = append(fixtures, fixture{[]byte(partitionedEntryKey(partition, dn.Key())), encoded})
		}
	}
	for _, seed := range []uint64{1, 0x6f97cf, 20260923} {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			store := newIncrementalNamingStore(t)
			warmIncrementalNamingStore(t, store)
			random := rand.New(rand.NewPCG(seed, ^seed))
			normalizers := [2]incrementalNamingNormalizer{{}, {foldExact: true}}
			selected := 0
			rollback := errors.New("randomized rollback")
			for round := range 32 {
				t.Run(fmt.Sprintf("round-%02d", round), func(t *testing.T) {
					err := store.Update(t.Context(), func(writer Writer) error {
						tx := writer.(*boltTx)
						if _, err := incrementalNamingParity(t, tx, normalizers[selected]); err != nil {
							t.Fatal(err)
						}
						for operation := range 8 {
							row := fixtures[random.IntN(len(fixtures))]
							if operation == 0 && round%17 == 16 {
								if err := tx.Clear(); err != nil {
									t.Fatal(err)
								}
							} else {
								switch random.IntN(10) {
								case 0, 1, 2:
									if err := tx.deleteEntry(row.key); err != nil {
										t.Fatal(err)
									}
								case 3:
									selected = 1 - selected
								default:
									if err := tx.putEntry(row.key, row.value); err != nil {
										t.Fatal(err)
									}
								}
							}
							if round%3 != 0 && random.IntN(2) == 0 {
								if _, err := incrementalNamingParity(t, tx, normalizers[selected]); err != nil {
									t.Fatalf("operation %d: %v", operation, err)
								}
							}
						}
						if round%7 == 0 {
							return rollback
						}
						return nil
					})
					if round%7 == 0 {
						if !errors.Is(err, rollback) {
							t.Fatalf("rollback = %v", err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				})
			}
			updateIncrementalNamingStore(t, store, func(tx *boltTx) {
				if _, err := incrementalNamingParity(t, tx, normalizers[selected]); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestNamingContextIncrementalRandomizedCodecMutations(t *testing.T) {
	store := newIncrementalNamingStore(t)
	warmIncrementalNamingStore(t, store)
	rows := []struct {
		partition string
		entry     directory.Entry
	}{
		{"a", directory.Entry{DN: "uid=child,dc=base"}},
		{"z", directory.Entry{DN: "UID=CHILD,dc=base"}},
		{"root", directory.Entry{DN: "exactName=Root"}},
		{OpenLDAPConfigPartition, directory.Entry{DN: "cn=config"}},
	}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		for index := range rows {
			row := &rows[index]
			row.entry.Attributes = []directory.Attribute{
				{Description: "description", Values: [][]byte{[]byte("mutable codec payload")}, RawNormalized: true},
				{Description: "jpegPhoto", Values: [][]byte{{0, 0xff, 0x80}, {}}},
			}
			if err := PutInWithDN(tx, row.partition, row.entry, incrementalNamingDN(t, row.entry.DN), false); err != nil {
				t.Fatal(err)
			}
		}
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base", "exactName=Root", "cn=config")
	})
	formats := []string{"v1", "v2", "v3", "json"}
	random := rand.New(rand.NewPCG(0x6f97cf, 20260923))
	rollback := errors.New("discard randomized codec mutation")
	for trial := range 64 {
		t.Run(fmt.Sprintf("trial-%02d", trial), func(t *testing.T) {
			row := rows[random.IntN(len(rows))]
			dn := incrementalNamingDN(t, row.entry.DN)
			key := []byte(partitionedEntryKey(row.partition, dn.Key()))
			encoded := encodeCandidateTestEntry(t, row.entry, dn.Key(), formats[trial%len(formats)])
			err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base", "exactName=Root", "cn=config")
				if err := tx.putEntry(key, encoded); err != nil {
					return err
				}
				requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base", "exactName=Root", "cn=config")
				mutated := bytes.Clone(encoded)
				switch trial % 5 {
				case 0:
					mutated = mutated[:random.IntN(len(mutated))]
				case 1:
					mutated[random.IntN(len(mutated))] ^= byte(1 + random.IntN(255))
				case 2:
					mutated = append(mutated, byte(random.IntN(256)))
				case 3:
					mutated = nil
				case 4:
					mutated = []byte{}
				}
				if err := tx.putEntry(key, mutated); err != nil {
					return err
				}
				if trial%2 == 0 {
					if err := tx.putEntry([]byte(partitionedEntryKey("zzzz", "cn=broken")), []byte("later corruption")); err != nil {
						return err
					}
				}
				_, _ = incrementalNamingParity(t, tx, incrementalNamingNormalizer{})
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("codec trial rollback = %v", err)
			}
		})
	}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		requireIncrementalNamingContexts(t, tx, incrementalNamingNormalizer{}, "dc=base", "exactName=Root", "cn=config")
	})
}
