package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func newDeletePreflightStore(t *testing.T, format string) *Bolt {
	t.Helper()
	store, err := OpenBolt(filepath.Join(t.TempDir(), "delete.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		for i, raw := range []string{
			"dc=example", "uid=parent,dc=example",
			"uid=grandchild,uid=missing,uid=parent,dc=example",
			"exactName=Root,dc=example", "exactName=root,dc=example",
			"uid=child,exactName=Root,dc=example",
			`uid=Comma\, Value+exactName=Root,dc=example`,
			"UID=NONCANONICAL,DC=EXAMPLE",
			"uid= spaced  value ,dc=example",
		} {
			dn, err := directory.ParseDNWithNormalizer(raw, testDNNormalizer{})
			if err != nil {
				return err
			}
			entry := directory.Entry{DN: raw, Attributes: []directory.Attribute{
				{Description: "description", Values: [][]byte{bytes.Repeat([]byte("x"), 4096)}, RawNormalized: true},
				{Description: "binary;lang-en", Values: [][]byte{nil, {}, {0, 255}}},
			}}
			mode := format
			if mode == "mixed" {
				mode = []string{"v1", "v2", "v3", "json"}[i%4]
			}
			if err := tx.putEntry([]byte(partitionedEntryKey("db", dn.Key())), encodeCandidateTestEntry(t, entry, dn.Key(), mode)); err != nil {
				return err
			}
		}
		if err := tx.putEntry([]byte(partitionedEntryKey("unrelated", "broken")), []byte("broken")); err != nil {
			return err
		}
		return tx.setSchemaAwareDNIdentityReady("db")
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDeletePreflightMetadataParityAndOwnership(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v3", "json", "mixed"} {
		t.Run(format, func(t *testing.T) {
			store := newDeletePreflightStore(t, format)
			var want, got []directory.Entry
			if err := store.Update(t.Context(), func(writer Writer) error {
				scoped := WriterInPartitionWithNormalizerLegacy(writer, "db", testDNNormalizer{})
				if err := scoped.ForEach(func(entry directory.Entry) error {
					entry.Attributes = nil
					want = append(want, entry)
					return nil
				}); err != nil {
					return err
				}
				handled, err := ForEachDeleteCandidateDN(scoped, func(entry directory.Entry) error {
					if entry.Attributes != nil {
						t.Fatal("metadata materialized attributes")
					}
					got = append(got, entry)
					return nil
				})
				if !handled {
					t.Fatal("eligible writer was not handled")
				}
				if err != nil {
					return err
				}
				return writer.Clear()
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || len(got) != 9 {
				t.Fatal("DNs, identity hints, ordering or ownership differ after mutation and unmap")
			}
		})
	}
}

func TestDeletePreflightDecoderParity(t *testing.T) {
	entry := directory.Entry{DN: "uid=alice,dc=example", Attributes: []directory.Attribute{
		{Description: "cn", Values: [][]byte{[]byte("Alice"), nil}, RawNormalized: true},
	}}
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		encoded := encodeCandidateTestEntry(t, entry, "dn:v2:binding", format)
		check := func(value []byte) {
			t.Helper()
			want, wantErr := decodeStoredEntry(value)
			got, gotErr := decodeDeleteDNMetadata(value)
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) ||
				gotErr == nil && (got.DN != want.DN || got.Attributes != nil) {
				t.Fatalf("%s bytes=%x: got %q/%v, want %q/%v", format, value, got.DN, gotErr, want.DN, wantErr)
			}
		}
		check(encoded)
		for i := range encoded {
			check(encoded[:i])
			mutated := bytes.Clone(encoded)
			mutated[i] ^= 255
			check(mutated)
		}
		check(append(bytes.Clone(encoded), 0))
		got, err := decodeDeleteDNMetadata(encoded)
		if err != nil {
			t.Fatal(err)
		}
		clear(encoded)
		if got.DN != entry.DN {
			t.Fatal("DN borrowed decoder input")
		}
	}
}

func TestDeletePreflightValidationAndCancellation(t *testing.T) {
	for _, damage := range []string{"none", "early-codec", "late-codec", "bad-dn", "bad-key", "wrong-depth", "empty-key", "legacy-key", "bad-binding"} {
		t.Run(damage, func(t *testing.T) {
			store := newDeletePreflightStore(t, "mixed")
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				prefix := []byte("db\x00")
				var keys [][]byte
				cursor := tx.entries.Cursor()
				for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
					keys = append(keys, bytes.Clone(key))
				}
				key := keys[len(keys)-1]
				stored, err := decodeStoredEntry(tx.entries.Get(key))
				if err != nil {
					return err
				}
				identity := string(key[len(prefix):])
				switch damage {
				case "early-codec":
					err = tx.entries.Put(keys[0], []byte("broken"))
				case "late-codec":
					err = tx.entries.Put(key, []byte("broken"))
				case "bad-dn":
					stored.DN = "uid=broken,"
					err = tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "v2"))
				case "wrong-depth":
					stored.DN = "uid=a,uid=b,uid=c,uid=d,dc=example"
					err = tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "v2"))
				case "bad-key", "empty-key", "legacy-key":
					if err := tx.entries.Delete(key); err != nil {
						return err
					}
					replacement := "dn:v2:!"
					if damage == "empty-key" {
						replacement = ""
					} else if damage == "legacy-key" {
						legacy, err := directory.ParseDN(stored.DN)
						if err != nil {
							return err
						}
						replacement = legacy.Key()
					}
					err = tx.entries.Put([]byte(partitionedEntryKey("db", replacement)), encodeCandidateTestEntry(t, stored.Entry, identity, "v2"))
				case "bad-binding":
					// Physical ForEach does not validate binding contents. Do not move
					// a later write/refresh failure ahead of the ancestry result.
					err = tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, "different binding", "v2"))
				}
				if err != nil {
					return err
				}
				originalContext := tx.ctx
				defer func() { tx.ctx = originalContext }()
				for _, cancelAt := range []int{1, 2, 5, 10, 11, 100} {
					for _, stopAt := range []int{0, 1, 4} {
						var want []directory.Entry
						var wantErr error
						var wantRemaining int
						for _, metadata := range []bool{false, true} {
							ctx, cancel := context.WithCancel(context.Background())
							checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
							tx.ctx = checked
							scoped := WriterInPartitionWithNormalizerLegacy(writer, "db", testDNNormalizer{})
							var rows []directory.Entry
							visit := func(entry directory.Entry) error {
								entry.Attributes = nil
								rows = append(rows, entry)
								if len(rows) == stopAt {
									return errors.New("callback stop")
								}
								return nil
							}
							var scanErr error
							if metadata {
								var handled bool
								handled, scanErr = ForEachDeleteCandidateDN(scoped, visit)
								if !handled {
									t.Fatal("eligible writer was not handled")
								}
							} else {
								scanErr = scoped.ForEach(visit)
							}
							cancel()
							if !metadata {
								want, wantErr, wantRemaining = rows, scanErr, checked.remaining
							} else if !reflect.DeepEqual(rows, want) || fmt.Sprint(scanErr) != fmt.Sprint(wantErr) ||
								reflect.TypeOf(scanErr) != reflect.TypeOf(wantErr) || checked.remaining != wantRemaining {
								t.Fatalf("cancel=%d stop=%d: rows/error/checkpoints differ: %v vs %v", cancelAt, stopAt, scanErr, wantErr)
							}
						}
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type deletePreflightWrappedWriter struct {
	Writer
	err error
}

func (writer deletePreflightWrappedWriter) ForEach(func(directory.Entry) error) error {
	return writer.err
}

func (writer deletePreflightWrappedWriter) MaintenanceStorageReader() Reader { return writer.Writer }

func TestDeletePreflightUnsupportedFallback(t *testing.T) {
	store := newDeletePreflightStore(t, "v2")
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		originalContext := tx.ctx
		defer func() { tx.ctx = originalContext }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: 100}
		tx.ctx = checked
		injected := errors.New("decorator iteration error")
		wrapped := deletePreflightWrappedWriter{Writer: WriterInPartitionWithNormalizer(writer, "db", testDNNormalizer{}), err: injected}
		for _, unsupported := range []Writer{writer, WriterInPartition(writer, "db"),
			WriterInPartitionWithNormalizer(writer, "", testDNNormalizer{}),
			WriterInPartitionWithNormalizer(writer, "db\x00nested", testDNNormalizer{}), wrapped} {
			handled, err := ForEachDeleteCandidateDN(unsupported, func(directory.Entry) error { t.Fatal("unsupported callback"); return nil })
			if handled || err != nil || checked.remaining != 100 {
				t.Fatalf("unsupported writer consumed work: %v/%v/%d", handled, err, checked.remaining)
			}
		}
		if err := wrapped.ForEach(func(directory.Entry) error { return nil }); !errors.Is(err, injected) {
			t.Fatal("fallback lost decorator error")
		}
		for _, marker := range [][]byte{nil, {}, {255}} {
			key := boltSchemaAwareDNMigrationMetadataKey("db")
			if marker == nil {
				if err := tx.meta.Delete(key); err != nil {
					return err
				}
			} else if err := tx.meta.Put(key, marker); err != nil {
				return err
			}
			handled, err := ForEachDeleteCandidateDN(WriterInPartitionWithNormalizer(writer, "db", testDNNormalizer{}), func(directory.Entry) error { t.Fatal("marker fallback callback"); return nil })
			if handled || err != nil || checked.remaining != 100 {
				t.Fatal("marker fallback consumed work")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.View(t.Context(), func(reader Reader) error {
		handled, err := ForEachDeleteCandidateDN(WriterInPartitionWithNormalizer(reader.(Writer), "db", testDNNormalizer{}), func(directory.Entry) error { t.Fatal("read transaction callback"); return nil })
		if handled || err != nil {
			t.Fatal("read transaction was handled")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	memory := NewMemory()
	t.Cleanup(func() { _ = memory.Close() })
	if err := memory.Update(t.Context(), func(writer Writer) error {
		handled, err := ForEachDeleteCandidateDN(WriterInPartitionWithNormalizer(writer, "db", testDNNormalizer{}), func(directory.Entry) error { t.Fatal("memory callback"); return nil })
		if handled || err != nil {
			t.Fatal("memory writer was handled")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
