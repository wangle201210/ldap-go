package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	bolt "go.etcd.io/bbolt"
)

func legacyScanReference(tx *boltTx, fn func(directory.Entry) error) error {
	cursor := tx.entries.Cursor()
	for key, value := cursor.Seek([]byte{0}); key != nil && bytes.HasPrefix(key, []byte{0}); key, value = cursor.Next() {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		_, physical := splitPartitionedEntryKey(string(key))
		entry, err := decodeAndValidateEntry(physical, value)
		if err != nil {
			return err
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		if bytes.IndexByte(key, 0) >= 0 {
			continue
		}
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		entry, err := decodeAndValidateEntry(string(key), value)
		if err != nil {
			return err
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	return nil
}

func legacyScanFixture(t testing.TB, count int) *Bolt {
	t.Helper()
	store, err := OpenBolt(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	err = store.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(entriesBucket)
		for _, raw := range []string{"cn=a", "cn=middle", "cn=z"} {
			dn, err := directory.ParseDN(raw)
			if err != nil {
				return err
			}
			entry := directory.Entry{DN: raw}
			value, err := encodeEntry(entry, "", "")
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte(dn.LegacyKey()), value); err != nil {
				return err
			}
			if raw == "cn=a" {
				if err := bucket.Put(append([]byte{0}, []byte(dn.LegacyKey())...), value); err != nil {
					return err
				}
			}
		}
		for _, partition := range []string{"a", "cn=", "cn=m", "cn=middle", "cn=middle\x01", "z", strings.Repeat("long", 100)} {
			for i := 0; i < count; i++ {
				if err := bucket.Put([]byte(fmt.Sprintf("%s\x00%08d", partition, i)), []byte("ignored corrupt partition entry")); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestBoltLegacyScanMatchesReference(t *testing.T) {
	store := legacyScanFixture(t, 150)
	for _, mode := range []string{"all", "stop", "cancel", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "corrupt" {
				if err := store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(entriesBucket).Put([]byte("cn=middle"), []byte("corrupt")) }); err != nil {
					t.Fatal(err)
				}
			}
			var reference []string
			var referenceErr string
			for _, optimized := range []bool{false, true} {
				ctx, cancel := context.WithCancel(context.Background())
				var got []string
				err := store.View(ctx, func(reader Reader) error {
					tx := reader.(*boltTx)
					visit := func(entry directory.Entry) error {
						got = append(got, entry.DN)
						if len(got) == 2 {
							if mode == "stop" {
								return errors.New("callback stop")
							}
							if mode == "cancel" {
								cancel()
							}
						}
						return nil
					}
					if optimized {
						return tx.ForEachIn("", visit)
					}
					return legacyScanReference(tx, visit)
				})
				cancel()
				message := fmt.Sprint(err)
				if mode == "all" && (err != nil || len(got) != 4) {
					t.Fatalf("full scan returned %v/%s, want four entries", got, message)
				}
				if !optimized {
					reference, referenceErr = got, message
				} else if !reflect.DeepEqual(got, reference) || message != referenceErr {
					t.Fatalf("got %v/%s, want %v/%s", got, message, reference, referenceErr)
				}
			}
		})
	}
}

func BenchmarkBoltLegacyPartitionScan(b *testing.B) {
	store := legacyScanFixture(b, 15000)
	for _, optimized := range []bool{false, true} {
		b.Run(fmt.Sprintf("optimized=%t", optimized), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				err := store.View(context.Background(), func(reader Reader) error {
					tx := reader.(*boltTx)
					visit := func(directory.Entry) error { return nil }
					if optimized {
						return tx.ForEachIn("", visit)
					}
					return legacyScanReference(tx, visit)
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
