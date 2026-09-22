package storage

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// BenchmarkNamingContextParsedInference isolates inference on the same read
// snapshot. Fixture creation, transactions, and CRUD are outside the timed loop.
func BenchmarkNamingContextParsedInference(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("Entries%d", count), func(b *testing.B) {
			store, err := OpenBolt(filepath.Join(b.TempDir(), "inference.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			const root = "dc=example,dc=com"
			attributes := []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{[]byte("top")}},
				{Description: "cn", Values: [][]byte{[]byte("Example")}},
				{Description: "sn", Values: [][]byte{[]byte("Example")}},
				{Description: "description", Values: [][]byte{bytes.Repeat([]byte("x"), 256)}},
			}
			if err := store.Update(b.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				for i := range count {
					raw := root
					if i != 0 {
						raw = fmt.Sprintf("uid=user%06d,%s", i, root)
					}
					dn, err := directory.ParseDNWithNormalizer(raw, testDNNormalizer{})
					if err != nil {
						return err
					}
					encoded, err := encodeEntry(directory.Entry{DN: raw, Attributes: attributes}, dn.Key(), raw)
					if err != nil {
						return err
					}
					if err := tx.putEntry([]byte(partitionedEntryKey("db", dn.Key())), encoded); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
			for _, implementation := range []struct {
				name  string
				infer func(Reader, directory.DNAttributeNormalizer) ([]string, error)
			}{
				{"NormalizingInference", InferNamingContextsWithNormalizer},
				{"Metadata", InferNamingContextsMetadataWithNormalizer},
			} {
				b.Run(implementation.name, func(b *testing.B) {
					b.ReportAllocs()
					if err := store.View(b.Context(), func(reader Reader) error {
						for b.Loop() {
							contexts, err := implementation.infer(reader, testDNNormalizer{})
							if err != nil {
								return err
							}
							if len(contexts) != 1 || contexts[0] != root {
								return fmt.Errorf("unexpected contexts: %q", contexts)
							}
						}
						return nil
					}); err != nil {
						b.Fatal(err)
					}
				})
			}
		})
	}
}
