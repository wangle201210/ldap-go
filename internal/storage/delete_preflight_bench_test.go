package storage

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// BenchmarkDeletePreflight isolates the nonleaf scan in a writable transaction.
// Fixture creation and transaction commits are outside the timed loop.
func BenchmarkDeletePreflight(b *testing.B) {
	for _, payload := range []int{256, 16 << 10} {
		b.Run(fmt.Sprintf("Entries10000/Payload%d", payload), func(b *testing.B) {
			store, err := OpenBolt(filepath.Join(b.TempDir(), "preflight.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			if err := store.Update(b.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				for i := 0; i < 10000; i++ {
					raw := fmt.Sprintf("uid=user%06d,dc=example,dc=com", i)
					dn, err := directory.ParseDNWithNormalizer(raw, testDNNormalizer{})
					if err != nil {
						return err
					}
					encoded, err := encodeEntry(directory.Entry{DN: raw, Attributes: []directory.Attribute{
						{Description: "description", Values: [][]byte{bytes.Repeat([]byte("x"), payload)}},
					}}, dn.Key(), raw)
					if err != nil {
						return err
					}
					if err := tx.putEntry([]byte(partitionedEntryKey("db", dn.Key())), encoded); err != nil {
						return err
					}
				}
				return tx.setSchemaAwareDNIdentityReady("db")
			}); err != nil {
				b.Fatal(err)
			}
			base, err := directory.ParseDNWithNormalizer("uid=user000000,dc=example,dc=com", testDNNormalizer{})
			if err != nil {
				b.Fatal(err)
			}
			for _, implementation := range []string{"ForEach", "Metadata"} {
				b.Run(implementation, func(b *testing.B) {
					b.ReportAllocs()
					if err := store.Update(b.Context(), func(writer Writer) error {
						scoped := WriterInPartitionWithNormalizerLegacy(writer, "db", testDNNormalizer{})
						for b.Loop() {
							hasChildren := false
							visit := func(entry directory.Entry) error {
								dn, ok := entry.NormalizedDNHint()
								if !ok || dn.String() != entry.DN {
									var err error
									dn, err = directory.ParseDN(entry.DN)
									if err != nil {
										return err
									}
									dn, err = NormalizeReaderDN(scoped, dn)
									if err != nil {
										return err
									}
								}
								if base.AncestorOf(dn) {
									hasChildren = true
								}
								return nil
							}
							var err error
							if implementation == "Metadata" {
								var handled bool
								handled, err = ForEachDeleteCandidateDN(scoped, visit)
								if !handled {
									return fmt.Errorf("metadata preflight was not selected")
								}
							} else {
								err = scoped.ForEach(visit)
							}
							if err != nil {
								return err
							}
							if hasChildren {
								return fmt.Errorf("leaf unexpectedly has descendants")
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
