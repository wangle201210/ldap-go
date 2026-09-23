package storage

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// The timed loop changes a leaf and refreshes twice in the same write
// transaction. Setup, the initial index build and durable commit are excluded.
func BenchmarkNamingContextIncrementalWrites(b *testing.B) {
	for _, count := range []int{1000, 100000} {
		b.Run(fmt.Sprintf("Entries%d", count), func(b *testing.B) {
			store, err := OpenBolt(filepath.Join(b.TempDir(), "naming.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = store.Close() })
			normalizer := incrementalNamingNormalizer{}
			const root = "dc=example,dc=com"
			if err := store.Update(b.Context(), func(writer Writer) error {
				for i := range count + 1 {
					raw := root
					if i != 0 {
						raw = fmt.Sprintf("uid=user%06d,%s", i, root)
					}
					dn, err := directory.ParseDNWithNormalizer(raw, normalizer)
					if err != nil {
						return err
					}
					if err := PutInWithDN(writer, "db", directory.Entry{DN: raw}, dn, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
			probe := directory.Entry{DN: "uid=probe," + root}
			dn, err := directory.ParseDNWithNormalizer(probe.DN, normalizer)
			if err != nil {
				b.Fatal(err)
			}
			for _, test := range []struct {
				name  string
				infer func(Reader, directory.DNAttributeNormalizer) ([]string, error)
			}{
				{"Scan", InferNamingContextsMetadataWithNormalizer},
				{"Incremental", InferNamingContextsIncremental},
			} {
				b.Run(test.name, func(b *testing.B) {
					b.ReportAllocs()
					if err := store.Update(b.Context(), func(writer Writer) error {
						check := func() error {
							contexts, err := test.infer(writer, normalizer)
							if err != nil {
								return err
							}
							if len(contexts) != 1 || contexts[0] != root {
								return fmt.Errorf("unexpected naming contexts %q", contexts)
							}
							return nil
						}
						if err := check(); err != nil {
							return err
						}
						for b.Loop() {
							if err := PutInWithDN(writer, "db", probe, dn, false); err != nil {
								return err
							}
							if err := check(); err != nil {
								return err
							}
							if err := writer.DeleteIn("db", dn); err != nil {
								return err
							}
							if err := check(); err != nil {
								return err
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
