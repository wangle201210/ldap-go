package storage

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type namingContextParsedNormalizer struct {
	testCanonicalDNNormalizer
	calls  []string
	failAt int
	err    error
}

func (n *namingContextParsedNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	n.calls = append(n.calls, "normalize:"+attribute+"="+string(value))
	if len(n.calls) == n.failAt {
		return "", nil, n.err
	}
	canonical, normalized, err := n.testCanonicalDNNormalizer.NormalizeDNAttribute(attribute, value)
	// Deliberately differ from the schema that produced the physical identities.
	return canonical, bytes.ToLower(normalized), err
}

func (n *namingContextParsedNormalizer) CanonicalDNAttributeName(attribute string) (string, error) {
	n.calls = append(n.calls, "canonical:"+attribute)
	if len(n.calls) == n.failAt {
		return "", n.err
	}
	return n.testCanonicalDNNormalizer.CanonicalDNAttributeName(attribute)
}

func TestNamingContextParsedCurrentSchemaAndCallOrder(t *testing.T) {
	for _, backend := range []string{"bolt", "memory"} {
		t.Run(backend, func(t *testing.T) {
			var store Store = NewMemory()
			if backend == "bolt" {
				var err error
				store, err = OpenBolt(filepath.Join(t.TempDir(), "parsed.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(t.Context(), func(writer Writer) error {
				for _, row := range []struct{ partition, raw string }{
					{OpenLDAPConfigPartition, "cn=config"},
					{"pending", "uid=Configuration,cn=config"},
					{"a", "exactName=Root"}, {"b", "exactName=root"},
					{"c", "uid=child,exactName=ROOT"},
					{"d", "uid=Orphan,dc=missing"}, {"empty", ""},
				} {
					entry := directory.Entry{DN: row.raw}
					if row.partition == OpenLDAPConfigPartition || row.partition == "pending" || row.raw == "" {
						if err := writer.PutIn(row.partition, entry, false); err != nil {
							return err
						}
						continue
					}
					dn, err := directory.ParseDNWithNormalizer(row.raw, testCanonicalDNNormalizer{})
					if err != nil {
						return err
					}
					if err := PutInWithDN(writer, row.partition, entry, dn, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected naming failure")
			if err := store.View(t.Context(), func(reader Reader) error {
				for failAt := 0; failAt <= 12; failAt++ {
					reference := &namingContextParsedNormalizer{failAt: failAt, err: injected}
					want, wantErr := InferNamingContextsWithNormalizer(reader, reference)
					current := &namingContextParsedNormalizer{failAt: failAt, err: injected}
					got, gotErr := InferNamingContextsMetadataWithNormalizer(reader, current)
					if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
						reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || !reflect.DeepEqual(current.calls, reference.calls) {
						t.Fatalf("failure %d: got %q, %v, %q; want %q, %v, %q", failAt, got, gotErr, current.calls, want, wantErr, reference.calls)
					}
					if failAt != 0 && !errors.Is(gotErr, injected) {
						t.Fatalf("lost error at call %d: %v", failAt, gotErr)
					}
					if failAt == 0 {
						if gotErr != nil || len(got) != 3 {
							t.Fatalf("current schema roots = %q, %v", got, gotErr)
						}
						for _, raw := range []string{"cn=config", "exactName=root", "uid=Orphan,dc=missing"} {
							if !slices.Contains(got, raw) {
								t.Fatalf("missing current-schema root %q in %q", raw, got)
							}
						}
					}
				}
				_, wantErr := InferNamingContextsWithNormalizer(reader, nil)
				_, gotErr := InferNamingContextsMetadataWithNormalizer(reader, nil)
				if wantErr == nil || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Fatalf("nil normalizer: got %v, want %v", gotErr, wantErr)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNamingContextParsedDecoderOwnership(t *testing.T) {
	const raw = `uid=ALICE\, Smith+exactName=Root,dc=Example`
	dn, err := directory.ParseDNWithNormalizer(raw, testCanonicalDNNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	wantLegacy, err := directory.ParseDN(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		t.Run(format, func(t *testing.T) {
			encoded := encodeCandidateTestEntry(t, directory.Entry{DN: raw}, dn.Key(), format)
			entry, legacy, err := decodeNamingContextMetadataDN(dn.Key(), encoded)
			if err != nil {
				t.Fatal(err)
			}
			clear(encoded)
			if entry.DN != raw || !reflect.DeepEqual(legacy, wantLegacy) || legacy.Key() == dn.Key() {
				t.Fatal("metadata retained borrowed bytes or substituted the physical identity")
			}
		})
	}
}

func TestNamingContextParsedCodecInferenceParity(t *testing.T) {
	const raw = "uid=ALICE,exactName=Root"
	dn, err := directory.ParseDNWithNormalizer(raw, testCanonicalDNNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		t.Run(format, func(t *testing.T) {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "codec.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			encoded := encodeCandidateTestEntry(t, directory.Entry{DN: raw}, dn.Key(), format)
			if validBinaryCandidateEntry(encoded) != (format != "json") {
				t.Fatal("fixture does not exercise the intended decoder path")
			}
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				if err := tx.entries.Put([]byte(partitionedEntryKey("data", dn.Key())), encoded); err != nil {
					return err
				}
				injected := errors.New("codec inference normalizer failure")
				for failAt := -1; failAt <= 4; failAt++ {
					current := &namingContextParsedNormalizer{failAt: failAt, err: injected}
					reference := &namingContextParsedNormalizer{failAt: failAt, err: injected}
					var gotNormalizer, wantNormalizer directory.DNAttributeNormalizer = current, reference
					if failAt == -1 {
						gotNormalizer, wantNormalizer = nil, nil
					}
					want, wantErr := InferNamingContextsWithNormalizer(writer, wantNormalizer)
					got, gotErr := InferNamingContextsMetadataWithNormalizer(writer, gotNormalizer)
					if !reflect.DeepEqual(got, want) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
						reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || !reflect.DeepEqual(current.calls, reference.calls) {
						t.Fatalf("failure %d: got %q, %v, %q; want %q, %v, %q", failAt, got, gotErr, current.calls, want, wantErr, reference.calls)
					}
					if failAt > 0 && !errors.Is(gotErr, injected) {
						t.Fatalf("lost injected error: %v", gotErr)
					}
					if failAt == -1 && (gotErr == nil || gotErr.Error() != "scan directory entries: DN attribute normalizer is required") {
						t.Fatalf("nil normalizer error = %v", gotErr)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
