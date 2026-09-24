package storage

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type smallCandidateRecordingSchema struct {
	indexTestSchema
	calls    []string
	failAt   string
	failure  error
	retained []directory.Entry
}

func (schema *smallCandidateRecordingSchema) record(stage, argument string) error {
	schema.calls = append(schema.calls, stage+":"+argument)
	if schema.failAt == stage {
		return schema.failure
	}
	return nil
}

func (schema *smallCandidateRecordingSchema) EqualityIndexConfiguration() EqualityIndexConfig {
	schema.calls = append(schema.calls, "configuration")
	return schema.indexTestSchema.EqualityIndexConfiguration()
}

func (schema *smallCandidateRecordingSchema) ResolveEqualityIndexAttribute(description string) (string, bool, bool, error) {
	if err := schema.record("resolve", description); err != nil {
		return "", false, false, err
	}
	return schema.indexTestSchema.ResolveEqualityIndexAttribute(description)
}

func (schema *smallCandidateRecordingSchema) NormalizeEqualityIndexAssertion(description string, value []byte) ([]byte, error) {
	if err := schema.record("assertion", description+"="+string(value)); err != nil {
		return nil, err
	}
	// Custom normalizers may mutate caller-owned assertion buffers.
	value[0] = 'S'
	return schema.indexTestSchema.NormalizeEqualityIndexAssertion(description, value)
}

func (schema *smallCandidateRecordingSchema) NormalizeDNAttribute(description string, value []byte) (string, []byte, error) {
	if err := schema.record("dn", description+"="+string(value)); err != nil {
		return "", nil, err
	}
	return schema.indexTestSchema.NormalizeDNAttribute(description, value)
}

func (schema *smallCandidateRecordingSchema) ResolveDNIdentityHint(entry directory.Entry, identity string) (directory.Entry, error) {
	if err := schema.record("hint", identity); err != nil {
		return directory.Entry{}, err
	}
	// The non-equality planner passes owned entries to custom hint resolvers.
	entry.Attributes[0].Values[0][0] = 'T'
	schema.retained = append(schema.retained, entry)
	return entry, nil
}

type smallCandidateReferenceSchema struct {
	*smallCandidateRecordingSchema
}

func (schema smallCandidateReferenceSchema) ResolveEqualityIndexDNReference(reference string) (directory.DN, error) {
	if err := schema.record("reference", reference); err != nil {
		return directory.DN{}, err
	}
	return directory.ParseDNWithNormalizer(reference, schema.smallCandidateRecordingSchema)
}

func TestReadOnlySmallCandidatesCustomSchemaFallbacks(t *testing.T) {
	for _, mode := range []string{"physical", "display-reference", "legacy-entry", "and-filter"} {
		for _, withResolver := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/resolver=%v", mode, withResolver), func(t *testing.T) {
				store, schema, filter := newSmallGroupCandidateStore(t, 2, 1000, "v3")
				if mode == "display-reference" || mode == "legacy-entry" {
					if err := store.Update(t.Context(), func(writer Writer) error {
						tx := writer.(*boltTx)
						for _, ref := range boltCandidateReferences(t, tx) {
							key := boltCandidateKey(t, tx, ref)
							stored, err := decodeStoredEntry(tx.entries.Get(key))
							if err != nil {
								return err
							}
							if mode == "legacy-entry" {
								dn, err := directory.ParseDN(stored.DN)
								if err != nil {
									return err
								}
								value, err := encodeEntry(stored.Entry, "", "")
								if err != nil {
									return err
								}
								if err := tx.entries.Put([]byte(partitionedEntryKey("db", dn.Key())), value); err != nil {
									return err
								}
								if err := tx.entries.Delete(key); err != nil {
									return err
								}
							}
							if err := tx.equalityIndexRefs.Put([]byte(ref), encodeEqualityIndexEntryReference("db", stored.DN)); err != nil {
								return err
							}
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				var retained, wantRetained []directory.Entry
				if err := store.View(t.Context(), func(reader Reader) error {
					tx := reader.(*boltTx)
					original := make(map[string][]byte)
					if err := tx.entries.ForEach(func(key, value []byte) error {
						original[string(key)] = bytes.Clone(value)
						return nil
					}); err != nil {
						return err
					}
					for _, failure := range []string{"", "resolve", "assertion", "reference", "dn", "hint"} {
						t.Run("fail="+failure, func(t *testing.T) {
							sentinel := errors.New("custom schema failure")
							var wantPlanned bool
							var wantCount int
							var wantErr error
							var wantCalls []string
							var wantEntries []directory.Entry
							for i, iterate := range []readOnlyCandidateIterator{ForEachFilterCandidate, ForEachReadOnlyFilterCandidate} {
								recording := &smallCandidateRecordingSchema{indexTestSchema: schema, failAt: failure, failure: sentinel}
								var normalizer directory.DNAttributeNormalizer = recording
								if withResolver {
									normalizer = smallCandidateReferenceSchema{recording}
								}
								query := filter
								query.Assertion = bytes.Clone(filter.Assertion)
								if mode == "and-filter" {
									query = directory.Filter{Kind: directory.FilterAnd, Children: []directory.Filter{query}}
								}
								var entries []directory.Entry
								planned, count, err := iterate(ReaderInPartitionWithNormalizer(reader, "db", normalizer), query, func(entry directory.Entry) error {
									recording.calls = append(recording.calls, "callback:"+entry.DN)
									entries = append(entries, entry.Clone())
									return nil
								})
								if i == 0 {
									wantPlanned, wantCount, wantErr, wantCalls, wantEntries = planned, count, err, recording.calls, entries
								} else if planned != wantPlanned || count != wantCount || fmt.Sprint(err) != fmt.Sprint(wantErr) ||
									reflect.TypeOf(err) != reflect.TypeOf(wantErr) || errors.Is(err, sentinel) != errors.Is(wantErr, sentinel) ||
									!slices.Equal(recording.calls, wantCalls) || !reflect.DeepEqual(entries, wantEntries) {
									t.Fatalf("planned/count/error/calls = %v/%d/%v/%v; want %v/%d/%v/%v", planned, count, err, recording.calls, wantPlanned, wantCount, wantErr, wantCalls)
								}
								if failure == "" && (err != nil || !planned || count != 2) {
									t.Fatalf("fallback planned/count/error = %v/%d/%v", planned, count, err)
								}
								for _, entry := range recording.retained {
									retained = append(retained, entry)
									wantRetained = append(wantRetained, entry.Clone())
								}
							}
						})
					}
					for key, value := range original {
						if !bytes.Equal(tx.entries.Get([]byte(key)), value) {
							t.Fatal("custom schema mutated stored bytes")
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(retained, wantRetained) {
					t.Fatal("custom resolver retained borrowed entry data")
				}
			})
		}
	}
}

func TestReadOnlySmallCandidatesWriteTransactionFallback(t *testing.T) {
	store, schema, filter := newSmallGroupCandidateStore(t, 4, 1000, "v3")
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		scoped := ReaderInPartitionWithNormalizer(writer, "db", schema).(schemaAwarePartitionReader)
		var encoded []encodedEqualityIndexCandidate
		want, planned, err := scoped.planEqualityIndexCandidatesWithEncoded(filter, &encoded, true)
		if err != nil || !planned || len(want) != 4 || len(encoded) != 0 {
			t.Fatalf("write plan entries/encoded/planned/error = %d/%d/%v/%v", len(want), len(encoded), planned, err)
		}
		refs := boltCandidateReferences(t, tx)
		calls := 0
		planned, count, err := ForEachReadOnlyFilterCandidate(scoped, filter, func(entry directory.Entry) error {
			if !reflect.DeepEqual(entry, want[calls]) {
				t.Fatalf("write callback %d differs from owned snapshot", calls)
			}
			calls++
			if calls == 1 {
				return tx.entries.Delete(boltCandidateKey(t, tx, refs[len(refs)-1]))
			}
			return nil
		})
		if err != nil || !planned || count != 4 || calls != 4 {
			t.Fatalf("write iteration planned/count/calls/error = %v/%d/%d/%v", planned, count, calls, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
