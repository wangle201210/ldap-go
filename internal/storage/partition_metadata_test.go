package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestEntryMetadataMaterializeOwnership(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	var oldDecoder readOnlyCandidateDecoder
	for _, shape := range readOnlyCandidateShapes() {
		for i := range shape.entry.Attributes {
			shape.entry.Attributes[i].RawNormalized = i%2 == 0
		}
		for _, format := range []string{"v1", "v2", "v3", "json"} {
			t.Run(shape.name+"/"+format, func(t *testing.T) {
				identity := []byte("dn:v2:physical-identity")
				encoded := encodeCandidateTestEntry(t, shape.entry, string(identity), format)
				original := bytes.Clone(encoded)
				stored, err := decodeStoredEntry(encoded)
				if err != nil {
					t.Fatal(err)
				}
				want := stored.Entry.WithDNIdentityKey(string(identity)).Clone()
				old, err := oldDecoder.decode(encoded)
				if err != nil {
					t.Fatal(err)
				}
				view, err := decoder.decodeMetadata(encoded, identity)
				if err != nil || !view.HasIdentity() || !reflect.DeepEqual(view.Attributes(), stored.Attributes) {
					t.Fatalf("metadata differs from owned decode: %v", err)
				}
				count := 0
				for _, attr := range stored.Attributes {
					count += len(attr.Values)
				}
				if format != "json" && len(stored.Attributes) <= maxReadOnlyCandidateAttributes && count <= maxReadOnlyCandidateValues && len(view.dn) > 0 {
					position := bytes.Index(encoded, []byte(stored.DN))
					if position < 0 || &view.dn[0] != &encoded[position] {
						t.Fatal("binary metadata DN was copied")
					}
				}
				readOnly := view.ReadOnlyEntry()
				if !reflect.DeepEqual(readOnly.Attributes, view.Attributes()) || len(view.Attributes()) > 0 && &readOnly.Attributes[0] != &view.Attributes()[0] {
					t.Fatal("ReadOnlyEntry must borrow attribute descriptors")
				}
				selected, cloned := readOnly.Select([]string{"*"}, false), readOnly.Clone()
				first, second := view.Materialize(), view.Materialize()
				if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(second, want) {
					t.Fatal("materialization changed DN, key, values or normalization flags")
				}
				for i := range first.Attributes {
					attr := &first.Attributes[i]
					for j := range attr.Values {
						clear(attr.Values[j])
						attr.Values[j] = []byte("changed")
					}
					attr.Description = "changed"
					attr.RawNormalized = !attr.RawNormalized
					attr.Values = nil
				}
				if !reflect.DeepEqual(second, want) || !reflect.DeepEqual(view.Materialize(), want) || !bytes.Equal(encoded, original) {
					t.Fatal("materialized entries share mutable data with each other or the row")
				}
				clear(encoded)
				clear(identity)
				replacement := encodeCandidateTestEntry(t, benchmarkBinaryEntryCodecEntry(), "", "v2")
				if _, err := decoder.decodeMetadata(replacement, nil); err != nil {
					t.Fatal(err)
				}
				if _, err := oldDecoder.decode(replacement); err != nil {
					t.Fatal(err)
				}
				key, _ := readOnly.DNIdentity()
				wantKey, _ := want.DNIdentity()
				if !reflect.DeepEqual(second, want) || !reflect.DeepEqual(cloned, want) || !reflect.DeepEqual(selected, want.Select([]string{"*"}, false)) || old.DN != stored.DN || readOnly.DN != stored.DN || key != wantKey {
					t.Fatal("owned output retained row bytes, physical key bytes or reusable descriptors")
				}
			})
		}
	}
}

func TestEntryMetadataHasIdentity(t *testing.T) {
	for _, key := range [][]byte{nil, {}, []byte("cn=legacy"), []byte("dn:v2:AA")} {
		view := EntryMetadataView{identity: key}
		entry := view.Materialize()
		identity, present := entry.DNIdentity()
		if view.HasIdentity() != (len(key) > 0) || present != view.HasIdentity() || identity != string(key) {
			t.Fatalf("physical identity %q: view=%v entry=%q/%v", key, view.HasIdentity(), identity, present)
		}
	}
}

func TestEntryMetadataCodecErrorsMatchOwned(t *testing.T) {
	var decoder readOnlyCandidateDecoder
	check := func(value []byte) {
		t.Helper()
		want, wantErr := decodeStoredEntry(value)
		view, err := decoder.decodeMetadata(value, nil)
		if !reflect.DeepEqual(err, wantErr) {
			t.Fatalf("codec %x: error %v, want %v", value, err, wantErr)
		}
		if err == nil && (!reflect.DeepEqual(view.Attributes(), want.Attributes) || !reflect.DeepEqual(view.Materialize(), want.Entry.Clone())) {
			t.Fatalf("codec %x: materialized entry differs", value)
		}
	}
	seeds := append(candidateCodecSeeds(t), []byte("null"), []byte(`{"dn":"cn=test","attributes":[]}`), []byte{0, 'L', 'G', 'E', 4})
	for _, seed := range seeds {
		check(seed)
		for end := range seed {
			check(seed[:end])
			mutated := bytes.Clone(seed)
			mutated[end] ^= 0x80
			check(mutated)
		}
		check(append(bytes.Clone(seed), 0))
	}
}

func TestMetadataPhysicalScanOwnershipAfterUnmap(t *testing.T) {
	for _, format := range []string{"v1", "v2", "v3", "json", "mixed"} {
		t.Run(format, func(t *testing.T) {
			store, schema, _ := newBoltCandidateStore(t, 8)
			if err := store.Update(t.Context(), func(writer Writer) error {
				tx := writer.(*boltTx)
				for i, ref := range physicalBoltCandidateReferences(t, tx) {
					key := boltCandidateKey(t, tx, ref)
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					stored.Attributes = append(stored.Attributes, directory.Attribute{Description: "description;lang-EN", Values: [][]byte{nil, {}, {0, 255}}})
					if i%3 == 1 {
						for len(stored.Attributes) <= maxReadOnlyCandidateAttributes {
							stored.Attributes = append(stored.Attributes, directory.Attribute{Description: "extra"})
						}
					}
					mode := format
					if mode == "mixed" {
						mode = []string{"v1", "v2", "v3", "json"}[i%4]
					}
					_, identity := splitPartitionedEntryKey(string(key))
					if err := tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, mode)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			base, err := directory.ParseDNWithNormalizer("dc=example", schema)
			if err != nil {
				t.Fatal(err)
			}
			type retainedStrings struct{ dn, key string }
			var oldStrings, readOnlyStrings []retainedStrings
			var want, got, cloned, selected []directory.Entry
			if err := store.View(t.Context(), func(reader Reader) error {
				scoped := ReaderInPartitionWithNormalizer(indexMaintenanceReader{Reader: reader}, "db", schema)
				streamed, err := ForEachReadOnlyStablePhysicalEntry(scoped, func(entry directory.Entry) error {
					identity, _ := entry.DNIdentity()
					// Retain strings directly: Clone does not copy DN or identity bytes.
					oldStrings = append(oldStrings, retainedStrings{entry.DN, identity})
					want = append(want, entry.Clone())
					return nil
				})
				if !streamed || err != nil {
					return fmt.Errorf("reference %v/%v", streamed, err)
				}
				streamed, err = ForEachReadOnlyStablePhysicalMetadataInScope(scoped, base, directory.ScopeWholeSubtree, func(view EntryMetadataView, inScope bool, scopeErr error) error {
					if !view.HasIdentity() || !inScope || scopeErr != nil {
						t.Fatalf("identity/scope = %v/%v/%v", view.HasIdentity(), inScope, scopeErr)
					}
					got = append(got, view.Materialize())
					entry := view.ReadOnlyEntry()
					identity, _ := entry.DNIdentity()
					readOnlyStrings = append(readOnlyStrings, retainedStrings{entry.DN, identity})
					cloned = append(cloned, entry.Clone())
					selected = append(selected, entry.Select([]string{"*"}, false))
					return nil
				})
				if !streamed {
					return errors.New("metadata iterator not selected")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if len(got) != 8 || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(cloned, want) {
				t.Fatal("physical order or materialized output changed after unmap")
			}
			for i, old := range oldStrings {
				key, _ := got[i].DNIdentity()
				if old.dn != got[i].DN || old.key != key || readOnlyStrings[i] != old {
					t.Fatal("original API no longer owns DN and identity strings")
				}
				if !reflect.DeepEqual(selected[i], want[i].Select([]string{"*"}, false)) {
					t.Fatal("ReadOnlyEntry selection retained borrowed data after unmap")
				}
			}
		})
	}
}

type metadataScanRow struct {
	entry    directory.Entry
	inScope  bool
	scopeErr error
}

type metadataScanResult struct {
	rows      []metadataScanRow
	streamed  bool
	err       error
	remaining int
}

func compareMetadataPhysicalScan(t *testing.T, reader Reader, schema indexTestSchema, base directory.DN, scope directory.Scope, cancelAt, stopAt int, returnScopeError bool) metadataScanResult {
	t.Helper()
	tx := reader.(*boltTx)
	originalContext := tx.ctx
	defer func() { tx.ctx = originalContext }()
	scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
	stop := errors.New("callback deadline stop")
	var want metadataScanResult
	for _, metadata := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelAt == 0 {
			cancel()
		}
		checked := &candidateCancelContext{Context: ctx, cancel: cancel, remaining: cancelAt}
		tx.ctx = checked
		var got metadataScanResult
		visit := func(entry directory.Entry, inScope bool, scopeErr error) error {
			got.rows = append(got.rows, metadataScanRow{entry.Clone(), inScope, scopeErr})
			if len(got.rows) == stopAt {
				return stop
			}
			if returnScopeError {
				return scopeErr
			}
			return nil
		}
		if metadata {
			got.streamed, got.err = ForEachReadOnlyStablePhysicalMetadataInScope(scoped, base, scope, func(view EntryMetadataView, inScope bool, scopeErr error) error {
				return visit(view.Materialize(), inScope, scopeErr)
			})
		} else {
			got.streamed, got.err = ForEachReadOnlyStablePhysicalEntryInScope(scoped, base, scope, visit)
		}
		got.remaining = checked.remaining
		cancel()
		if !metadata {
			want = got
		} else if !reflect.DeepEqual(got, want) {
			t.Fatalf("scope=%d cancel=%d stop=%d: callbacks, errors or checkpoints differ\ngot %#v\nwant %#v", scope, cancelAt, stopAt, got, want)
		}
	}
	return want
}

func TestMetadataPhysicalScanScopeAndDeferredErrors(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 8)
	for _, raw := range []string{"dc=example", "uid=user000005,dc=example", "dc=elsewhere", ""} {
		base, err := directory.ParseDNWithNormalizer(raw, schema)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.View(t.Context(), func(reader Reader) error {
			for _, scope := range []directory.Scope{directory.ScopeBase, directory.ScopeSingleLevel, directory.ScopeWholeSubtree, directory.ScopeChildren, 99} {
				got := compareMetadataPhysicalScan(t, reader, schema, base, scope, 100, 0, false)
				if !got.streamed || got.err != nil || len(got.rows) != 8 {
					t.Fatal("valid rows were omitted before the callback")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	legacy, err := directory.ParseDN("dc=example")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.View(t.Context(), func(reader Reader) error {
		for _, stopAt := range []int{0, 1} {
			got := compareMetadataPhysicalScan(t, reader, schema, legacy, directory.ScopeWholeSubtree, 100, stopAt, true)
			if len(got.rows) != 1 || got.rows[0].scopeErr == nil || got.err == nil {
				t.Fatal("scope errors must reach the callback after validation")
			}
			if stopAt == 1 && got.err.Error() != "callback deadline stop" {
				t.Fatal("scope error displaced callback deadline error")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPhysicalScanLegacyIdentity(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 1)
	if err := store.Update(t.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		for _, dn := range []string{"", "cn=legacy"} {
			entry := directory.Entry{DN: dn}
			// Stored metadata must not replace the physical key, even in JSON.
			value := encodeCandidateTestEntry(t, entry, "dn:v2:stored-metadata", "json")
			if err := tx.entries.Put([]byte(partitionedEntryKey("db", dn)), value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	base, err := directory.ParseDNWithNormalizer("dc=example", schema)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.View(t.Context(), func(reader Reader) error {
		got := compareMetadataPhysicalScan(t, reader, schema, base, directory.ScopeWholeSubtree, 100, 0, false)
		if got.err != nil || len(got.rows) != 3 {
			t.Fatalf("legacy scan rows/error = %d/%v", len(got.rows), got.err)
		}
		seen := make(map[string]bool)
		_, err := ForEachReadOnlyStablePhysicalMetadataInScope(ReaderInPartitionWithNormalizer(reader, "db", schema), base, directory.ScopeWholeSubtree, func(view EntryMetadataView, inScope bool, scopeErr error) error {
			entry := view.ReadOnlyEntry()
			if entry.DN == "" || entry.DN == "cn=legacy" {
				key, present := entry.DNIdentity()
				if key != entry.DN || view.HasIdentity() != (entry.DN != "") || present != view.HasIdentity() || inScope || scopeErr == nil {
					t.Fatalf("legacy DN %q: identity %q/%v/%v scope %v/%v", entry.DN, key, present, view.HasIdentity(), inScope, scopeErr)
				}
				seen[entry.DN] = true
			}
			return nil
		})
		if len(seen) != 2 {
			t.Fatal("valid empty or legacy identity was omitted")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataPhysicalScanOutOfScopeErrorsAndCancellation(t *testing.T) {
	for _, mode := range []string{"valid", "json", "codec", "dn", "identity", "identity_tail", "identity_rdn", "identity_length"} {
		t.Run(mode, func(t *testing.T) {
			store, schema, _ := newBoltCandidateStore(t, 8)
			if mode != "valid" {
				if err := store.Update(t.Context(), func(writer Writer) error {
					tx := writer.(*boltTx)
					refs := physicalBoltCandidateReferences(t, tx)
					key := boltCandidateKey(t, tx, refs[len(refs)-1])
					stored, err := decodeStoredEntry(tx.entries.Get(key))
					if err != nil {
						return err
					}
					_, identity := splitPartitionedEntryKey(string(key))
					switch mode {
					case "json":
						return tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "json"))
					case "codec":
						return tx.entries.Put(key, append(encodeCandidateTestEntry(t, stored.Entry, identity, "v3"), 0))
					case "dn":
						stored.DN = "invalid DN"
						return tx.entries.Put(key, encodeCandidateTestEntry(t, stored.Entry, identity, "v2"))
					case "identity_tail", "identity_rdn", "identity_length":
						payload, err := base64.RawURLEncoding.Strict().DecodeString(identity[len("dn:v2:"):])
						if err != nil {
							return err
						}
						switch mode {
						case "identity_tail":
							payload = append(payload, 0)
						case "identity_rdn":
							count, rest, err := consumeEntryBinaryCount(payload)
							if err != nil || count != 2 {
								t.Fatalf("fixture identity count = %d, error = %v", count, err)
							}
							_, rest, err = consumeEntryBinaryField(rest)
							if err != nil {
								return err
							}
							rdn, tail, err := consumeEntryBinaryField(rest)
							if err != nil || len(rdn) == 0 || len(tail) != 0 {
								t.Fatalf("fixture final RDN = %x, tail = %x, error = %v", rdn, tail, err)
							}
							rdn[0] = 0
						case "identity_length":
							payload = payload[:len(payload)-1]
						}
						corruptIdentity := "dn:v2:" + base64.RawURLEncoding.EncodeToString(payload)
						if err := tx.entries.Delete(key); err != nil {
							return err
						}
						return tx.entries.Put([]byte(partitionedEntryKey("db", corruptIdentity)), encodeCandidateTestEntry(t, stored.Entry, corruptIdentity, "v2"))
					default:
						if err := tx.entries.Delete(key); err != nil {
							return err
						}
						return tx.entries.Put(append(key, '!'), encodeCandidateTestEntry(t, stored.Entry, identity, "v2"))
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			// The first RDN differs, before any corruption in the final RDN or tail.
			base, err := directory.ParseDNWithNormalizer("uid=elsewhere,dc=example", schema)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.View(t.Context(), func(reader Reader) error {
				for _, cancelAt := range []int{0, 1, 2, 5, 8, 9, 100} {
					for _, stopAt := range []int{0, 3} {
						got := compareMetadataPhysicalScan(t, reader, schema, base, directory.ScopeWholeSubtree, cancelAt, stopAt, false)
						for _, row := range got.rows {
							if row.inScope || row.scopeErr != nil {
								t.Fatal("fixture row must be outside scope")
							}
						}
						if cancelAt == 100 && stopAt == 0 {
							bad := mode != "valid" && mode != "json"
							if bad && (got.err == nil || len(got.rows) != 7) || !bad && (got.err != nil || len(got.rows) != 8) {
								t.Fatalf("out-of-scope bad row was skipped: %d/%v", len(got.rows), got.err)
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

func TestMetadataPhysicalScanUnsupportedReaders(t *testing.T) {
	store, schema, _ := newBoltCandidateStore(t, 1)
	check := func(reader Reader) {
		t.Helper()
		streamed, err := ForEachReadOnlyStablePhysicalMetadataInScope(reader, directory.DN{}, directory.ScopeWholeSubtree, func(EntryMetadataView, bool, error) error {
			t.Fatal("unsupported reader visited a row")
			return nil
		})
		if streamed || err != nil {
			t.Fatalf("unsupported reader = %v/%v", streamed, err)
		}
	}
	if err := store.View(t.Context(), func(reader Reader) error {
		tx := reader.(*boltTx)
		originalContext := tx.ctx
		defer func() { tx.ctx = originalContext }()
		checked := &candidateCancelContext{Context: context.Background(), remaining: 100}
		tx.ctx = checked
		check(reader)
		check(ReaderInPartition(reader, "db"))
		check(ReaderInPartitionWithNormalizer(reader, "", schema))
		check(ReaderInPartitionWithNormalizer(struct{ Reader }{reader}, "db", schema))
		if checked.remaining != 100 {
			t.Fatal("unsupported reader consumed cancellation checkpoints")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(t.Context(), func(writer Writer) error {
		check(ReaderInPartitionWithNormalizer(writer, "db", schema))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	memory := NewMemory()
	t.Cleanup(func() { _ = memory.Close() })
	if err := memory.View(t.Context(), func(reader Reader) error {
		check(ReaderInPartitionWithNormalizer(reader, "db", schema))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Both paths validate DN/scope, match the same raw UID prefix once, and select
// owned output only for hits. This measures the server's ReadOnlyEntry + Select
// path, without Materialize's additional copy of all attributes.
func BenchmarkMetadataPhysicalScan(b *testing.B) {
	const rows = 100000
	store, schema, _ := newBoltCandidateStore(b, rows)
	base, err := directory.ParseDNWithNormalizer("dc=example", schema)
	if err != nil {
		b.Fatal(err)
	}
	requested := []string{"uid", "cn"}
	for _, hits := range []struct {
		name   string
		prefix string
		count  int
	}{
		{name: "0", prefix: "missing", count: 0},
		{name: "sparse", prefix: "user000", count: 1000},
		{name: "all", prefix: "user", count: rows},
	} {
		prefix := []byte(hits.prefix)
		matches := func(attributes []directory.Attribute) bool {
			for _, attribute := range attributes {
				if attribute.Description == "uid" {
					for _, value := range attribute.Values {
						if bytes.HasPrefix(value, prefix) {
							return true
						}
					}
				}
			}
			return false
		}
		for _, mode := range []string{"readonly", "metadata"} {
			b.Run("hits="+hits.name+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					seen := 0
					retained := make([]directory.Entry, 0, hits.count)
					retain := func(entry directory.Entry) {
						retained = append(retained, entry.Select(requested, false))
					}
					err := store.View(b.Context(), func(reader Reader) error {
						scoped := ReaderInPartitionWithNormalizer(reader, "db", schema)
						var streamed bool
						var err error
						if mode == "metadata" {
							streamed, err = ForEachReadOnlyStablePhysicalMetadataInScope(scoped, base, directory.ScopeWholeSubtree, func(view EntryMetadataView, inScope bool, scopeErr error) error {
								seen++
								if scopeErr != nil {
									return scopeErr
								}
								if inScope && matches(view.Attributes()) {
									retain(view.ReadOnlyEntry())
								}
								return nil
							})
						} else {
							streamed, err = ForEachReadOnlyStablePhysicalEntryInScope(scoped, base, directory.ScopeWholeSubtree, func(entry directory.Entry, inScope bool, scopeErr error) error {
								seen++
								if scopeErr != nil {
									return scopeErr
								}
								if inScope && matches(entry.Attributes) {
									retain(entry)
								}
								return nil
							})
						}
						if err == nil && !streamed {
							return errors.New("physical scan unavailable")
						}
						return err
					})
					if err != nil || seen != rows || len(retained) != hits.count {
						b.Fatalf("rows=%d/%d hits=%d/%d error=%v", seen, rows, len(retained), hits.count, err)
					}
					runtime.KeepAlive(retained)
				}
				b.ReportMetric(rows, "rows/op")
				b.ReportMetric(float64(hits.count), "hits/op")
			})
		}
	}
}
