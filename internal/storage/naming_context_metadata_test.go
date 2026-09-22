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

func TestNamingContextMetadataDecoderParity(t *testing.T) {
	dn, err := directory.ParseDNWithNormalizer("uid=alice,dc=example", testDNNormalizer{})
	if err != nil {
		t.Fatal(err)
	}
	assertParity := func(t *testing.T, identity string, encoded []byte) {
		t.Helper()
		original := bytes.Clone(encoded)
		want, wantErr := decodeAndValidateEntry(identity, encoded)
		got, gotErr := decodeNamingContextMetadata(identity, encoded)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
			t.Fatalf("decode %x: error = %v, want %v", encoded, gotErr, wantErr)
		}
		if got.DN != want.DN || len(got.Attributes) != 0 || !bytes.Equal(encoded, original) {
			t.Fatalf("metadata differs or modified input: got %#v, want DN %q", got, want.DN)
		}
		clear(encoded)
		if got.DN != want.DN {
			t.Fatal("metadata retained borrowed DN bytes")
		}
	}
	for _, shape := range readOnlyCandidateShapes() {
		shape.entry.DN = dn.String()
		for i := range shape.entry.Attributes {
			shape.entry.Attributes[i].RawNormalized = i%2 == 0
		}
		for _, format := range []string{"v1", "v2", "v3", "json"} {
			t.Run(shape.name+"/"+format, func(t *testing.T) {
				encoded := encodeCandidateTestEntry(t, shape.entry, dn.Key(), format)
				assertParity(t, dn.Key(), bytes.Clone(encoded))
				assertParity(t, "dn:v2:invalid", bytes.Clone(encoded))
			})
		}
	}
	entry := directory.Entry{DN: dn.String(), Attributes: []directory.Attribute{
		{Description: "uid", Values: [][]byte{[]byte("alice")}, RawNormalized: true},
	}}
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		encoded := encodeCandidateTestEntry(t, entry, dn.Key(), format)
		for i := range encoded {
			assertParity(t, dn.Key(), bytes.Clone(encoded[:i]))
			for _, mask := range []byte{1, 0x80, 0xff} {
				mutated := bytes.Clone(encoded)
				mutated[i] ^= mask
				assertParity(t, dn.Key(), mutated)
			}
		}
		assertParity(t, dn.Key(), append(bytes.Clone(encoded), 0))
	}
	legacy, err := encodeEntry(directory.Entry{DN: "cn=config"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	assertParity(t, "cn=config", legacy)
}

func TestNamingContextMetadataInferenceParity(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			var store Store = NewMemory()
			if backend == "bolt" {
				var err error
				store, err = OpenBolt(filepath.Join(t.TempDir(), "contexts.db"))
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = store.Close() })
			var retained []string
			if err := store.Update(context.Background(), func(writer Writer) error {
				for _, row := range []struct{ partition, dn string }{
					{OpenLDAPConfigPartition, "cn=config"},
					{"pending", "olcDatabase={0}config,cn=config"},
					{"superior", "dc=example,dc=com"},
					{"subordinate", "dc=child,dc=example,dc=com"},
					{"orphan", "uid=alice,dc=missing,dc=com"},
					{"exact", "exactName=Root"},
					{"exact", "exactName=root"},
					{"exact", "uid=upper,exactName=Root"},
					{"duplicate-a", "uid=SHARED,dc=orphan"},
					{"duplicate-z", "uid=shared,dc=orphan"},
					{"root", ""},
				} {
					entry := directory.Entry{DN: row.dn, Attributes: []directory.Attribute{
						{Description: "description", Values: [][]byte{[]byte("payload")}},
					}}
					if row.partition == OpenLDAPConfigPartition || row.partition == "pending" || row.dn == "" {
						if err := writer.PutIn(row.partition, entry, false); err != nil {
							return err
						}
						continue
					}
					dn, err := directory.ParseDNWithNormalizer(row.dn, testDNNormalizer{})
					if err != nil {
						return err
					}
					if err := PutInWithDN(writer, row.partition, entry, dn, false); err != nil {
						return err
					}
				}
				want, err := InferNamingContextsWithNormalizer(writer, testDNNormalizer{})
				if err != nil {
					return err
				}
				got, err := InferNamingContextsMetadataWithNormalizer(writer, testDNNormalizer{})
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("contexts = %q, want %q", got, want)
				}
				retained = got
				for _, required := range []string{"cn=config", "uid=alice,dc=missing,dc=com", "exactName=Root", "exactName=root", "uid=shared,dc=orphan"} {
					found := false
					for _, contextDN := range got {
						found = found || contextDN == required
					}
					if !found {
						t.Fatalf("missing inferred root %q in %q", required, got)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.View(context.Background(), func(reader Reader) error {
				want, err := InferNamingContextsWithNormalizer(reader, testDNNormalizer{})
				if err == nil && !reflect.DeepEqual(retained, want) {
					t.Fatalf("DNs changed after transaction: got %q, want %q", retained, want)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type namingContextFailureReader struct {
	Reader
	err error
}

func (reader namingContextFailureReader) ForEachPartition(func(string, directory.Entry) error) error {
	return reader.err
}

func (reader namingContextFailureReader) MaintenanceStorageReader() Reader {
	return reader.Reader
}

func TestNamingContextMetadataPreservesReaderErrors(t *testing.T) {
	store := NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	injected := errors.New("injected iteration failure")
	if err := store.View(context.Background(), func(reader Reader) error {
		wrapped := namingContextFailureReader{Reader: reader, err: injected}
		_, err := InferNamingContextsMetadataWithNormalizer(wrapped, testDNNormalizer{})
		if !errors.Is(err, injected) {
			t.Fatalf("error = %v, want injected error", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNamingContextMetadataErrorOrder(t *testing.T) {
	for _, first := range []string{"schema", "codec", "binding", "canceled"} {
		t.Run(first, func(t *testing.T) {
			store, err := OpenBolt(filepath.Join(t.TempDir(), "errors.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer Writer) error {
				tx := writer.(*boltTx)
				entry := directory.Entry{DN: "undefinedName=value"}
				encoded, err := encodeEntry(entry, "", "")
				if err != nil {
					return err
				}
				badKey := "a\x00undefinedname=value"
				switch first {
				case "codec":
					encoded = []byte("malformed entry")
				case "binding":
					badKey = "a\x00dn:v2:invalid"
				}
				if err := tx.entries.Put([]byte(badKey), encoded); err != nil {
					return err
				}
				if err := tx.entries.Put([]byte("z\x00cn=broken"), []byte("second malformed entry")); err != nil {
					return err
				}
				if first == "canceled" {
					ctx, cancel := context.WithCancel(tx.ctx)
					cancel()
					tx.ctx = ctx
				}
				want, wantErr := InferNamingContextsWithNormalizer(writer, testDNNormalizer{})
				got, gotErr := InferNamingContextsMetadataWithNormalizer(writer, testDNNormalizer{})
				if wantErr == nil || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
					reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) || !reflect.DeepEqual(got, want) {
					t.Fatalf("got %q, %v; want %q, %v", got, gotErr, want, wantErr)
				}
				if first == "canceled" && !errors.Is(gotErr, context.Canceled) {
					t.Fatalf("cancellation lost: %v", gotErr)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func FuzzNamingContextMetadataDecoder(f *testing.F) {
	dn, err := directory.ParseDNWithNormalizer("uid=alice,dc=example", testDNNormalizer{})
	if err != nil {
		f.Fatal(err)
	}
	entry := directory.Entry{DN: dn.String(), Attributes: []directory.Attribute{
		{Description: "uid", Values: [][]byte{[]byte("alice")}, RawNormalized: true},
		{Description: "jpegPhoto", Values: [][]byte{nil, {}, {0, 0xff}, bytes.Repeat([]byte{0xab}, 2048)}},
	}}
	for _, format := range []string{"v1", "v2", "v3", "json"} {
		encoded := encodeCandidateTestEntry(f, entry, dn.Key(), format)
		f.Add(dn.Key(), encoded)
		f.Add("dn:v2:invalid", encoded)
		f.Add(dn.Key(), encoded[:len(encoded)-1])
		f.Add(dn.Key(), append(bytes.Clone(encoded), 0))
	}
	for _, encoded := range candidateCodecSeeds(f) {
		f.Add(dn.Key(), encoded)
	}
	f.Add("cn=config", []byte(`{"dn":"cn=config","attributes":[]}`))
	f.Add("", []byte("null"))
	f.Fuzz(func(t *testing.T, identity string, encoded []byte) {
		original := bytes.Clone(encoded)
		want, wantErr := decodeAndValidateEntry(identity, encoded)
		got, gotErr := decodeNamingContextMetadata(identity, encoded)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) ||
			got.DN != want.DN || len(got.Attributes) != 0 || !bytes.Equal(encoded, original) {
			t.Fatalf("metadata decode differs: got %#v, %v; want DN %q, %v", got, gotErr, want.DN, wantErr)
		}
	})
}

func BenchmarkNamingContextMetadataInference(b *testing.B) {
	const entries = 1000
	store, err := OpenBolt(filepath.Join(b.TempDir(), "contexts.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	attributes := []directory.Attribute{
		{Description: "objectClass", Values: [][]byte{[]byte("inetOrgPerson")}},
		{Description: "jpegPhoto", Values: [][]byte{bytes.Repeat([]byte{0xab}, 16<<10)}},
		{Description: "entryCSN", Values: [][]byte{[]byte("20260922000000.000000Z#000000#000#000000")}, RawNormalized: true},
	}
	for i := range 16 {
		attributes = append(attributes, directory.Attribute{
			Description: fmt.Sprintf("description;lang-x-%d", i),
			Values:      [][]byte{[]byte("additional attribute payload")},
		})
	}
	if err := store.Update(b.Context(), func(writer Writer) error {
		tx := writer.(*boltTx)
		for i := range entries + 1 {
			rawDN := "dc=example,dc=com"
			if i != 0 {
				rawDN = fmt.Sprintf("uid=user%04d,dc=example,dc=com", i)
			}
			dn, err := directory.ParseDNWithNormalizer(rawDN, testDNNormalizer{})
			if err != nil {
				return err
			}
			encoded, err := encodeEntry(directory.Entry{DN: rawDN, Attributes: attributes}, dn.Key(), rawDN)
			if err != nil {
				return err
			}
			if err := tx.entries.Put([]byte(partitionedEntryKey("db", dn.Key())), encoded); err != nil {
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
		{"Original", InferNamingContextsWithNormalizer},
		{"Metadata", InferNamingContextsMetadataWithNormalizer},
	} {
		b.Run("Entries1000/Payload16KiB/"+implementation.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := store.View(b.Context(), func(reader Reader) error {
					contexts, err := implementation.infer(reader, testDNNormalizer{})
					if err == nil && (len(contexts) != 1 || contexts[0] != "dc=example,dc=com") {
						b.Fatalf("unexpected contexts: %q", contexts)
					}
					return err
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
