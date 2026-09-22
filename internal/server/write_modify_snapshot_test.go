package server

import (
	"bytes"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const modifySnapshotDN = "uid=alice,dc=example,dc=com"

func newModifySnapshotFixture(t testing.TB, backend string, photoBytes int) (*Server, runtimeDatabase, directory.DN) {
	t.Helper()
	var store storage.Store
	if backend == "bolt" {
		var err error
		store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		store = storage.NewMemory()
	}
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{DN: "dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("domain")},
			{Description: "dc", Values: stringValues("example")},
		}},
		{DN: modifySnapshotDN, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("alice")},
			{Description: "cn", Values: stringValues("Alice Original")},
			{Description: "sn", Values: stringValues("Example")},
			{Description: "jpegPhoto", Values: [][]byte{bytes.Repeat([]byte{0xff}, photoBytes)}},
			{Description: "entryUUID", Values: stringValues("00000000-0000-4000-8000-000000000001")},
			{Description: "entryCSN", Values: stringValues("20260730010101.000001Z#000000#000#000000")},
		}},
		{DN: "olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcDbIndex", Values: stringValues("cn eq")},
			{Description: "olcAccess", Values: stringValues("to * by * none")},
		}},
		{DN: "olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues("{0}syncprov")},
		}},
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Store: store, RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
	if err != nil {
		t.Fatal(err)
	}
	runtime := server.runtime.Load()
	dn, err := parseCoreWriteDN(runtime, modifySnapshotDN)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForNormalizedDN(runtime, dn)
	if database == nil || !database.syncProvider {
		t.Fatal("missing sync provider database")
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return storage.EnsureEqualityIndexes(writer, database.partition, database.dnNormalizer.(storage.EqualityIndexSchema))
	}); err != nil {
		t.Fatal(err)
	}
	return server, *database, dn
}

func TestModifyEntrySnapshots(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		t.Run(backend, func(t *testing.T) {
			server, database, dn := newModifySnapshotFixture(t, backend, 64<<10)
			runtime := server.runtime.Load()
			read := func() directory.Entry {
				t.Helper()
				var entry directory.Entry
				if err := server.config.Store.View(t.Context(), func(reader storage.Reader) error {
					var err error
					entry, err = readerForDatabase(reader, database).Get(dn)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return entry
			}
			before := read()
			changes := []ldapwire.Modification{
				{Operation: ldapwire.ModificationReplace, Attribute: directory.Attribute{Description: "cn", Values: stringValues("Alice Intermediate")}},
				{Operation: ldapwire.ModificationAdd, Attribute: directory.Attribute{Description: "cn", Values: stringValues("Alice Final")}},
				{Operation: ldapwire.ModificationDelete, Attribute: directory.Attribute{Description: "cn", Values: stringValues("Alice Intermediate")}},
				{Operation: ldapwire.ModificationReplace, Attribute: directory.Attribute{Description: "jpegPhoto", Values: [][]byte{{0, 1, 2}}}},
			}
			for _, test := range []struct {
				name    string
				noOp    bool
				changes []ldapwire.Modification
				want    ldapwire.ResultCode
			}{
				{name: "no-op", noOp: true, changes: changes, want: ldapwire.ResultNoOperation},
				{name: "first failure", changes: []ldapwire.Modification{
					changes[0],
					{Operation: ldapwire.ModificationDelete, Attribute: directory.Attribute{Description: "description"}},
					{Operation: ldapwire.ModificationDelete, Attribute: directory.Attribute{Description: "uid"}},
				}, want: ldapwire.ResultNoSuchAttribute},
			} {
				t.Run(test.name, func(t *testing.T) {
					_, events, err := server.modifyEntry(t.Context(), runtime, syncTestRootDN, dn, database,
						test.changes, false, false, false, test.noOp, nil, nil, nil, nil)
					failure := asOperationFailure(err)
					if failure == nil || failure.result.Code != test.want {
						t.Fatalf("Modify error = %v, want %d", err, test.want)
					}
					if len(events) != 0 || !reflect.DeepEqual(read().Attributes, before.Attributes) {
						t.Fatal("rolled-back Modify changed the entry or produced sync events")
					}
				})
			}
			record := accesslogWriteRecord{operation: accesslogModify, requestDN: dn}
			_, events, err := server.modifyEntry(t.Context(), runtime, syncTestRootDN, dn, database,
				changes, false, false, false, false, nil, nil, nil, &record)
			if err != nil {
				t.Fatal(err)
			}
			after := read()
			if !reflect.DeepEqual(after.Values("cn"), stringValues("Alice Final")) ||
				!reflect.DeepEqual(after.Values("jpegPhoto"), [][]byte{{0, 1, 2}}) {
				t.Fatal("multi-step Modify did not persist the final values")
			}
			if len(events) != 1 || !events[0].hasBefore || !events[0].hasAfter ||
				!reflect.DeepEqual(events[0].before.Attributes, before.Attributes) ||
				!reflect.DeepEqual(events[0].after.Attributes, after.Attributes) {
				t.Fatal("sync event lost the original or final entry snapshot")
			}
			if record.before == nil || record.after == nil ||
				!reflect.DeepEqual(record.before.Attributes, before.Attributes) ||
				!reflect.DeepEqual(record.after.Attributes, after.Attributes) {
				t.Fatal("accesslog record lost the original or final entry snapshot")
			}
			if err := server.config.Store.View(t.Context(), func(reader storage.Reader) error {
				for value, want := range map[string]int{"Alice Original": 0, "Alice Intermediate": 0, "Alice Final": 1} {
					planned, count, err := storage.ForEachFilterCandidate(readerForDatabase(reader, database), directory.Filter{
						Kind: directory.FilterEquality, Attribute: "cn", Assertion: []byte(value),
					}, func(entry directory.Entry) error {
						if entry.DN != modifySnapshotDN {
							t.Fatalf("unexpected indexed entry %q", entry.DN)
						}
						return nil
					})
					if err != nil || !planned || count != want {
						t.Fatalf("cn=%q candidates = %d, planned=%v, err=%v; want %d", value, count, planned, err, want)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkModifyEntrySnapshots(b *testing.B) {
	for _, backend := range []string{"memory", "bolt"} {
		for _, photoBytes := range []int{1024, 64 << 10} {
			for _, changeCount := range []int{1, 8} {
				b.Run(fmt.Sprintf("%s/photo=%d/changes=%d", backend, photoBytes, changeCount), func(b *testing.B) {
					server, database, dn := newModifySnapshotFixture(b, backend, photoBytes)
					runtime := server.runtime.Load()
					requests := [2][]ldapwire.Modification{}
					for version := range requests {
						for index := range changeCount {
							requests[version] = append(requests[version], ldapwire.Modification{
								Operation: ldapwire.ModificationReplace,
								Attribute: directory.Attribute{Description: "cn", Values: stringValues(fmt.Sprintf("Alice %d %d", version, index))},
							})
						}
					}
					// Warm the write path and alternate final values to maintain the index on every iteration.
					if _, _, err := server.modifyEntry(b.Context(), runtime, syncTestRootDN, dn, database,
						requests[1], false, false, false, false, nil, nil, nil, nil); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					version := 0
					for b.Loop() {
						if _, _, err := server.modifyEntry(b.Context(), runtime, syncTestRootDN, dn, database,
							requests[version], false, false, false, false, nil, nil, nil, nil); err != nil {
							b.Fatal(err)
						}
						version ^= 1
					}
				})
			}
		}
	}
}
