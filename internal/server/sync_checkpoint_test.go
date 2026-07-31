package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncProviderCheckpointsContextCSNByOperationCount(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(
			"olcOverlay={0}syncprov,olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		overlay, err := writer.Get(dn)
		if err != nil {
			return err
		}
		overlay.ReplaceValues("olcSpCheckpoint", stringValues("2 60"))
		return writer.Put(overlay, true)
	})
	if err != nil {
		t.Fatalf("configure Sync checkpoint: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()

	initial := readStoredEntry(t, store, "dc=example,dc=com").
		Values("contextCSN")
	if len(initial) != 1 {
		t.Fatalf("initial stored contextCSN = %q", initial)
	}
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Checkpoint One"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("first Modify(): %v", err)
	}
	afterFirst := readStoredEntry(t, store, "dc=example,dc=com").
		Values("contextCSN")
	if len(afterFirst) != 1 || !bytes.Equal(afterFirst[0], initial[0]) {
		t.Fatalf(
			"stored contextCSN changed before threshold: got %q, want %q",
			afterFirst,
			initial,
		)
	}

	modify = ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Checkpoint Two"})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("second Modify(): %v", err)
	}
	checkpoint := readStoredEntry(t, store, "dc=example,dc=com").
		Values("contextCSN")
	if len(checkpoint) != 1 || bytes.Equal(checkpoint[0], initial[0]) {
		t.Fatalf("checkpointed contextCSN = %q, initial = %q", checkpoint, initial)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"contextCSN"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(contextCSN): %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(contextCSN) entries = %#v", result.Entries)
	}
	live := result.Entries[0].GetAttributeValues("contextCSN")
	if len(live) != 1 || live[0] != string(checkpoint[0]) {
		t.Fatalf("live contextCSN = %q, checkpoint = %q", live, checkpoint)
	}
}

func TestUpdateSyncCheckpointUsesElapsedMinutes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	suffix, err := directory.ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := runtimeDatabase{
		partition:             "checkpoint-test",
		suffixes:              []directory.DN{suffix},
		syncProvider:          true,
		syncCheckpointOps:     100,
		syncCheckpointMinutes: 10,
	}
	csn := "20260730010101.000001Z#000000#000#000000"
	first := time.Date(2026, 7, 30, 1, 1, 1, 0, time.UTC)
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
		if err := tx.Put(directory.Entry{
			DN: suffix.String(),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		}, false); err != nil {
			return err
		}
		if err := writer.SetMetadata(
			syncContextCSNMetadataKey(database.partition),
			[]byte(csn),
		); err != nil {
			return err
		}
		if err := updateSyncCheckpoint(writer, database, first); err != nil {
			return err
		}
		return updateSyncCheckpoint(
			writer,
			database,
			first.Add(10*time.Minute),
		)
	})
	if err != nil {
		t.Fatalf("updateSyncCheckpoint(): %v", err)
	}

	var stored directory.Entry
	err = store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		stored, err = storage.ReaderInPartition(
			reader,
			database.partition,
		).Get(suffix)
		return err
	})
	if err != nil {
		t.Fatalf("read checkpoint suffix: %v", err)
	}
	if got := stored.Values("contextCSN"); len(got) != 1 ||
		string(got[0]) != csn {
		t.Fatalf("checkpointed contextCSN = %q, want %q", got, csn)
	}
}
