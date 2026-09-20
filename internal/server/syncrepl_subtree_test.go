package server

import (
	"context"
	"errors"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSyncConsumerSubtreeRenameCollisionDoesNotAdvanceCookie(t *testing.T) {
	server, store, config := newSyncConsumerUnitServer(t)
	const oldDN = "cn=old,dc=example,dc=com"
	const newDN = "cn=new,dc=example,dc=com"
	identifier := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	entries := []directory.Entry{
		syncConsumerTestEntry(oldDN, identifier.String(), "old"),
		syncConsumerTestEntry("cn=child,"+oldDN, "aaaaaaaa-2222-3333-4444-555555555555", "child"),
		syncConsumerTestEntry("cn=child,"+newDN, "bbbbbbbb-2222-3333-4444-555555555555", "collision"),
	}
	seedSyncConsumerEntries(t, store, config.partition, entries)
	initialCookie := []byte("rid=001,csn=20260730010101.000001Z#000000#001#000000")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return updateSyncConsumerCookie(writer, config, initialCookie)
	}); err != nil {
		t.Fatal(err)
	}
	err := server.applySyncConsumerEntry(context.Background(), config,
		ldap.NewEntry(newDN, map[string][]string{
			"objectClass": {"inetOrgPerson"}, "cn": {"new"}, "sn": {"Example"},
			"entryCSN": {"20260730010102.000001Z#000000#001#000000"},
		}), &ldap.ControlSyncState{
			State: ldap.SyncStateModify, EntryUUID: identifier,
			Cookie: []byte("rid=001,csn=20260730010102.000001Z#000000#001#000000"),
		})
	if !errors.Is(err, storage.ErrEntryExists) {
		t.Fatalf("rename collision = %v, want ErrEntryExists", err)
	}
	assertSyncConsumerCookie(t, store, config, initialCookie)
	assertSyncConsumerMissingEntry(t, store, config.partition, newDN)
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		for _, want := range entries {
			got, err := reader.GetIn(config.partition, mustSyncConsumerDN(t, want.DN))
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("failed rename changed entry:\n got: %#v\nwant: %#v", got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
