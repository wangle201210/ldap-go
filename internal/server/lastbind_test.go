package server

import (
	"context"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLastBindOverlayLifecycleAndPrecision(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLPlainConfiguration(t, store, "none")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		databaseDN := staticRuntimeDN("olcDatabase={1}mdb,cn=config")
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcLastBindPrecision", stringValues("3600"))
		if err := writer.Put(database, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}lastbind,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcLastBindConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}lastbind")},
				{Description: "olcLastBindForwardUpdates", Values: stringValues("FALSE")},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	address, stop := startServer(t, store, Config{Clock: func() time.Time { return now }})
	t.Cleanup(stop)

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertLDAPResultCode(t, client.Bind(aliceDN, "wrong"), ldap.LDAPResultInvalidCredentials)
	assertLastBindTimestamp(t, store, nil)

	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatal(err)
	}
	first := []byte(formatPasswordPolicyTime(now))
	assertLastBindTimestamp(t, store, first)

	now = now.Add(30 * time.Minute)
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatal(err)
	}
	assertLastBindTimestamp(t, store, first)

	now = now.Add(2 * time.Hour)
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatal(err)
	}
	assertLastBindTimestamp(t, store, []byte(formatPasswordPolicyTime(now)))

	now = now.Add(2 * time.Hour)
	raw, err := dialAndBindSASLPlain(address, "", "alice", "secret")
	if err != nil {
		t.Fatalf("SASL PLAIN Bind: %v", err)
	}
	_ = raw.Close()
	assertLastBindTimestamp(t, store, []byte(formatPasswordPolicyTime(now)))
}

func TestLastBindForwardChangeContainsAuthTimestamp(t *testing.T) {
	before := directory.Entry{DN: aliceDN}
	after := before.Clone()
	after.ReplaceValues("authTimestamp", stringValues("20260828020000Z"))
	changes := passwordPolicyBindStateChanges(before, after)
	if len(changes) != 1 ||
		changes[0].Attribute.Description != "authTimestamp" ||
		changes[0].Operation != ldapwire.ModificationReplace {
		t.Fatalf("lastbind forward changes = %#v", changes)
	}
}

func assertLastBindTimestamp(t *testing.T, store storage.Store, want []byte) {
	t.Helper()
	values := readStoredEntry(t, store, aliceDN).Values("authTimestamp")
	if want == nil {
		if len(values) != 0 {
			t.Fatalf("authTimestamp = %q, want absent", values)
		}
		return
	}
	if len(values) != 1 || string(values[0]) != string(want) {
		t.Fatalf("authTimestamp = %q, want %q", values, want)
	}
}
