package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestStoreContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		open func(*testing.T) Store
	}{
		{
			name: "memory",
			open: func(t *testing.T) Store {
				t.Helper()
				return NewMemory()
			},
		},
		{
			name: "bolt",
			open: func(t *testing.T) Store {
				t.Helper()
				store, err := OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
				if err != nil {
					t.Fatalf("OpenBolt(): %v", err)
				}
				return store
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runStoreContract(t, test.open(t))
		})
	}
}

func runStoreContract(t *testing.T, store Store) {
	t.Helper()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})

	ctx := context.Background()
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "cn", Values: [][]byte{[]byte("Alice"), {0x00, 0xff}}},
		},
	}
	if err := store.Update(ctx, func(tx Writer) error {
		if err := tx.Put(entry, false); err != nil {
			return err
		}
		return tx.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("initial Update(): %v", err)
	}

	dn := mustDN(t, entry.DN)
	if err := store.View(ctx, func(tx Reader) error {
		got, err := tx.Get(dn)
		if err != nil {
			return err
		}
		if !entry.Equal(got) {
			t.Fatalf("Get() = %#v, want %#v", got, entry)
		}
		contexts, err := tx.NamingContexts()
		if err != nil {
			return err
		}
		if len(contexts) != 1 || contexts[0] != "dc=example,dc=com" {
			t.Fatalf("NamingContexts() = %v", contexts)
		}
		return nil
	}); err != nil {
		t.Fatalf("View(): %v", err)
	}

	rollback := errors.New("rollback")
	if err := store.Update(ctx, func(tx Writer) error {
		if err := tx.Delete(dn); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback Update() error = %v", err)
	}

	if err := store.View(ctx, func(tx Reader) error {
		_, err := tx.Get(dn)
		return err
	}); err != nil {
		t.Fatalf("entry disappeared after rollback: %v", err)
	}
}

func mustDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", value, err)
	}
	return dn
}
