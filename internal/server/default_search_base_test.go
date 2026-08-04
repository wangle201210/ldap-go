package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadDefaultSearchBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		global     []string
		frontend   []string
		want       string
		configured bool
		wantError  string
	}{
		{name: "unset"},
		{
			name:       "global compatibility value",
			global:     []string{"dc=global,dc=example"},
			want:       "dc=global,dc=example",
			configured: true,
		},
		{
			name:       "frontend value",
			frontend:   []string{"DC=Example,DC=COM"},
			want:       "DC=Example,DC=COM",
			configured: true,
		},
		{
			name:       "frontend overrides global",
			global:     []string{"dc=global,dc=example"},
			frontend:   []string{"dc=frontend,dc=example"},
			want:       "dc=frontend,dc=example",
			configured: true,
		},
		{
			name:     "empty value is disabled",
			frontend: []string{""},
		},
		{
			name:      "duplicate value",
			frontend:  []string{"dc=one,dc=example", "dc=two,dc=example"},
			wantError: "exactly one value",
		},
		{
			name:      "invalid DN",
			frontend:  []string{"cn=unterminated\\"},
			wantError: "parse",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDefaultSearchBaseConfiguration(t, store, test.global, test.frontend)

			var got defaultSearchBaseConfiguration
			err := store.View(context.Background(), func(reader storage.Reader) error {
				var err error
				got, err = loadDefaultSearchBase(reader)
				return err
			})
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("loadDefaultSearchBase() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadDefaultSearchBase(): %v", err)
			}
			if got.configured != test.configured {
				t.Fatalf("configured = %v, want %v", got.configured, test.configured)
			}
			if got.configured && !strings.EqualFold(got.dn.String(), test.want) {
				t.Fatalf("DN = %q, want %q", got.dn.String(), test.want)
			}
		})
	}
}

func TestLoadDefaultSearchBaseRejectsDatabaseLocation(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDefaultSearchBaseConfiguration(t, store, nil, nil)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcDefaultSearchBase", Values: stringValues("dc=example,dc=com")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed database default search base: %v", err)
	}
	err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := loadDefaultSearchBase(reader)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "frontend database") {
		t.Fatalf("loadDefaultSearchBase() error = %v, want location rejection", err)
	}
}

func TestNormalizeDefaultSearchBaseConfigurationPreservesPartition(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	const partition = storage.OpenLDAPConfigPartition
	entry := directory.Entry{
		DN: "olcDatabase={-1}frontend,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			{Description: "olcDefaultSearchBase", Values: stringValues("DC=Example, DC=COM")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(partition, entry, false)
	}); err != nil {
		t.Fatalf("seed partitioned default search base: %v", err)
	}

	if err := normalizeDefaultSearchBaseConfiguration(context.Background(), store); err != nil {
		t.Fatalf("normalizeDefaultSearchBaseConfiguration(): %v", err)
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		stored, err := reader.GetIn(partition, dn)
		if err != nil {
			return err
		}
		values := stored.Values("olcDefaultSearchBase")
		if len(values) != 1 || string(values[0]) != "dc=Example,dc=COM" {
			t.Fatalf("normalized values = %q", values)
		}
		if _, err := reader.GetIn("", dn); !errors.Is(err, storage.ErrEntryNotFound) {
			t.Fatalf("unpartitioned Get() error = %v, want entry not found", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("read normalized default search base: %v", err)
	}
}

func TestNormalizeDefaultSearchBaseConfigurationIgnoresDataEntry(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "cn=data,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "olcDefaultSearchBase",
			Values:      stringValues("DC=Example, DC=COM"),
		}},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed data entry: %v", err)
	}
	if err := normalizeDefaultSearchBaseConfiguration(context.Background(), store); err != nil {
		t.Fatalf("normalizeDefaultSearchBaseConfiguration(): %v", err)
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		stored, err := reader.Get(dn)
		if err != nil {
			return err
		}
		values := stored.Values("olcDefaultSearchBase")
		if len(values) != 1 || string(values[0]) != "DC=Example, DC=COM" {
			t.Fatalf("data values = %q", values)
		}
		return nil
	}); err != nil {
		t.Fatalf("read data entry: %v", err)
	}
}

func TestValidateDefaultSearchBaseOnlineChanges(t *testing.T) {
	t.Parallel()

	change := func(
		operation ldapwire.ModificationOperation,
		description string,
	) ldapwire.Modification {
		return ldapwire.Modification{
			Operation: operation,
			Attribute: directory.Attribute{Description: description},
		}
	}
	for _, test := range []struct {
		name    string
		changes []ldapwire.Modification
		code    ldapwire.ResultCode
	}{
		{name: "unrelated", changes: []ldapwire.Modification{
			change(ldapwire.ModificationReplace, "olcReadOnly"),
		}},
		{name: "delete", changes: []ldapwire.Modification{
			change(ldapwire.ModificationDelete, "olcDefaultSearchBase"),
		}},
		{name: "add", changes: []ldapwire.Modification{
			change(ldapwire.ModificationAdd, "olcDefaultSearchBase"),
		}, code: ldapwire.ResultConstraintViolation},
		{name: "replace optioned", changes: []ldapwire.Modification{
			change(ldapwire.ModificationReplace, "olcDefaultSearchBase;binary"),
		}, code: ldapwire.ResultConstraintViolation},
		{name: "mixed delete add", changes: []ldapwire.Modification{
			change(ldapwire.ModificationDelete, "olcDefaultSearchBase"),
			change(ldapwire.ModificationAdd, "olcDefaultSearchBase"),
		}, code: ldapwire.ResultConstraintViolation},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateDefaultSearchBaseOnlineChanges(test.changes)
			if test.code == ldapwire.ResultSuccess {
				if err != nil {
					t.Fatalf("validateDefaultSearchBaseOnlineChanges(): %v", err)
				}
				return
			}
			failure := asOperationFailure(err)
			if failure == nil || failure.result.Code != test.code {
				t.Fatalf("failure = %#v, want code %d", failure, test.code)
			}
		})
	}
}

func seedDefaultSearchBaseConfiguration(
	t *testing.T,
	store storage.Store,
	global,
	frontend []string,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		},
	}
	if global != nil {
		entries[0].Attributes = append(entries[0].Attributes, directory.Attribute{
			Description: "olcDefaultSearchBase",
			Values:      stringValues(global...),
		})
	}
	if frontend != nil {
		entries[1].Attributes = append(entries[1].Attributes, directory.Attribute{
			Description: "olcDefaultSearchBase",
			Values:      stringValues(frontend...),
		})
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed default search base configuration: %v", err)
	}
}
