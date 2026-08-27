package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadDefaultReferralConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		addGlobal bool
		values    []string
		want      []string
		wantError string
	}{
		{name: "missing cn=config"},
		{name: "missing attribute", addGlobal: true},
		{
			name:      "order and duplicates",
			addGlobal: true,
			values: []string{
				"ldap://one.example",
				"not an LDAP URL",
				"ldap://one.example",
				"ldaps://two.example/",
			},
			want: []string{
				"ldap://one.example",
				"not an LDAP URL",
				"ldap://one.example",
				"ldaps://two.example/",
			},
		},
		{
			name:      "recognized schemes and extensions",
			addGlobal: true,
			values: []string{
				"ldap://ldap.example",
				"LDAPS://ldaps.example/",
				"ldapi://%2Fvar%2Frun%2Fldapi",
				"ldapi://%ZZ",
				"pldap://proxy.example/??",
				"pldaps://proxy.example/????!bindname=cn%3Droot",
				"<URL:ldap://wrapped.example/>",
			},
			want: []string{
				"ldap://ldap.example",
				"LDAPS://ldaps.example/",
				"ldapi://%2Fvar%2Frun%2Fldapi",
				"ldapi://%ZZ",
				"pldap://proxy.example/??",
				"pldaps://proxy.example/????!bindname=cn%3Droot",
				"<URL:ldap://wrapped.example/>",
			},
		},
		{
			name:      "unrecognized values remain opaque",
			addGlobal: true,
			values: []string{
				"https://example.test/dc=example??sub",
				"ldap:missing-double-slash",
				"ldap+tlcp://example.test/bad?still-opaque",
				"ordinary referral text",
			},
			want: []string{
				"https://example.test/dc=example??sub",
				"ldap:missing-double-slash",
				"ldap+tlcp://example.test/bad?still-opaque",
				"ordinary referral text",
			},
		},
		{
			name:      "DN forbidden",
			addGlobal: true,
			values:    []string{"ldap://example.test/dc=example,dc=com"},
			wantError: "contains a DN",
		},
		{
			name:      "attributes forbidden",
			addGlobal: true,
			values:    []string{"ldap://example.test/?cn,sn"},
			wantError: "requests attributes",
		},
		{
			name:      "scope forbidden",
			addGlobal: true,
			values:    []string{"ldap://example.test/??sub"},
			wantError: "explicit scope",
		},
		{
			name:      "filter forbidden",
			addGlobal: true,
			values:    []string{"ldap://example.test/???%28objectClass%3D%2A%29"},
			wantError: "contains a filter",
		},
		{
			name:      "invalid recognized port",
			addGlobal: true,
			values:    []string{"ldap://example.test:not-a-port"},
			wantError: "invalid LDAP URL port",
		},
		{
			name:      "invalid recognized IPv6 authority",
			addGlobal: true,
			values:    []string{"ldaps://[2001:db8::1"},
			wantError: "unterminated IPv6",
		},
		{
			name:      "invalid empty extensions",
			addGlobal: true,
			values:    []string{"pldap://example.test/????"},
			wantError: "empty extensions",
		},
		{
			name:      "invalid enclosure",
			addGlobal: true,
			values:    []string{"<ldap://example.test"},
			wantError: "invalid enclosed LDAP URL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if test.addGlobal {
				putDefaultReferralConfigGlobalEntry(t, store, test.values)
			}

			var got []string
			err := store.View(t.Context(), func(reader storage.Reader) error {
				var err error
				got, err = loadDefaultReferralConfiguration(reader)
				return err
			})
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("load error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadDefaultReferralConfiguration(): %v", err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("default referrals = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDefaultReferralRuntimeRebuildAndValidationRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	original := []string{
		"ldap://one.example",
		"opaque referral",
		"ldap://one.example",
	}
	putDefaultReferralConfigGlobalEntry(t, store, original)

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	active := instance.runtime.Load()
	assertDefaultReferrals(t, active, original)

	err = store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceDefaultReferralValues(
			writer,
			[]string{"ldap://example.test/dc=forbidden"},
		); err != nil {
			return err
		}
		_, err := instance.validateRuntimeConfiguration(writer)
		return err
	})
	if err == nil {
		t.Fatal("invalid default referral runtime rebuild succeeded")
	}
	if instance.runtime.Load() != active {
		t.Fatal("failed rebuild replaced the active runtime")
	}
	assertDefaultReferrals(t, active, original)
	assertStoredDefaultReferrals(t, store, original)

	nextValues := []string{"ldaps://next.example", "ldaps://next.example"}
	var next *runtimeState
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceDefaultReferralValues(writer, nextValues); err != nil {
			return err
		}
		var err error
		next, err = instance.validateRuntimeConfiguration(writer)
		return err
	}); err != nil {
		t.Fatalf("valid default referral runtime rebuild: %v", err)
	}
	assertDefaultReferrals(t, next, nextValues)
	assertDefaultReferrals(t, active, original)
	if len(active.defaultReferrals) > 0 && len(next.defaultReferrals) > 0 &&
		&active.defaultReferrals[0] == &next.defaultReferrals[0] {
		t.Fatal("runtime snapshots share the default referral slice")
	}
}

func putDefaultReferralConfigGlobalEntry(
	t *testing.T,
	store storage.Store,
	values []string,
) {
	t.Helper()
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry := directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		}
		if values != nil {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description: "olcReferral",
				Values:      stringValues(values...),
			})
		}
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	}); err != nil {
		t.Fatalf("seed default referral configuration: %v", err)
	}
}

func replaceDefaultReferralValues(
	writer storage.Writer,
	values []string,
) error {
	configuration := storage.WriterInPartition(
		writer,
		storage.OpenLDAPConfigPartition,
	)
	entry, err := configuration.Get(configurationSuffix)
	if err != nil {
		return err
	}
	entry.ReplaceValues("olcReferral", stringValues(values...))
	return configuration.Put(entry, true)
}

func assertDefaultReferrals(
	t *testing.T,
	runtime *runtimeState,
	want []string,
) {
	t.Helper()
	if runtime == nil || !slices.Equal(runtime.defaultReferrals, want) {
		t.Fatalf("runtime default referrals = %#v, want %#v", runtime, want)
	}
}

func assertStoredDefaultReferrals(
	t *testing.T,
	store storage.Store,
	want []string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(
			storage.OpenLDAPConfigPartition,
			configurationSuffix,
		)
		if err != nil {
			return err
		}
		got := entry.Values("olcReferral")
		if len(got) != len(want) {
			return fmt.Errorf("stored value count = %d, want %d", len(got), len(want))
		}
		for index := range got {
			if string(got[index]) != want[index] {
				return fmt.Errorf("stored value #%d = %q, want %q", index, got[index], want[index])
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
