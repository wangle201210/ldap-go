package server

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadPasswordHashSchemes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		global        []string
		frontend      []string
		want          []string
		wantError     bool
		addFrontend   bool
		outsideConfig bool
	}{
		{
			name: "OpenLDAP default",
			want: []string{auth.OpenLDAPDefaultHashScheme},
		},
		{
			name:   "legacy global",
			global: []string{"{pbkdf2-sm3}"},
			want:   []string{auth.SMPBKDF2HashScheme},
		},
		{
			name:        "frontend overrides global",
			global:      []string{"{SSHA}"},
			frontend:    []string{"{PBKDF2-SM3}", "{SSM3}"},
			addFrontend: true,
			want:        []string{"{PBKDF2-SM3}", "{SSM3}"},
		},
		{
			name:        "frontend accepts space-separated compatibility values",
			frontend:    []string{"{SSHA} {SHA}"},
			addFrontend: true,
			want:        []string{"{SSHA}", "{SHA}"},
		},
		{
			name:        "unsupported",
			frontend:    []string{"{CRYPT}"},
			addFrontend: true,
			wantError:   true,
		},
		{
			name:        "verify-only Netscape scheme",
			frontend:    []string{auth.OpenLDAPNetscapeMTAHashScheme},
			addFrontend: true,
			want:        []string{auth.OpenLDAPNetscapeMTAHashScheme},
		},
		{
			name:          "configuration attributes outside config are ignored",
			outsideConfig: true,
			want:          []string{auth.OpenLDAPDefaultHashScheme},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(context.Background(), func(writer storage.Writer) error {
				if len(test.global) > 0 {
					if err := writer.Put(directory.Entry{
						DN: "cn=config",
						Attributes: []directory.Attribute{
							{Description: "olcPasswordHash", Values: stringValues(test.global...)},
						},
					}, false); err != nil {
						return err
					}
				}
				if test.addFrontend {
					return writer.Put(directory.Entry{
						DN: "olcDatabase={-1}frontend,cn=config",
						Attributes: []directory.Attribute{
							{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
							{Description: "olcPasswordHash", Values: stringValues(test.frontend...)},
						},
					}, false)
				}
				if test.outsideConfig {
					return writer.Put(directory.Entry{
						DN: "cn=frontend,dc=example,dc=com",
						Attributes: []directory.Attribute{
							{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
							{Description: "olcPasswordHash", Values: stringValues("{PBKDF2-SM3}")},
						},
					}, false)
				}
				return nil
			}); err != nil {
				t.Fatalf("seed configuration: %v", err)
			}

			var got []string
			err := store.View(context.Background(), func(reader storage.Reader) error {
				var err error
				got, err = loadPasswordHashSchemes(reader)
				return err
			})
			if test.wantError {
				if err == nil {
					t.Fatalf("loadPasswordHashSchemes() = %#v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadPasswordHashSchemes(): %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("loadPasswordHashSchemes() = %#v, want %#v", got, test.want)
			}
		})
	}
}
