package server

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSSHAPasswordBindFinalSnapshotAndACL(t *testing.T) {
	t.Parallel()

	var hashes [][]byte
	for _, password := range []string{"denied", "original", "replacement"} {
		stored, err := auth.HashPassword(
			[]byte(password), auth.OpenLDAPDefaultHashScheme, bytes.NewReader([]byte{1, 2, 3, 4}),
		)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, stored)
	}
	for _, backend := range []string{"memory", "bolt"} {
		for _, supplied := range []string{"denied", "original", "replacement", "wrong"} {
			t.Run(backend+"/"+supplied, func(t *testing.T) {
				instance, database, dn := newReadOnlyPasswordBindFixture(t, backend, hashes[:2], []string{
					`{0}to attrs=userPassword val.exact="` + string(hashes[0]) + `" by * none`,
					`{1}to attrs=userPassword by anonymous auth by * none`,
				})
				runtime := instance.runtime.Load()
				// Warm successful verification before replacing the password during a Bind.
				initial, err := instance.authenticatePasswordBind(t.Context(), runtime, dn.String(), []byte("original"), false)
				if err != nil || !initial.authenticated {
					t.Fatalf("initial Bind = %#v, %v", initial, err)
				}
				probe := &readOnlyBindProbeStore{Store: instance.config.Store}
				probe.beforeView = func(view int) error {
					if view != 2 {
						return nil
					}
					return probe.Store.Update(t.Context(), func(writer storage.Writer) error {
						tx := writerForDatabase(writer, *database)
						entry, err := tx.Get(dn)
						if err != nil {
							return err
						}
						entry.ReplaceValues("userPassword", [][]byte{hashes[0], hashes[2]})
						return tx.Put(entry, true)
					})
				}
				instance.config.Store = probe
				result, err := instance.authenticatePasswordBind(t.Context(), runtime, dn.String(), []byte(supplied), false)
				want := passwordBindResult{authenticated: supplied == "replacement", authenticatedDN: dn.String()}
				if err != nil || !reflect.DeepEqual(result, want) || probe.views != 2 || probe.updates != 0 {
					t.Fatalf("Bind = %#v, %v; want %#v; views=%d updates=%d", result, err, want, probe.views, probe.updates)
				}
			})
		}
	}
}
