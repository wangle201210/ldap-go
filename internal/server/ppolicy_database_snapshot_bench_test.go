package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
)

// The detached input forces the legacy per-helper shallow copy. It is prepared
// outside the timer so the comparison does not add another caller allocation.
func BenchmarkPasswordBindDatabaseSnapshot(b *testing.B) {
	for _, stage := range []string{"preverify", "two-views"} {
		for _, ownership := range []string{"borrowed", "legacy-copy"} {
			b.Run(stage+"/"+ownership, func(b *testing.B) {
				password := []byte("secret")
				stored, err := auth.HashPassword(password, auth.OpenLDAPDefaultHashScheme, nil)
				if err != nil {
					b.Fatal(err)
				}
				instance, database, dn := newReadOnlyPasswordBindFixture(b, "bolt", [][]byte{stored}, nil)
				runtime := instance.runtime.Load()
				if databaseForDN(runtime, dn) != database || instance.passwordBindDatabaseSnapshot(runtime, database) != database {
					b.Fatal("benchmark must use an eligible runtime database pointer")
				}
				detached := *database
				if ownership == "legacy-copy" {
					database = &detached
					if instance.passwordBindDatabaseSnapshot(runtime, database) == database {
						b.Fatal("detached input must take the per-helper copy path")
					}
				}
				now := instance.clock()
				ctx := b.Context()
				// Warm the same normalization paths in both variants.
				if result, err := instance.authenticatePasswordBind(ctx, runtime, dn.String(), password, false); err != nil || !result.authenticated {
					b.Fatalf("warm Bind = %#v, %v", result, err)
				}
				b.ReportAllocs()
				for b.Loop() {
					matches, err := instance.preverifyExternalPasswordBind(ctx, runtime, database, dn, password, now)
					if err != nil || !matches.empty() {
						b.Fatalf("preverify = %#v, %v", matches, err)
					}
					if stage == "two-views" {
						result, err := instance.authenticateReadOnlyPasswordBind(ctx, runtime, database, dn, password, matches)
						if err != nil || !result.authenticated || result.authenticatedDN != dn.String() {
							b.Fatalf("final Bind = %#v, %v", result, err)
						}
					}
				}
			})
		}
	}
}
