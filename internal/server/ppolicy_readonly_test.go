package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestReadOnlyPasswordBindStorage(t *testing.T) {
	for _, backend := range []string{"memory", "bolt"} {
		for _, scheme := range []string{auth.OpenLDAPDefaultHashScheme, "{SM3}", auth.SMPBKDF2HashScheme} {
			t.Run(backend+"/"+scheme, func(t *testing.T) {
				stored, err := auth.HashPassword([]byte("secret"), scheme, nil)
				if err != nil {
					t.Fatal(err)
				}
				instance, database, dn := newReadOnlyPasswordBindFixture(t, backend, [][]byte{stored}, nil)
				var before directory.Entry
				if err := instance.config.Store.View(t.Context(), func(reader storage.Reader) error {
					before, err = readerForDatabase(reader, *database).Get(dn)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				revision, available := instance.currentStorageSnapshotRevision(t.Context())
				if !available {
					t.Fatal("storage revision is unavailable")
				}
				probe := &readOnlyBindProbeStore{Store: instance.config.Store}
				instance.config.Store = probe
				for _, supplied := range []string{"secret", "wrong", "secret"} {
					result, err := instance.authenticatePasswordBind(t.Context(), instance.runtime.Load(), dn.String(), []byte(supplied), true)
					want := passwordBindResult{authenticated: supplied == "secret", authenticatedDN: before.DN}
					if err != nil || !reflect.DeepEqual(result, want) {
						t.Fatalf("Bind(%q) = %#v, %v; want %#v", supplied, result, err, want)
					}
				}
				if probe.views != 6 || probe.updates != 0 {
					t.Fatalf("storage calls: views=%d updates=%d; want 6/0", probe.views, probe.updates)
				}
				instance.config.Store = probe.Store
				afterRevision, available := instance.currentStorageSnapshotRevision(t.Context())
				if !available || revision != afterRevision {
					t.Fatalf("revision changed from %d to %d; available=%t", revision, afterRevision, available)
				}
				if err := instance.config.Store.View(t.Context(), func(reader storage.Reader) error {
					after, err := readerForDatabase(reader, *database).Get(dn)
					if err == nil && !before.Equal(after) {
						t.Fatal("Bind changed the entry")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestReadOnlyPasswordBindRejectedEntries(t *testing.T) {
	for _, test := range []struct {
		name        string
		objectClass string
		passwords   [][]byte
		missing     bool
	}{
		{name: "missing", missing: true},
		{name: "no password"},
		{name: "invalid hash", passwords: stringValues("{PBKDF2-SM3}invalid")},
		{name: "subentry", objectClass: "subentry", passwords: stringValues("secret")},
		{name: "alias", objectClass: "alias", passwords: stringValues("secret")},
		{name: "referral", objectClass: "referral", passwords: stringValues("secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, database, dn := newReadOnlyPasswordBindFixture(t, "memory", test.passwords, nil)
			if test.missing || test.objectClass != "" {
				if err := instance.config.Store.Update(t.Context(), func(writer storage.Writer) error {
					tx := writerForDatabase(writer, *database)
					if test.missing {
						return tx.Delete(dn)
					}
					entry, err := tx.Get(dn)
					if err != nil {
						return err
					}
					entry.ReplaceValues("objectClass", stringValues(test.objectClass))
					return tx.Put(entry, true)
				}); err != nil {
					t.Fatal(err)
				}
			}
			probe := &readOnlyBindProbeStore{Store: instance.config.Store}
			instance.config.Store = probe
			result, err := instance.authenticatePasswordBind(t.Context(), instance.runtime.Load(), dn.String(), []byte("secret"), true)
			if err != nil || result.authenticated || result.restricted || len(result.controls) != 0 || probe.updates != 0 {
				t.Fatalf("Bind = %#v, %v; updates=%d", result, err, probe.updates)
			}
			if (test.missing || test.objectClass != "") && result.authenticatedDN != "" {
				t.Fatalf("excluded entry returned identity %q", result.authenticatedDN)
			}
		})
	}
}

func TestPasswordBindValuesPreserveACLAndFullVerification(t *testing.T) {
	const verifiedExternal = "{RADIUS}verified"
	const changedExternal = "{RADIUS}changed"
	instance, database, dn := newReadOnlyPasswordBindFixture(t, "memory", stringValues("first", "denied", verifiedExternal, changedExternal, "last"), []string{
		`{0}to attrs=userPassword val.exact="denied" by * none`,
		`{1}to attrs=userPassword by anonymous auth by * none`,
	})
	var verified []string
	var matches []bool
	externalMatches := newExternalPasswordMatches()
	externalMatches.values[newExternalPasswordMatchKey([]byte(verifiedExternal), []byte("first"))] = true
	externalMatches.values[newExternalPasswordMatchKey([]byte("{RADIUS}old"), []byte("first"))] = true
	externalMatches.values[newExternalPasswordMatchKey([]byte(changedExternal), []byte("other-password"))] = true
	if err := instance.config.Store.View(t.Context(), func(reader storage.Reader) error {
		tx := readerForDatabase(reader, *database)
		entry, err := tx.Get(dn)
		if err != nil {
			return err
		}
		matched := instance.verifyPasswordBindValues(instance.runtime.Load(), tx, entry, "userPassword", func(stored []byte) bool {
			verified = append(verified, string(stored))
			matched := verifyStoredPasswordWithExternalMatches(stored, []byte("first"), externalMatches)
			matches = append(matches, matched)
			return matched
		})
		if !matched || !slices.Equal(verified, []string{"first", verifiedExternal, changedExternal, "last"}) ||
			!slices.Equal(matches, []bool{true, true, false, false}) {
			t.Fatalf("matched=%t verified=%q matches=%v", matched, verified, matches)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, supplied := range []string{"first", "denied", "last"} {
		result, err := instance.authenticatePasswordBind(t.Context(), instance.runtime.Load(), dn.String(), []byte(supplied), false)
		if err != nil || result.authenticated != (supplied != "denied") {
			t.Fatalf("Bind(%q) = %#v, %v", supplied, result, err)
		}
	}
}

func TestReadOnlyPasswordBindErrorsAndCancellation(t *testing.T) {
	storageFailure := errors.New("read failure")
	for _, test := range []struct {
		name       string
		view       int
		after      bool
		cancel     bool
		storageErr bool
	}{
		{name: "preverify open", view: 1, storageErr: true},
		{name: "preverify completion", view: 1, after: true, storageErr: true},
		{name: "final open", view: 2, storageErr: true},
		{name: "final completion", view: 2, after: true, storageErr: true},
		{name: "cancel after preverify", view: 1, after: true, cancel: true},
		{name: "cancel after final verification", view: 2, after: true, cancel: true},
		{name: "read error precedes cancellation", view: 2, after: true, cancel: true, storageErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, _, dn := newReadOnlyPasswordBindFixture(t, "memory", stringValues("secret"), nil)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			probe := &readOnlyBindProbeStore{Store: instance.config.Store}
			hook := func(view int) error {
				if view != test.view {
					return nil
				}
				if test.cancel {
					cancel()
				}
				if test.storageErr {
					return storageFailure
				}
				return nil
			}
			if test.after {
				probe.afterView = hook
			} else {
				probe.beforeView = hook
			}
			instance.config.Store = probe
			result, err := instance.authenticatePasswordBind(ctx, instance.runtime.Load(), dn.String(), []byte("secret"), false)
			want := error(context.Canceled)
			if test.storageErr {
				want = storageFailure
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(result, passwordBindResult{}) || probe.updates != 0 {
				t.Fatalf("Bind = %#v, %v; want empty result/%v; updates=%d", result, err, want, probe.updates)
			}
		})
	}
}

func TestReadOnlyPasswordBindUsesFinalSnapshot(t *testing.T) {
	for _, supplied := range []string{"secret", "replacement"} {
		t.Run(supplied, func(t *testing.T) {
			instance, database, dn := newReadOnlyPasswordBindFixture(t, "memory", stringValues("secret"), nil)
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
					entry.ReplaceValues("userPassword", stringValues("replacement"))
					return tx.Put(entry, true)
				})
			}
			instance.config.Store = probe
			result, err := instance.authenticatePasswordBind(t.Context(), instance.runtime.Load(), dn.String(), []byte(supplied), false)
			if err != nil || result.authenticated != (supplied == "replacement") || probe.updates != 0 {
				t.Fatalf("Bind(%q) = %#v, %v; updates=%d", supplied, result, err, probe.updates)
			}
		})
	}
}

func TestReadOnlyPasswordBindStatefulFallback(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*runtimeState, *runtimeDatabase)
	}{
		{name: "ppolicy without policy", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.ppolicy = &passwordPolicyRuntimeConfiguration{}
		}},
		{name: "ppolicy disable write", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.ppolicy = &passwordPolicyRuntimeConfiguration{disableWrite: true}
		}},
		{name: "ppolicy forward updates", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.ppolicy = &passwordPolicyRuntimeConfiguration{forwardUpdates: true}
			database.shadow = true
		}},
		{name: "last success", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.lastBind = true
		}},
		{name: "lastbind overlay", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.lastBindOverlay = true
		}},
		{name: "OTP", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.otp = &otpRuntimeConfiguration{}
		}},
		{name: "TOTP static password", configure: func(_ *runtimeState, database *runtimeDatabase) {
			database.totpPasswords = []totpPasswordRuntimeConfiguration{{}}
		}},
		{name: "frontend TOTP", configure: func(runtime *runtimeState, _ *runtimeDatabase) {
			runtime.databases = append(runtime.databases, runtimeDatabase{
				name: "frontend", totpPasswords: []totpPasswordRuntimeConfiguration{{}},
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, database, dn := newReadOnlyPasswordBindFixture(t, "memory", stringValues("secret"), nil)
			runtime := instance.runtime.Load()
			test.configure(runtime, database)
			probe := &readOnlyBindProbeStore{Store: instance.config.Store}
			instance.config.Store = probe
			for _, supplied := range []string{"secret", "wrong"} {
				result, err := instance.authenticatePasswordBind(t.Context(), runtime, dn.String(), []byte(supplied), false)
				if !errors.Is(err, errReadOnlyBindUnexpectedUpdate) || !reflect.DeepEqual(result, passwordBindResult{}) {
					t.Fatalf("Bind(%q) = %#v, %v; want write transaction failure", supplied, result, err)
				}
			}
			if probe.updates != 2 {
				t.Fatalf("updates=%d; want 2", probe.updates)
			}
		})
	}
}

var errReadOnlyBindUnexpectedUpdate = errors.New("unexpected Bind update")

type readOnlyBindProbeStore struct {
	storage.Store
	views      int
	updates    int
	beforeView func(int) error
	afterView  func(int) error
}

func (store *readOnlyBindProbeStore) View(ctx context.Context, view func(storage.Reader) error) error {
	store.views++
	if store.beforeView != nil {
		if err := store.beforeView(store.views); err != nil {
			return err
		}
	}
	if err := store.Store.View(ctx, view); err != nil {
		return err
	}
	if store.afterView != nil {
		return store.afterView(store.views)
	}
	return nil
}

func (store *readOnlyBindProbeStore) Update(context.Context, func(storage.Writer) error) error {
	store.updates++
	return errReadOnlyBindUnexpectedUpdate
}

func newReadOnlyPasswordBindFixture(
	t testing.TB,
	backend string,
	passwords [][]byte,
	access []string,
) (*Server, *runtimeDatabase, directory.DN) {
	t.Helper()
	var store storage.Store
	if backend == "bolt" {
		var err error
		store, err = storage.OpenBolt(filepath.Join(t.TempDir(), "bind.db"))
		if err != nil {
			t.Fatal(err)
		}
	} else {
		store = storage.NewMemory()
	}
	t.Cleanup(func() { _ = store.Close() })
	if access == nil {
		access = []string{"to attrs=userPassword by anonymous auth by * none"}
	}
	entries := []directory.Entry{
		{DN: "dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("domain")},
			{Description: "dc", Values: stringValues("example")},
		}},
		{DN: aliceDN, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("alice")},
			{Description: "cn", Values: stringValues("Alice")},
			{Description: "sn", Values: stringValues("Example")},
			{Description: "userPassword", Values: passwords},
		}},
		{DN: "olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcAccess", Values: stringValues(access...)},
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
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	runtime := instance.runtime.Load()
	dn, err := parseRuntimeConnectionDN(runtime, aliceDN)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil || !passwordBindReadOnly(runtime, database) {
		t.Fatal("fixture is not eligible for read-only Bind")
	}
	return instance, database, dn
}

func BenchmarkReadOnlyLocalPasswordBind(b *testing.B) {
	for _, backend := range []string{"memory", "bolt"} {
		for _, scheme := range []string{auth.OpenLDAPDefaultHashScheme, "{SM3}"} {
			for _, mode := range []string{"cold", "warm"} {
				for _, supplied := range []string{"secret", "wrong"} {
					b.Run(backend+"/"+scheme+"/"+mode+"/"+supplied, func(b *testing.B) {
						stored, err := auth.HashPassword([]byte("secret"), scheme, nil)
						if err != nil {
							b.Fatal(err)
						}
						instance, database, dn := newReadOnlyPasswordBindFixture(b, backend, [][]byte{stored}, nil)
						runtime := instance.runtime.Load()
						// Cold rotates through more DNs than the parser cache holds;
						// storage pages and schema remain warm in both modes.
						names := make([]string, 256)
						if err := instance.config.Store.Update(b.Context(), func(writer storage.Writer) error {
							tx := writerForDatabase(writer, *database)
							template, err := tx.Get(dn)
							if err != nil {
								return err
							}
							for index := range names {
								uid := fmt.Sprintf("bind-%03d", index)
								entry := template.Clone()
								entry.DN = "uid=" + uid + ",dc=example,dc=com"
								entry.ReplaceValues("uid", stringValues(uid))
								names[index] = entry.DN
								if err := tx.Put(entry.WithoutDNIdentity(), false); err != nil {
									return err
								}
							}
							return nil
						}); err != nil {
							b.Fatal(err)
						}
						password := []byte(supplied)
						if mode == "warm" {
							names = names[:1]
							if _, err := instance.authenticatePasswordBind(b.Context(), runtime, names[0], password, false); err != nil {
								b.Fatal(err)
							}
						}
						index := 0
						b.ReportAllocs()
						for b.Loop() {
							result, err := instance.authenticatePasswordBind(b.Context(), runtime, names[index%len(names)], password, false)
							index++
							if err != nil || result.authenticated != (supplied == "secret") {
								b.Fatalf("Bind = %#v, %v", result, err)
							}
						}
					})
				}
			}
		}
	}
}
