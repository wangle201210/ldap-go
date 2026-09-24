package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestPasswordBindDatabaseSnapshotEligibility(t *testing.T) {
	for _, mode := range []string{"local", "custom-store", "custom-normalizer", "other-schema", "detached", "radius", "ppolicy", "lastbind", "TOTP", "frontend-TOTP", "relay", "rewrite"} {
		t.Run(mode, func(t *testing.T) {
			instance, database, _ := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
			runtime := instance.runtime.Load()
			switch mode {
			case "custom-store":
				instance.config.Store = &bindDatabaseSnapshotProbeStore{Store: instance.config.Store}
			case "custom-normalizer":
				database.dnNormalizer = &bindDatabaseSnapshotNormalizer{Registry: runtime.schema}
			case "other-schema":
				database.dnNormalizer = runtime.schema.Clone()
			case "detached":
				database = new(*database)
			case "radius":
				runtime.externalPasswords.radiusEnabled = true
			case "ppolicy":
				database.ppolicy = &passwordPolicyRuntimeConfiguration{}
			case "lastbind":
				database.lastBind = true
			case "TOTP":
				database.totpPasswords = []totpPasswordRuntimeConfiguration{{}}
			case "frontend-TOTP":
				runtime.databases = append(runtime.databases, runtimeDatabase{name: "frontend", totpPasswords: []totpPasswordRuntimeConfiguration{{}}})
				database = databaseForDN(runtime, staticRuntimeDN(aliceDN))
			case "relay":
				database.relay = &relayRuntimeConfiguration{}
			case "rewrite":
				database.rwm = &rwmRuntimeConfiguration{}
			}
			database.rootPassword = []byte("snapshot")
			snapshot := instance.passwordBindDatabaseSnapshot(runtime, database)
			if (snapshot == database) != (mode == "local") || !reflect.DeepEqual(*snapshot, *database) {
				t.Fatal("database reuse eligibility or shallow copy differs")
			}
			partition := database.partition
			database.partition = "changed"
			snapshot.rootPassword[0] = 'S'
			if mode != "local" && snapshot.partition != partition {
				t.Fatal("fallback did not freeze database fields")
			}
			if database.rootPassword[0] != 'S' {
				t.Fatal("fallback must preserve existing shallow-copy aliasing")
			}
		})
	}
	instance, database, _ := newReadOnlyPasswordBindFixture(t, "memory", stringValues("secret"), nil)
	if instance.passwordBindDatabaseSnapshot(instance.runtime.Load(), database) == database {
		t.Fatal("non-Bolt store reused the database")
	}
}

type bindDatabaseSnapshotProbeStore struct {
	storage.Store
	views      int
	updates    int
	reads      []string
	beforeView func(int) error
	afterView  func(int) error
	afterGet   func(int)
}

func (store *bindDatabaseSnapshotProbeStore) View(ctx context.Context, fn func(storage.Reader) error) error {
	store.views++
	view := store.views
	if store.beforeView != nil {
		if err := store.beforeView(view); err != nil {
			return err
		}
	}
	if err := store.Store.View(ctx, func(reader storage.Reader) error {
		return fn(bindDatabaseSnapshotProbeReader{Reader: reader, store: store, view: view})
	}); err != nil {
		return err
	}
	if store.afterView != nil {
		return store.afterView(view)
	}
	return nil
}

func (store *bindDatabaseSnapshotProbeStore) Update(context.Context, func(storage.Writer) error) error {
	store.updates++
	return errReadOnlyBindUnexpectedUpdate
}

type bindDatabaseSnapshotProbeReader struct {
	storage.Reader
	store *bindDatabaseSnapshotProbeStore
	view  int
}

func (reader bindDatabaseSnapshotProbeReader) GetIn(partition string, dn directory.DN) (directory.Entry, error) {
	reader.store.reads = append(reader.store.reads, partition)
	entry, err := reader.Reader.GetIn(partition, dn)
	if err == nil && reader.store.afterGet != nil {
		reader.store.afterGet(reader.view)
	}
	return entry, err
}

func TestPasswordBindDatabaseSnapshotBeforeViewMutation(t *testing.T) {
	for _, view := range []int{1, 2} {
		t.Run(fmt.Sprint(view), func(t *testing.T) {
			instance, database, dn := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
			partition := database.partition
			probe := &bindDatabaseSnapshotProbeStore{Store: instance.config.Store}
			probe.beforeView = func(current int) error {
				if current == view {
					database.partition = "missing"
				}
				return nil
			}
			probe.afterView = func(int) error { database.partition = partition; return nil }
			instance.config.Store = probe
			result, err := instance.authenticatePasswordBind(t.Context(), instance.runtime.Load(), dn.String(), []byte("secret"), false)
			if err != nil || !result.authenticated || result.authenticatedDN != dn.String() || probe.views != 2 || probe.updates != 0 ||
				!slices.Equal(probe.reads, []string{partition, partition}) {
				t.Fatalf("Bind = %#v, %v; views=%d updates=%d reads=%v", result, err, probe.views, probe.updates, probe.reads)
			}
		})
	}
}

type bindDatabaseSnapshotNormalizer struct {
	*schema.Registry
	before func(string, []byte)
}

func (normalizer *bindDatabaseSnapshotNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	if normalizer.before != nil {
		normalizer.before(attribute, value)
	}
	return normalizer.Registry.NormalizeDNAttribute(attribute, value)
}

func TestPasswordBindDatabaseSnapshotMidCallbackMutation(t *testing.T) {
	for _, mode := range []string{"reader", "normalizer"} {
		t.Run(mode, func(t *testing.T) {
			instance, database, dn := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
			runtime := instance.runtime.Load()
			policyDN := staticRuntimeDN("cn=injected-policy,dc=example,dc=com")
			calls := 0
			mutate := func() {
				calls++
				database.ppolicy = &passwordPolicyRuntimeConfiguration{defaultPolicy: &policyDN}
			}
			var probe *bindDatabaseSnapshotProbeStore
			if mode == "reader" {
				probe = &bindDatabaseSnapshotProbeStore{Store: instance.config.Store, afterGet: func(int) { mutate() }}
				instance.config.Store = probe
			} else {
				database.dnNormalizer = &bindDatabaseSnapshotNormalizer{Registry: runtime.schema, before: func(_ string, value []byte) {
					if string(value) == "injected-policy" {
						t.Error("preverify observed a policy installed after its database snapshot")
					}
					mutate()
				}}
			}
			matches, err := instance.preverifyExternalPasswordBind(t.Context(), runtime, database, dn, []byte("secret"), instance.clock())
			if err != nil || !matches.empty() || calls == 0 || database.ppolicy == nil {
				t.Fatalf("preverify = %#v, %v; mutation calls=%d", matches, err, calls)
			}
			if probe != nil && (probe.views != 1 || len(probe.reads) != 1) {
				t.Fatalf("preverify read the injected policy: views=%d reads=%v", probe.views, probe.reads)
			}
		})
	}
}

func TestPasswordBindDatabaseSnapshotBetweenViews(t *testing.T) {
	for _, supplied := range []string{"secret", "replacement"} {
		t.Run(supplied, func(t *testing.T) {
			instance, database, dn := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
			runtime := instance.runtime.Load()
			original := *database
			next := original
			next.partition = "next-bind-snapshot"
			if err := instance.config.Store.Update(t.Context(), func(writer storage.Writer) error {
				entry, err := readerForDatabase(writer, original).Get(dn)
				if err != nil {
					return err
				}
				entry.ReplaceValues("userPassword", stringValues("replacement"))
				return writerForDatabase(writer, next).Put(entry, false)
			}); err != nil {
				t.Fatal(err)
			}
			probe := &bindDatabaseSnapshotProbeStore{Store: instance.config.Store, afterView: func(view int) error {
				if view == 1 {
					database.partition = next.partition
				}
				return nil
			}}
			instance.config.Store = probe
			result, err := instance.authenticatePasswordBind(t.Context(), runtime, dn.String(), []byte(supplied), false)
			if err != nil || result.authenticated != (supplied == "replacement") || result.authenticatedDN != dn.String() ||
				probe.views != 2 || probe.updates != 0 || !slices.Equal(probe.reads, []string{original.partition, next.partition}) {
				t.Fatalf("Bind = %#v, %v; views=%d updates=%d reads=%v", result, err, probe.views, probe.updates, probe.reads)
			}
		})
	}
}

func TestPasswordBindDatabaseSnapshotRuntimeReplacement(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		for _, supplied := range []string{"secret", "replacement"} {
			t.Run(fmt.Sprintf("fallback=%t/%s", fallback, supplied), func(t *testing.T) {
				instance, database, dn := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("secret"), nil)
				runtime := instance.runtime.Load()
				store := instance.config.Store
				var probe *bindDatabaseSnapshotProbeStore
				if fallback {
					probe = &bindDatabaseSnapshotProbeStore{Store: store}
					instance.config.Store = probe
				}
				if (instance.passwordBindDatabaseSnapshot(runtime, database) == database) == fallback {
					t.Fatal("fixture did not select the intended ownership path")
				}
				matches, err := instance.preverifyExternalPasswordBind(t.Context(), runtime, database, dn, []byte(supplied), instance.clock())
				if err != nil || !matches.empty() {
					t.Fatalf("preverify = %#v, %v", matches, err)
				}
				if err := store.Update(t.Context(), func(writer storage.Writer) error {
					tx := writerForDatabase(writer, *database)
					entry, err := tx.Get(dn)
					if err != nil {
						return err
					}
					entry.ReplaceValues("userPassword", stringValues("replacement"))
					return tx.Put(entry, true)
				}); err != nil {
					t.Fatal(err)
				}
				next := *runtime
				next.databases = slices.Clone(runtime.databases)
				databaseForDN(&next, dn).partition = "replacement-runtime"
				instance.runtime.Store(&next)
				result, err := instance.authenticateReadOnlyPasswordBind(t.Context(), runtime, database, dn, []byte(supplied), matches)
				if err != nil || result.authenticated != (supplied == "replacement") || result.authenticatedDN != dn.String() {
					t.Fatalf("final Bind = %#v, %v", result, err)
				}
				if probe != nil && (probe.views != 2 || probe.updates != 0 || !slices.Equal(probe.reads, []string{database.partition, database.partition})) {
					t.Fatalf("views=%d updates=%d reads=%v", probe.views, probe.updates, probe.reads)
				}
			})
		}
	}
}

type bindDatabaseSnapshotLogHandler struct {
	slog.Handler
	onLog func()
}

func (handler bindDatabaseSnapshotLogHandler) Handle(context.Context, slog.Record) error {
	handler.onLog()
	return nil
}

func TestPasswordBindDatabaseSnapshotExternalCallback(t *testing.T) {
	instance, database, dn := newReadOnlyPasswordBindFixture(t, "bolt", stringValues("{RADIUS}reader"), nil)
	runtime := instance.runtime.Load()
	runtime.externalPasswords = externalPasswordRuntimeConfiguration{
		radiusEnabled: true, radiusConfigPath: filepath.Join(t.TempDir(), "missing-radius.conf"),
	}
	if !plainBoltSearchStore(instance.config.Store) || instance.passwordBindDatabaseSnapshot(runtime, database) == database {
		t.Fatal("external verification must exclude even a plain Bolt database")
	}
	probe := &bindDatabaseSnapshotProbeStore{Store: instance.config.Store}
	instance.config.Store = probe
	calls := 0
	instance.config.Logger = slog.New(bindDatabaseSnapshotLogHandler{
		Handler: slog.NewTextHandler(io.Discard, nil),
		onLog: func() {
			calls++
			if probe.views != 1 {
				t.Error("external verification moved out of the preverify stage")
			}
			database.lastBind = true
		},
	})
	result, err := instance.authenticatePasswordBind(t.Context(), runtime, dn.String(), []byte("secret"), false)
	if !errors.Is(err, errReadOnlyBindUnexpectedUpdate) || !reflect.DeepEqual(result, passwordBindResult{}) ||
		calls != 1 || probe.views != 1 || probe.updates != 1 {
		t.Fatalf("Bind = %#v, %v; external calls=%d views=%d updates=%d", result, err, calls, probe.views, probe.updates)
	}
}
