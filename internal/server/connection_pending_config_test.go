package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadConnectionPendingRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		addGlobal     bool
		maxPending    []string
		maxAuth       []string
		wantPending   int
		wantAuth      int
		wantErrorText string
	}{
		{
			name:        "missing cn=config uses defaults",
			wantPending: defaultConnectionMaxPending,
			wantAuth:    defaultConnectionMaxPendingAuth,
		},
		{
			name:        "missing attributes use defaults",
			addGlobal:   true,
			wantPending: defaultConnectionMaxPending,
			wantAuth:    defaultConnectionMaxPendingAuth,
		},
		{
			name:        "anonymous override keeps authenticated default",
			addGlobal:   true,
			maxPending:  []string{"7"},
			wantPending: 7,
			wantAuth:    defaultConnectionMaxPendingAuth,
		},
		{
			name:        "authenticated override keeps anonymous default",
			addGlobal:   true,
			maxAuth:     []string{"70"},
			wantPending: defaultConnectionMaxPending,
			wantAuth:    70,
		},
		{
			name:        "OpenLDAP signed and zero values",
			addGlobal:   true,
			maxPending:  []string{"-1"},
			maxAuth:     []string{"0"},
			wantPending: -1,
			wantAuth:    0,
		},
		{
			name:        "OpenLDAP base zero values",
			addGlobal:   true,
			maxPending:  []string{" \t+0x10"},
			maxAuth:     []string{"010"},
			wantPending: 16,
			wantAuth:    8,
		},
		{
			name:        "32-bit boundaries",
			addGlobal:   true,
			maxPending:  []string{"-2147483648"},
			maxAuth:     []string{"2147483647"},
			wantPending: -2147483648,
			wantAuth:    2147483647,
		},
		{
			name:          "invalid anonymous integer",
			addGlobal:     true,
			maxPending:    []string{"invalid"},
			wantErrorText: "olcConnMaxPending must be a 32-bit integer",
		},
		{
			name:          "trailing whitespace is not an integer token",
			addGlobal:     true,
			maxPending:    []string{"7 "},
			wantErrorText: "olcConnMaxPending must be a 32-bit integer",
		},
		{
			name:          "authenticated integer overflow",
			addGlobal:     true,
			maxAuth:       []string{"2147483648"},
			wantErrorText: "olcConnMaxPendingAuth must be a 32-bit integer",
		},
		{
			name:          "duplicate anonymous value",
			addGlobal:     true,
			maxPending:    []string{"1", "2"},
			wantErrorText: "olcConnMaxPending must contain exactly one value",
		},
		{
			name:          "duplicate authenticated value",
			addGlobal:     true,
			maxAuth:       []string{"10", "20"},
			wantErrorText: "olcConnMaxPendingAuth must contain exactly one value",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if test.addGlobal {
				putConnectionPendingGlobalEntry(
					t,
					store,
					test.maxPending,
					test.maxAuth,
				)
			}

			var got connectionPendingRuntimeConfiguration
			err := store.View(t.Context(), func(reader storage.Reader) error {
				var err error
				got, err = loadConnectionPendingRuntimeConfiguration(reader)
				return err
			})
			if test.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
					t.Fatalf("load error = %v, want %q", err, test.wantErrorText)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConnectionPendingRuntimeConfiguration(): %v", err)
			}
			if got.maxPending != test.wantPending || got.maxPendingAuth != test.wantAuth {
				t.Fatalf(
					"connection pending configuration = %#v, want pending=%d auth=%d",
					got,
					test.wantPending,
					test.wantAuth,
				)
			}
		})
	}
}

func TestConnectionPendingRuntimeRebuildAndValidationRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	putConnectionPendingGlobalEntry(t, store, []string{"7"}, []string{"70"})

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	assertConnectionPendingRuntime(t, instance.runtime.Load(), 7, 70)

	next := rebuildConnectionPendingRuntime(t, instance, store, []string{"9"}, nil)
	assertConnectionPendingRuntime(
		t,
		next,
		9,
		defaultConnectionMaxPendingAuth,
	)
	instance.activateRuntime(next)
	assertConnectionPendingRuntime(
		t,
		instance.runtime.Load(),
		9,
		defaultConnectionMaxPendingAuth,
	)

	for _, test := range []struct {
		name       string
		maxPending []string
		maxAuth    []string
	}{
		{
			name:       "invalid integer",
			maxPending: []string{"not-an-integer"},
			maxAuth:    []string{"1000"},
		},
		{
			name:       "duplicate value",
			maxPending: []string{"1", "2"},
			maxAuth:    []string{"1000"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			active := instance.runtime.Load()
			err := store.Update(t.Context(), func(writer storage.Writer) error {
				if err := replaceConnectionPendingValues(
					writer,
					test.maxPending,
					test.maxAuth,
				); err != nil {
					return err
				}
				_, err := instance.validateRuntimeConfiguration(writer)
				return err
			})
			if err == nil {
				t.Fatal("invalid configuration rebuild succeeded")
			}
			if instance.runtime.Load() != active {
				t.Fatal("failed rebuild replaced the active runtime")
			}
			assertStoredConnectionPendingValues(t, store, []string{"9"}, nil)
		})
	}
}

func putConnectionPendingGlobalEntry(
	t *testing.T,
	store storage.Store,
	maxPending,
	maxAuth []string,
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
		if maxPending != nil {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description: "olcConnMaxPending",
				Values:      stringValues(maxPending...),
			})
		}
		if maxAuth != nil {
			entry.Attributes = append(entry.Attributes, directory.Attribute{
				Description: "olcConnMaxPendingAuth",
				Values:      stringValues(maxAuth...),
			})
		}
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	}); err != nil {
		t.Fatalf("seed connection pending configuration: %v", err)
	}
}

func rebuildConnectionPendingRuntime(
	t *testing.T,
	instance *Server,
	store storage.Store,
	maxPending,
	maxAuth []string,
) *runtimeState {
	t.Helper()
	var next *runtimeState
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceConnectionPendingValues(writer, maxPending, maxAuth); err != nil {
			return err
		}
		var err error
		next, err = instance.validateRuntimeConfiguration(writer)
		return err
	}); err != nil {
		t.Fatalf("rebuild connection pending runtime: %v", err)
	}
	return next
}

func replaceConnectionPendingValues(
	writer storage.Writer,
	maxPending,
	maxAuth []string,
) error {
	configuration := storage.WriterInPartition(writer, storage.OpenLDAPConfigPartition)
	entry, err := configuration.Get(configurationSuffix)
	if err != nil {
		return err
	}
	entry.ReplaceValues("olcConnMaxPending", stringValues(maxPending...))
	entry.ReplaceValues("olcConnMaxPendingAuth", stringValues(maxAuth...))
	return configuration.Put(entry, true)
}

func assertConnectionPendingRuntime(
	t *testing.T,
	runtime *runtimeState,
	wantPending,
	wantAuth int,
) {
	t.Helper()
	if runtime == nil ||
		runtime.connectionPending.maxPending != wantPending ||
		runtime.connectionPending.maxPendingAuth != wantAuth {
		t.Fatalf(
			"runtime connection pending configuration = %#v, want pending=%d auth=%d",
			runtime,
			wantPending,
			wantAuth,
		)
	}
}

func assertStoredConnectionPendingValues(
	t *testing.T,
	store storage.Store,
	wantPending,
	wantAuth []string,
) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(storage.OpenLDAPConfigPartition, configurationSuffix)
		if err != nil {
			return err
		}
		if !equalConnectionPendingValues(entry.Values("olcConnMaxPending"), wantPending) ||
			!equalConnectionPendingValues(entry.Values("olcConnMaxPendingAuth"), wantAuth) {
			return errors.New("failed connection pending configuration was committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func equalConnectionPendingValues(got [][]byte, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if string(got[index]) != want[index] {
			return false
		}
	}
	return true
}
