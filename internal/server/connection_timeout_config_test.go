package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadConnectionTimeoutRuntimeConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		addGlobal     bool
		idle          []string
		write         []string
		wantIdle      time.Duration
		wantWrite     time.Duration
		wantErrorText string
	}{
		{name: "missing cn=config"},
		{name: "missing attributes", addGlobal: true},
		{name: "idle independently overrides", addGlobal: true, idle: []string{"7"}, wantIdle: 7 * time.Second},
		{name: "write independently overrides", addGlobal: true, write: []string{"9"}, wantWrite: 9 * time.Second},
		{name: "zero", addGlobal: true, idle: []string{"0"}, write: []string{"-0"}},
		{name: "base zero", addGlobal: true, idle: []string{" \t+0x10"}, write: []string{"010"}, wantIdle: 16 * time.Second, wantWrite: 8 * time.Second},
		{name: "int32 maximum", addGlobal: true, idle: []string{"2147483647"}, wantIdle: 2147483647 * time.Second},
		{name: "hex int32 maximum", addGlobal: true, idle: []string{"0x7fffffff"}, wantIdle: 2147483647 * time.Second},
		{name: "octal int32 maximum", addGlobal: true, write: []string{"017777777777"}, wantWrite: 2147483647 * time.Second},
		{name: "negative idle disables", addGlobal: true, idle: []string{"-1"}, wantIdle: -time.Second},
		{name: "negative write disables", addGlobal: true, write: []string{"-2147483648"}, wantWrite: -2147483648 * time.Second},
		{name: "positive overflow", addGlobal: true, idle: []string{"2147483648"}, wantErrorText: "olcIdleTimeout: must be a 32-bit integer"},
		{name: "binary prefix rejected", addGlobal: true, idle: []string{"0b10"}, wantErrorText: "olcIdleTimeout: must be a 32-bit integer"},
		{name: "underscore rejected", addGlobal: true, write: []string{"1_0"}, wantErrorText: "olcWriteTimeout: must be a 32-bit integer"},
		{name: "trailing whitespace rejected", addGlobal: true, idle: []string{"1 "}, wantErrorText: "olcIdleTimeout: must be a 32-bit integer"},
		{name: "multiple idle values", addGlobal: true, idle: []string{"1", "2"}, wantErrorText: "olcIdleTimeout must contain exactly one value"},
		{name: "multiple write values", addGlobal: true, write: []string{"1", "2"}, wantErrorText: "olcWriteTimeout must contain exactly one value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if test.addGlobal {
				putConnectionTimeoutGlobalEntry(t, store, test.idle, test.write)
			}

			var idle, write time.Duration
			err := store.View(t.Context(), func(reader storage.Reader) error {
				var err error
				idle, write, err = loadConnectionTimeoutRuntimeConfiguration(reader)
				return err
			})
			if test.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
					t.Fatalf("load error = %v, want %q", err, test.wantErrorText)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConnectionTimeoutRuntimeConfiguration(): %v", err)
			}
			if idle != test.wantIdle || write != test.wantWrite {
				t.Fatalf("timeouts = (%v, %v), want (%v, %v)", idle, write, test.wantIdle, test.wantWrite)
			}
		})
	}
}

func TestValidateConnectionTimeoutOnlineChanges(t *testing.T) {
	t.Parallel()
	global := connectionTimeoutEntry("cn=config", []string{"5"}, []string{"6"})
	tests := []struct {
		name     string
		entry    directory.Entry
		changes  []ldapwire.Modification
		wantCode ldapwire.ResultCode
	}{
		{name: "unrelated change ignored", entry: connectionTimeoutEntry("dc=example,dc=com", nil, nil), changes: timeoutChanges(timeoutReplace("description", "value"))},
		{name: "only cn=config", entry: connectionTimeoutEntry("cn=other", nil, nil), changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "1")), wantCode: ldapwire.ResultObjectClassViolation},
		{name: "same add", entry: global, changes: timeoutChanges(timeoutAdd(idleTimeoutAttribute, "5")), wantCode: ldapwire.ResultAttributeOrValueExists},
		{name: "different add", entry: global, changes: timeoutChanges(timeoutAdd(idleTimeoutAttribute, "7")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "multi add", entry: connectionTimeoutEntry("cn=config", nil, nil), changes: timeoutChanges(timeoutAdd(idleTimeoutAttribute, "1", "2")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "multi replace", entry: global, changes: timeoutChanges(timeoutReplace(writeTimeoutAttribute, "1", "2")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "negative", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "-1"))},
		{name: "positive overflow", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "2147483648")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "negative overflow", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "-2147483649")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "leading zero", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "01")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "plus sign", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "+1")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "hex", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "0x10")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "negative zero", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, "-0")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "whitespace", entry: global, changes: timeoutChanges(timeoutReplace(idleTimeoutAttribute, " 1")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "delete resets idle", entry: global, changes: timeoutChanges(timeoutDelete(idleTimeoutAttribute))},
		{name: "replace zero", entry: global, changes: timeoutChanges(timeoutReplace(writeTimeoutAttribute, "0"))},
		{name: "delete then add observes order", entry: global, changes: timeoutChanges(timeoutDelete(idleTimeoutAttribute), timeoutAdd(idleTimeoutAttribute, "7"))},
		{name: "add then delete fails before delete", entry: global, changes: timeoutChanges(timeoutAdd(idleTimeoutAttribute, "7"), timeoutDelete(idleTimeoutAttribute, "5")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "replace then same add", entry: global, changes: timeoutChanges(timeoutReplace(writeTimeoutAttribute, "9"), timeoutAdd(writeTimeoutAttribute, "9")), wantCode: ldapwire.ResultAttributeOrValueExists},
		{name: "attributes are independent", entry: global, changes: timeoutChanges(timeoutDelete(idleTimeoutAttribute), timeoutReplace(writeTimeoutAttribute, "9"), timeoutAdd(idleTimeoutAttribute, "7"))},
		{name: "delete missing value", entry: global, changes: timeoutChanges(timeoutDelete(idleTimeoutAttribute, "7")), wantCode: ldapwire.ResultNoSuchAttribute},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := test.entry.Clone()
			err := validateConnectionTimeoutOnlineChanges(test.entry, test.changes)
			if test.wantCode == ldapwire.ResultSuccess {
				if err != nil {
					t.Fatalf("validateConnectionTimeoutOnlineChanges(): %v", err)
				}
			} else {
				failure := asOperationFailure(err)
				if failure == nil || failure.result.Code != test.wantCode {
					t.Fatalf("failure = %#v, want code %d", failure, test.wantCode)
				}
			}
			if !test.entry.Equal(before) {
				t.Fatal("validator mutated the entry after simulating changes")
			}
		})
	}
}

func TestConnectionTimeoutRuntimeRebuildAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	putConnectionTimeoutGlobalEntry(t, store, []string{"5"}, []string{"6"})

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	active := instance.runtime.Load()
	assertConnectionTimeoutRuntime(t, active, 5*time.Second, 6*time.Second)

	var next *runtimeState
	err = store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceConnectionTimeoutValues(writer, []string{"7"}, nil); err != nil {
			return err
		}
		var err error
		next, err = instance.validateRuntimeConfiguration(writer)
		return err
	})
	if err != nil {
		t.Fatalf("valid runtime rebuild: %v", err)
	}
	assertConnectionTimeoutRuntime(t, next, 7*time.Second, 0)
	assertConnectionTimeoutRuntime(t, active, 5*time.Second, 6*time.Second)
	instance.activateRuntime(next)

	err = store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceConnectionTimeoutValues(writer, []string{"2147483648"}, []string{"9"}); err != nil {
			return err
		}
		_, err := instance.validateRuntimeConfiguration(writer)
		return err
	})
	if err == nil {
		t.Fatal("invalid runtime rebuild succeeded")
	}
	if instance.runtime.Load() != next {
		t.Fatal("failed rebuild replaced the active runtime")
	}
	assertStoredConnectionTimeoutValues(t, store, []string{"7"}, nil)
}

func putConnectionTimeoutGlobalEntry(t *testing.T, store storage.Store, idle, write []string) {
	t.Helper()
	err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry := connectionTimeoutEntry("cn=config", idle, write)
		entry.Attributes = append(entry.Attributes,
			directory.Attribute{Description: "objectClass", Values: stringValues("olcGlobal")},
			directory.Attribute{Description: "cn", Values: stringValues("config")},
		)
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	})
	if err != nil {
		t.Fatalf("seed connection timeout configuration: %v", err)
	}
}

func connectionTimeoutEntry(dn string, idle, write []string) directory.Entry {
	entry := directory.Entry{DN: dn}
	if idle != nil {
		entry.Attributes = append(entry.Attributes, directory.Attribute{Description: idleTimeoutAttribute, Values: stringValues(idle...)})
	}
	if write != nil {
		entry.Attributes = append(entry.Attributes, directory.Attribute{Description: writeTimeoutAttribute, Values: stringValues(write...)})
	}
	return entry
}

func timeoutChanges(changes ...ldapwire.Modification) []ldapwire.Modification { return changes }

func timeoutAdd(description string, values ...string) ldapwire.Modification {
	return timeoutModification(ldapwire.ModificationAdd, description, values...)
}

func timeoutDelete(description string, values ...string) ldapwire.Modification {
	return timeoutModification(ldapwire.ModificationDelete, description, values...)
}

func timeoutReplace(description string, values ...string) ldapwire.Modification {
	return timeoutModification(ldapwire.ModificationReplace, description, values...)
}

func timeoutModification(operation ldapwire.ModificationOperation, description string, values ...string) ldapwire.Modification {
	return ldapwire.Modification{Operation: operation, Attribute: directory.Attribute{Description: description, Values: stringValues(values...)}}
}

func replaceConnectionTimeoutValues(writer storage.Writer, idle, write []string) error {
	configuration := storage.WriterInPartition(writer, storage.OpenLDAPConfigPartition)
	entry, err := configuration.Get(configurationSuffix)
	if err != nil {
		return err
	}
	entry.ReplaceValues(idleTimeoutAttribute, stringValues(idle...))
	entry.ReplaceValues(writeTimeoutAttribute, stringValues(write...))
	return configuration.Put(entry, true)
}

func assertConnectionTimeoutRuntime(t *testing.T, runtime *runtimeState, idle, write time.Duration) {
	t.Helper()
	if runtime == nil || runtime.idleTimeout != idle || runtime.writeTimeout != write {
		t.Fatalf("runtime timeouts = %#v, want idle=%v write=%v", runtime, idle, write)
	}
}

func assertStoredConnectionTimeoutValues(t *testing.T, store storage.Store, idle, write []string) {
	t.Helper()
	err := store.View(t.Context(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(storage.OpenLDAPConfigPartition, configurationSuffix)
		if err != nil {
			return err
		}
		if !equalConnectionTimeoutValues(entry.Values(idleTimeoutAttribute), idle) ||
			!equalConnectionTimeoutValues(entry.Values(writeTimeoutAttribute), write) {
			return errors.New("failed connection timeout configuration was committed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func equalConnectionTimeoutValues(got [][]byte, want []string) bool {
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
