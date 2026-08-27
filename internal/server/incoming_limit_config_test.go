package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadIncomingLimitRuntimeConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		addGlobal     bool
		anonymous     []string
		authenticated []string
		want          incomingLimits
		wantErrorText string
	}{
		{name: "missing cn=config", want: defaultIncomingLimits()},
		{name: "missing attributes", addGlobal: true, want: defaultIncomingLimits()},
		{name: "anonymous override", addGlobal: true, anonymous: []string{"7"}, want: incomingLimits{7, defaultIncomingLimitAuthenticated}},
		{name: "authenticated override", addGlobal: true, authenticated: []string{"9"}, want: incomingLimits{defaultIncomingLimitAnonymous, 9}},
		{name: "zero means unlimited", addGlobal: true, anonymous: []string{"0"}, authenticated: []string{"00"}, want: incomingLimits{}},
		{name: "base zero", addGlobal: true, anonymous: []string{"+0x10"}, authenticated: []string{"010"}, want: incomingLimits{16, 8}},
		{name: "uint64 maximum", addGlobal: true, anonymous: []string{"18446744073709551615"}, authenticated: []string{"0xffffffffffffffff"}, want: incomingLimits{^uint64(0), ^uint64(0)}},
		{name: "negative rejected", addGlobal: true, anonymous: []string{"-1"}, wantErrorText: "olcSockbufMaxIncoming: must be an unsigned 64-bit integer"},
		{name: "overflow rejected", addGlobal: true, authenticated: []string{"18446744073709551616"}, wantErrorText: "olcSockbufMaxIncomingAuth: must be an unsigned 64-bit integer"},
		{name: "binary rejected", addGlobal: true, anonymous: []string{"0b10"}, wantErrorText: "olcSockbufMaxIncoming: must be an unsigned 64-bit integer"},
		{name: "underscore rejected", addGlobal: true, anonymous: []string{"1_0"}, wantErrorText: "olcSockbufMaxIncoming: must be an unsigned 64-bit integer"},
		{name: "leading whitespace rejected", addGlobal: true, anonymous: []string{" 1"}, wantErrorText: "olcSockbufMaxIncoming: must be an unsigned 64-bit integer"},
		{name: "trailing whitespace rejected", addGlobal: true, authenticated: []string{"1 "}, wantErrorText: "olcSockbufMaxIncomingAuth: must be an unsigned 64-bit integer"},
		{name: "invalid octal rejected", addGlobal: true, anonymous: []string{"08"}, wantErrorText: "olcSockbufMaxIncoming: must be an unsigned 64-bit integer"},
		{name: "multiple anonymous values", addGlobal: true, anonymous: []string{"1", "2"}, wantErrorText: "olcSockbufMaxIncoming must contain exactly one value"},
		{name: "multiple authenticated values", addGlobal: true, authenticated: []string{"1", "2"}, wantErrorText: "olcSockbufMaxIncomingAuth must contain exactly one value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if test.addGlobal {
				putIncomingLimitGlobalEntry(t, store, test.anonymous, test.authenticated)
			}

			var got incomingLimits
			err := store.View(t.Context(), func(reader storage.Reader) error {
				var err error
				got, err = loadIncomingLimitRuntimeConfiguration(reader)
				return err
			})
			if test.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
					t.Fatalf("load error = %v, want %q", err, test.wantErrorText)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadIncomingLimitRuntimeConfiguration(): %v", err)
			}
			if got != test.want {
				t.Fatalf("incoming limits = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestIncomingLimitsSelectAuthenticationState(t *testing.T) {
	t.Parallel()
	limits := incomingLimits{anonymous: 11, authenticated: 22}
	if got := limits.forAuthentication(false); got != 11 {
		t.Fatalf("anonymous limit = %d, want 11", got)
	}
	if got := limits.forAuthentication(true); got != 22 {
		t.Fatalf("authenticated limit = %d, want 22", got)
	}
}

func TestValidateIncomingLimitOnlineChanges(t *testing.T) {
	t.Parallel()
	global := incomingLimitEntry("cn=config", []string{"5"}, []string{"6"})
	tests := []struct {
		name     string
		entry    directory.Entry
		changes  []ldapwire.Modification
		wantCode ldapwire.ResultCode
	}{
		{name: "unrelated change ignored", entry: incomingLimitEntry("dc=example,dc=com", nil, nil), changes: incomingLimitChanges(incomingLimitReplace("description", "value"))},
		{name: "only cn=config", entry: incomingLimitEntry("cn=other", nil, nil), changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "1")), wantCode: ldapwire.ResultObjectClassViolation},
		{name: "same add", entry: global, changes: incomingLimitChanges(incomingLimitAdd(incomingLimitAnonymousAttribute, "5")), wantCode: ldapwire.ResultAttributeOrValueExists},
		{name: "different add", entry: global, changes: incomingLimitChanges(incomingLimitAdd(incomingLimitAnonymousAttribute, "7")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "empty add", entry: incomingLimitEntry("cn=config", nil, nil), changes: incomingLimitChanges(incomingLimitAdd(incomingLimitAnonymousAttribute)), wantCode: ldapwire.ResultConstraintViolation},
		{name: "duplicate add", entry: incomingLimitEntry("cn=config", nil, nil), changes: incomingLimitChanges(incomingLimitAdd(incomingLimitAnonymousAttribute, "1", "1")), wantCode: ldapwire.ResultAttributeOrValueExists},
		{name: "distinct multi add", entry: incomingLimitEntry("cn=config", nil, nil), changes: incomingLimitChanges(incomingLimitAdd(incomingLimitAnonymousAttribute, "1", "2")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "duplicate replace", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAuthenticatedAttribute, "1", "1")), wantCode: ldapwire.ResultAttributeOrValueExists},
		{name: "distinct multi replace", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAuthenticatedAttribute, "1", "2")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "negative", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "-1")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "overflow", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "18446744073709551616")), wantCode: ldapwire.ResultConstraintViolation},
		{name: "leading zero", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "01")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "plus sign", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "+1")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "hex", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "0x10")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "negative zero", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, "-0")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "whitespace", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAnonymousAttribute, " 1")), wantCode: ldapwire.ResultInvalidAttributeSyntax},
		{name: "zero", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAuthenticatedAttribute, "0"))},
		{name: "uint64 maximum", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAuthenticatedAttribute, "18446744073709551615"))},
		{name: "delete whole", entry: global, changes: incomingLimitChanges(incomingLimitDelete(incomingLimitAnonymousAttribute))},
		{name: "delete absent whole", entry: incomingLimitEntry("cn=config", nil, nil), changes: incomingLimitChanges(incomingLimitDelete(incomingLimitAnonymousAttribute)), wantCode: ldapwire.ResultNoSuchAttribute},
		{name: "delete existing value", entry: global, changes: incomingLimitChanges(incomingLimitDelete(incomingLimitAnonymousAttribute, "5"))},
		{name: "delete missing value", entry: global, changes: incomingLimitChanges(incomingLimitDelete(incomingLimitAnonymousAttribute, "7")), wantCode: ldapwire.ResultNoSuchAttribute},
		{name: "replace without values deletes", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAuthenticatedAttribute))},
		{name: "delete then add observes order", entry: global, changes: incomingLimitChanges(incomingLimitDelete(incomingLimitAnonymousAttribute), incomingLimitAdd(incomingLimitAnonymousAttribute, "7"))},
		{name: "replace then same add", entry: global, changes: incomingLimitChanges(incomingLimitReplace(incomingLimitAuthenticatedAttribute, "9"), incomingLimitAdd(incomingLimitAuthenticatedAttribute, "9")), wantCode: ldapwire.ResultAttributeOrValueExists},
		{name: "attributes are independent", entry: global, changes: incomingLimitChanges(incomingLimitDelete(incomingLimitAnonymousAttribute), incomingLimitReplace(incomingLimitAuthenticatedAttribute, "9"), incomingLimitAdd(incomingLimitAnonymousAttribute, "7"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := test.entry.Clone()
			err := validateIncomingLimitOnlineChanges(test.entry, test.changes)
			if test.wantCode == ldapwire.ResultSuccess {
				if err != nil {
					t.Fatalf("validateIncomingLimitOnlineChanges(): %v", err)
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

func TestIncomingLimitRuntimeRebuildAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	putIncomingLimitGlobalEntry(t, store, []string{"010"}, []string{"0x20"})

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	active := instance.runtime.Load()
	assertIncomingLimitRuntime(t, active, incomingLimits{8, 32})

	var next *runtimeState
	err = store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceIncomingLimitValues(writer, []string{"7"}, nil); err != nil {
			return err
		}
		var err error
		next, err = instance.validateRuntimeConfiguration(writer)
		return err
	})
	if err != nil {
		t.Fatalf("valid runtime rebuild: %v", err)
	}
	assertIncomingLimitRuntime(t, next, incomingLimits{7, defaultIncomingLimitAuthenticated})
	assertIncomingLimitRuntime(t, active, incomingLimits{8, 32})
	instance.activateRuntime(next)

	err = store.Update(t.Context(), func(writer storage.Writer) error {
		if err := replaceIncomingLimitValues(
			writer,
			[]string{"18446744073709551616"},
			[]string{"9"},
		); err != nil {
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
	assertStoredIncomingLimitValues(t, store, []string{"7"}, nil)
}

func putIncomingLimitGlobalEntry(
	t *testing.T,
	store storage.Store,
	anonymous, authenticated []string,
) {
	t.Helper()
	err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry := incomingLimitEntry("cn=config", anonymous, authenticated)
		entry.Attributes = append(entry.Attributes,
			directory.Attribute{Description: "objectClass", Values: stringValues("olcGlobal")},
			directory.Attribute{Description: "cn", Values: stringValues("config")},
		)
		return writer.PutIn(storage.OpenLDAPConfigPartition, entry, false)
	})
	if err != nil {
		t.Fatalf("seed incoming limit configuration: %v", err)
	}
}

func incomingLimitEntry(dn string, anonymous, authenticated []string) directory.Entry {
	entry := directory.Entry{DN: dn}
	if anonymous != nil {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: incomingLimitAnonymousAttribute,
			Values:      stringValues(anonymous...),
		})
	}
	if authenticated != nil {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: incomingLimitAuthenticatedAttribute,
			Values:      stringValues(authenticated...),
		})
	}
	return entry
}

func incomingLimitChanges(changes ...ldapwire.Modification) []ldapwire.Modification {
	return changes
}

func incomingLimitAdd(description string, values ...string) ldapwire.Modification {
	return incomingLimitModification(ldapwire.ModificationAdd, description, values...)
}

func incomingLimitDelete(description string, values ...string) ldapwire.Modification {
	return incomingLimitModification(ldapwire.ModificationDelete, description, values...)
}

func incomingLimitReplace(description string, values ...string) ldapwire.Modification {
	return incomingLimitModification(ldapwire.ModificationReplace, description, values...)
}

func incomingLimitModification(
	operation ldapwire.ModificationOperation,
	description string,
	values ...string,
) ldapwire.Modification {
	return ldapwire.Modification{
		Operation: operation,
		Attribute: directory.Attribute{
			Description: description,
			Values:      stringValues(values...),
		},
	}
}

func replaceIncomingLimitValues(
	writer storage.Writer,
	anonymous, authenticated []string,
) error {
	configuration := storage.WriterInPartition(writer, storage.OpenLDAPConfigPartition)
	entry, err := configuration.Get(configurationSuffix)
	if err != nil {
		return err
	}
	entry.ReplaceValues(incomingLimitAnonymousAttribute, stringValues(anonymous...))
	entry.ReplaceValues(incomingLimitAuthenticatedAttribute, stringValues(authenticated...))
	return configuration.Put(entry, true)
}

func assertIncomingLimitRuntime(t *testing.T, runtime *runtimeState, want incomingLimits) {
	t.Helper()
	if runtime == nil || runtime.incomingLimits != want {
		t.Fatalf("runtime incoming limits = %#v, want %#v", runtime, want)
	}
}

func assertStoredIncomingLimitValues(
	t *testing.T,
	store storage.Store,
	anonymous, authenticated []string,
) {
	t.Helper()
	err := store.View(t.Context(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(storage.OpenLDAPConfigPartition, configurationSuffix)
		if err != nil {
			return err
		}
		if !equalIncomingLimitValues(entry.Values(incomingLimitAnonymousAttribute), anonymous) ||
			!equalIncomingLimitValues(entry.Values(incomingLimitAuthenticatedAttribute), authenticated) {
			return errors.New("failed incoming limit configuration was committed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func equalIncomingLimitValues(got [][]byte, want []string) bool {
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
