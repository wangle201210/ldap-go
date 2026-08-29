package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadGentleHUPConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		entries   []directory.Entry
		want      bool
		wantError string
	}{
		{name: "absent"},
		{
			name: "enabled",
			entries: []directory.Entry{{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: gentleHUPAttribute,
					Values:      stringValues("TRUE"),
				}},
			}},
			want: true,
		},
		{
			name: "disabled",
			entries: []directory.Entry{{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: gentleHUPAttribute,
					Values:      stringValues("false"),
				}},
			}},
		},
		{
			name: "invalid value",
			entries: []directory.Entry{{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: gentleHUPAttribute,
					Values:      stringValues("sometimes"),
				}},
			}},
			wantError: "invalid value",
		},
		{
			name: "multiple values",
			entries: []directory.Entry{{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: gentleHUPAttribute,
					Values:      stringValues("TRUE", "FALSE"),
				}},
			}},
			wantError: "single-valued",
		},
		{
			name: "wrong location",
			entries: []directory.Entry{
				{DN: "cn=config"},
				{
					DN: "olcDatabase={1}mdb,cn=config",
					Attributes: []directory.Attribute{{
						Description: gentleHUPAttribute,
						Values:      stringValues("TRUE"),
					}},
				},
			},
			wantError: "only valid on cn=config",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				for _, entry := range test.entries {
					if err := writer.Put(entry, false); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			var got bool
			err := store.View(t.Context(), func(reader storage.Reader) error {
				var err error
				got, err = loadGentleHUP(reader)
				return err
			})
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("loadGentleHUP() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("loadGentleHUP() = %t, %v; want %t", got, err, test.want)
			}
		})
	}
}

func TestServerGentleShutdownKeepsExistingReadsAndRejectsWrites(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: gentleHUPAttribute,
				Values:      stringValues("TRUE"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:           store,
		RootDN:          "cn=admin,dc=example,dc=com",
		RootPassword:    []byte("secret"),
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})

	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	if !instance.BeginGentleShutdown(listener) {
		t.Fatal("BeginGentleShutdown() did not start")
	}
	if instance.BeginGentleShutdown(listener) {
		t.Fatal("duplicate BeginGentleShutdown() started")
	}
	select {
	case err := <-done:
		t.Fatalf("Serve() returned with an existing client: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search during gentle shutdown = %#v, %v", result, err)
	}
	add := ldap.NewAddRequest("uid=blocked,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"blocked"})
	add.Attribute("cn", []string{"Blocked User"})
	add.Attribute("sn", []string{"User"})
	err = client.Add(add)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("Add during gentle shutdown = %v", err)
	}
	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
		"replacement",
	))
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("Password Modify during gentle shutdown = %v", err)
	}

	client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() after client close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not finish after the last client closed")
	}
}

func TestGentleHUPRuntimeRebuildAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues(gentleHUPAttribute, stringValues("FALSE"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	initial := instance.runtime.Load()
	if initial.gentleHUP {
		t.Fatal("initial runtime enabled gentle HUP")
	}

	var enabled *runtimeState
	err = store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues(gentleHUPAttribute, stringValues("TRUE"))
		if err := writer.PutIn(configurationStoragePartition, entry, true); err != nil {
			return err
		}
		enabled, err = instance.validateRuntimeConfiguration(writer)
		return err
	})
	if err != nil {
		if failure := asOperationFailure(err); failure != nil {
			t.Fatalf("enable runtime: %s", failure.result.DiagnosticMessage)
		}
		t.Fatalf("enable runtime: %v", err)
	}
	if !enabled.gentleHUP || initial.gentleHUP {
		t.Fatalf("runtime snapshots = initial:%t enabled:%t", initial.gentleHUP, enabled.gentleHUP)
	}
	instance.activateRuntime(enabled)

	err = store.Update(t.Context(), func(writer storage.Writer) error {
		entry, err := writer.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues(gentleHUPAttribute, stringValues("invalid"))
		if err := writer.PutIn(configurationStoragePartition, entry, true); err != nil {
			return err
		}
		_, err = instance.validateRuntimeConfiguration(writer)
		return err
	})
	if err == nil {
		t.Fatal("invalid gentle HUP runtime rebuild succeeded")
	}
	if instance.runtime.Load() != enabled || !instance.GentleHUPEnabled() {
		t.Fatal("failed rebuild replaced the active runtime")
	}
	if err := store.View(t.Context(), func(reader storage.Reader) error {
		entry, err := reader.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		values := entry.Values(gentleHUPAttribute)
		if len(values) != 1 || string(values[0]) != "TRUE" {
			return errors.New("failed rebuild changed persisted olcGentleHUP")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateGentleHUPOnlineChangesLocation(t *testing.T) {
	change := ldapwire.Modification{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{
			Description: gentleHUPAttribute,
			Values:      stringValues("TRUE"),
		},
	}
	if err := validateGentleHUPOnlineChanges(
		directory.Entry{DN: "cn=config"},
		[]ldapwire.Modification{change},
	); err != nil {
		t.Fatalf("global change: %v", err)
	}
	failure := asOperationFailure(validateGentleHUPOnlineChanges(
		directory.Entry{DN: "olcDatabase={1}mdb,cn=config"},
		[]ldapwire.Modification{change},
	))
	if failure == nil || failure.result.Code != ldapwire.ResultObjectClassViolation {
		t.Fatalf("misplaced change failure = %#v", failure)
	}
}

func TestGentleHUPOnlineConfigurationLifecycle(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("online gentle HUP test server did not stop")
		}
	})

	client, err := ldap.DialURL("ldap://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	enable := ldap.NewModifyRequest("cn=config", nil)
	enable.Replace(gentleHUPAttribute, []string{"TRUE"})
	if err := client.Modify(enable); err != nil {
		t.Fatalf("enable olcGentleHUP: %v", err)
	}
	if !instance.GentleHUPEnabled() {
		t.Fatal("online enable did not publish the runtime")
	}

	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace(gentleHUPAttribute, []string{"invalid"})
	if err := client.Modify(invalid); err == nil {
		t.Fatal("invalid olcGentleHUP was accepted")
	}
	if !instance.GentleHUPEnabled() {
		t.Fatal("invalid online change replaced the active runtime")
	}

	misplaced := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	misplaced.Replace(gentleHUPAttribute, []string{"FALSE"})
	err = client.Modify(misplaced)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != ldap.LDAPResultObjectClassViolation {
		t.Fatalf("misplaced olcGentleHUP = %v", err)
	}

	disable := ldap.NewModifyRequest("cn=config", nil)
	disable.Delete(gentleHUPAttribute, nil)
	if err := client.Modify(disable); err != nil {
		t.Fatalf("delete olcGentleHUP: %v", err)
	}
	if instance.GentleHUPEnabled() {
		t.Fatal("online delete did not restore the default")
	}
}

func TestServerGentleShutdownEscalatesOnContextCancellation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: gentleHUPAttribute,
				Values:      stringValues("TRUE"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:           store,
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer connection.Close()
	deadline := time.Now().Add(time.Second)
	for {
		instance.mu.Lock()
		accepted := len(instance.connections) != 0
		instance.mu.Unlock()
		if accepted {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("server did not register the existing connection")
		}
		time.Sleep(time.Millisecond)
	}
	if !instance.BeginGentleShutdown(listener) {
		cancel()
		t.Fatal("BeginGentleShutdown() did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() after escalation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not escalate gentle shutdown")
	}
}

func TestServerGentleShutdownBeforeServeStarts(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: gentleHUPAttribute,
				Values:      stringValues("TRUE"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{Store: store, ShutdownTimeout: time.Second})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if !instance.BeginGentleShutdown(listener) {
		t.Fatal("pre-Serve BeginGentleShutdown() did not start")
	}
	if err := instance.Serve(context.Background(), listener); err != nil {
		t.Fatalf("Serve() after pre-start gentle shutdown: %v", err)
	}
	if instance.gentleDraining.Load() {
		t.Fatal("Serve() retained gentle state after return")
	}
}

func TestGentleShutdownWriteClassification(t *testing.T) {
	instance := &Server{}
	instance.gentleDraining.Store(true)
	for _, test := range []struct {
		name    string
		request ldapwire.Request
		write   bool
	}{
		{name: "Add", request: ldapwire.AddRequest{}, write: true},
		{name: "Modify", request: ldapwire.ModifyRequest{}, write: true},
		{name: "Delete", request: ldapwire.DeleteRequest{}, write: true},
		{name: "ModifyDN", request: ldapwire.ModifyDNRequest{}, write: true},
		{name: "Password Modify", request: ldapwire.ExtendedRequest{Name: passwordModifyOID}, write: true},
		{name: "Dynamic Refresh", request: ldapwire.ExtendedRequest{Name: dynamicRefreshOID}, write: true},
		{name: "Search", request: ldapwire.SearchRequest{}},
		{name: "Compare", request: ldapwire.CompareRequest{}},
		{name: "Bind", request: ldapwire.BindRequest{}},
		{name: "Who Am I", request: ldapwire.ExtendedRequest{Name: whoAmIOID}},
		{name: "StartTLS", request: ldapwire.ExtendedRequest{Name: startTLSOID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := instance.gentleShutdownRequestResult(test.request)
			if (failure != nil) != test.write {
				t.Fatalf("gentle restriction = %#v, want write=%t", failure, test.write)
			}
			if failure != nil && failure.Code != ldapwire.ResultUnwillingToPerform {
				t.Fatalf("gentle restriction code = %d", failure.Code)
			}
		})
	}
}

func TestGentleShutdownRejectsQueuedTransactionCommit(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: gentleHUPAttribute,
				Values:      stringValues("TRUE"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		Store:           store,
		RootDN:          "cn=admin,dc=example,dc=com",
		RootPassword:    []byte("admin-secret"),
		ShutdownTimeout: time.Second,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})

	connection := dialAndBindRawLDAP(
		t,
		listener.Addr().String(),
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("gentle-transaction")
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(entry),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	if !instance.BeginGentleShutdown(listener) {
		connection.Close()
		t.Fatal("BeginGentleShutdown() did not start")
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, true, identifier),
		int64(ldapwire.ResultUnwillingToPerform),
	)
	if transactionEntryExists(t, store, entry.DN) {
		connection.Close()
		t.Fatal("rejected gentle transaction commit wrote its entry")
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
	connection.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() after transaction client close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not finish after transaction client close")
	}
}
