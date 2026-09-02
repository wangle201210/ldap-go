package server

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPLogLevelStartupOnlineRollbackAndDelete(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	setStoredOpenLDAPLogLevels(t, store, "ACL")
	captured := &capturedMonitorLogState{}
	instance, address, stop := startMonitorLogRoutingServer(
		t, store, slog.New(capturedMonitorLogHandler{state: captured}),
	)
	defer stop()

	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Debug("closing malformed LDAP connection")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message: "SASL auxiliary credential lookup failed", category: "ACL",
	}})

	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	captured.reset()
	replace := ldap.NewModifyRequest("cn=config", nil)
	replace.Replace("olcLogLevel", []string{"BER SYNC"})
	if err := client.Modify(replace); err != nil {
		t.Fatalf("replace olcLogLevel: %v", err)
	}
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Debug("closing malformed LDAP connection")
	instance.config.Logger.Debug("syncrepl consumer will retry")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{
		{message: "closing malformed LDAP connection", category: "BER"},
		{message: "syncrepl consumer will retry", category: "SYNC"},
	})

	captured.reset()
	invalid := ldap.NewModifyRequest("cn=config", nil)
	invalid.Replace("olcLogLevel", []string{"not-a-log-level"})
	if code := ldapOperationResultCode(client.Modify(invalid)); code != ldap.LDAPResultOther {
		t.Fatalf("invalid olcLogLevel result = %d, want %d", code, ldap.LDAPResultOther)
	}
	if got := readConfiguredLogLevels(t, client); !slices.Equal(got, []string{"BER SYNC"}) {
		t.Fatalf("persisted olcLogLevel after rollback = %q", got)
	}
	instance.config.Logger.Debug("closing malformed LDAP connection")
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message: "closing malformed LDAP connection", category: "BER",
	}})

	captured.reset()
	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcLogLevel", nil)
	if err := client.Modify(remove); err != nil {
		t.Fatalf("delete olcLogLevel: %v", err)
	}
	instance.config.Logger.Debug("closing malformed LDAP connection")
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{
		{message: "closing malformed LDAP connection"},
		{message: "SASL auxiliary credential lookup failed"},
	})
}

func TestLoadOpenLDAPLogLevels(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	setStoredOpenLDAPLogLevels(t, store, "stats sync", "0x10")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		levels, configured, err := loadOpenLDAPLogLevels(reader)
		if err != nil || !configured || !slices.Equal(levels, []string{"stats", "sync", "0x10"}) {
			t.Fatalf("loadOpenLDAPLogLevels() = %q, %v, %v", levels, configured, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	setStoredOpenLDAPLogLevels(t, store, "invalid")
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, _, err := loadOpenLDAPLogLevels(reader)
		if err == nil {
			t.Fatal("invalid olcLogLevel was accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenLDAPReferenceGlobalLogLevelConfiguration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI := startOpenLDAPDynamicConfigReferralServer(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	reference := observeOpenLDAPLogLevelConfiguration(t, referenceURI)
	implementation := observeOpenLDAPLogLevelConfiguration(t, "ldap://"+address)
	if !reflect.DeepEqual(implementation, reference) {
		t.Fatalf("olcLogLevel:\nldap-go:  %#v\nOpenLDAP: %#v", implementation, reference)
	}
}

type openLDAPLogLevelOutcome struct {
	NamedCode    uint16
	NamedValues  []string
	NumericCode  uint16
	Numeric      []string
	InvalidCode  uint16
	AfterInvalid []string
	DeleteCode   uint16
	AfterDelete  []string
}

func observeOpenLDAPLogLevelConfiguration(
	t *testing.T,
	uri string,
) openLDAPLogLevelOutcome {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	modify := func(values ...string) uint16 {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcLogLevel", values)
		return ldapOperationResultCode(client.Modify(request))
	}
	outcome := openLDAPLogLevelOutcome{}
	outcome.NamedCode = modify("ACL SYNC")
	outcome.NamedValues = readConfiguredLogLevels(t, client)
	outcome.NumericCode = modify("0x10")
	outcome.Numeric = readConfiguredLogLevels(t, client)
	outcome.InvalidCode = modify("not-a-log-level")
	outcome.AfterInvalid = readConfiguredLogLevels(t, client)
	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcLogLevel", nil)
	outcome.DeleteCode = ldapOperationResultCode(client.Modify(remove))
	outcome.AfterDelete = readConfiguredLogLevels(t, client)
	return outcome
}

func ldapOperationResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode
	}
	return ldap.LDAPResultOther
}

func setStoredOpenLDAPLogLevels(t *testing.T, store storage.Store, values ...string) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLogLevel", stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
}

func readConfiguredLogLevels(t *testing.T, client *ldap.Conn) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"olcLogLevel"}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read olcLogLevel = %#v, %v", result, err)
	}
	return result.Entries[0].GetAttributeValues("olcLogLevel")
}
