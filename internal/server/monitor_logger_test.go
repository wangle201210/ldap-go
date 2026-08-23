package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type capturedMonitorLogRecord struct {
	message  string
	category string
}

type capturedMonitorLogState struct {
	mu      sync.Mutex
	records []capturedMonitorLogRecord
}

type capturedMonitorLogHandler struct {
	state *capturedMonitorLogState
}

func (handler capturedMonitorLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (handler capturedMonitorLogHandler) Handle(_ context.Context, record slog.Record) error {
	captured := capturedMonitorLogRecord{message: record.Message}
	record.Attrs(func(attribute slog.Attr) bool {
		if attribute.Key == "openldap_category" {
			captured.category = attribute.Value.String()
		}
		return true
	})
	handler.state.mu.Lock()
	handler.state.records = append(handler.state.records, captured)
	handler.state.mu.Unlock()
	return nil
}

func (handler capturedMonitorLogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return handler
}

func (handler capturedMonitorLogHandler) WithGroup(string) slog.Handler {
	return handler
}

func (state *capturedMonitorLogState) reset() {
	state.mu.Lock()
	state.records = nil
	state.mu.Unlock()
}

func (state *capturedMonitorLogState) snapshot() []capturedMonitorLogRecord {
	state.mu.Lock()
	defer state.mu.Unlock()
	return append([]capturedMonitorLogRecord(nil), state.records...)
}

func TestMonitorLogLevelRoutesStructuredEventsImmediately(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedMonitorLogRoutingConfiguration(t, store)

	captured := &capturedMonitorLogState{}
	instance, address, stop := startMonitorLogRoutingServer(
		t,
		store,
		slog.New(capturedMonitorLogHandler{state: captured}),
	)
	defer stop()

	monitorClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(monitor): %v", err)
	}
	defer monitorClient.Close()
	if err := monitorClient.Bind("cn=admin,cn=Monitor", "monitor-secret"); err != nil {
		t.Fatalf("monitor Bind(): %v", err)
	}

	instance.config.Logger.Error("SASL auxiliary credential lookup failed")
	if records := captured.snapshot(); len(records) != 0 {
		t.Fatalf("initial monitorLogLevel=0 records = %#v", records)
	}

	replaceMonitorLogLevel(t, monitorClient, "ACL")
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Debug("closing malformed LDAP connection")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message:  "SASL auxiliary credential lookup failed",
		category: "ACL",
	}})

	captured.reset()
	unmanaged := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	unmanaged.Replace("description", []string{"must roll back"})
	assertMonitorLogLDAPResultCode(
		t,
		monitorClient.Modify(unmanaged),
		ldap.LDAPResultUnwillingToPerform,
	)
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Debug("closing malformed LDAP connection")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message:  "SASL auxiliary credential lookup failed",
		category: "ACL",
	}})

	captured.reset()
	replaceMonitorLogLevel(t, monitorClient, "not-a-level")
	instance.config.Logger.Error("SASL auxiliary credential lookup failed")
	instance.config.Logger.Error("unclassified structured event")
	if records := captured.snapshot(); len(records) != 0 {
		t.Fatalf("unknown monitorLogLevel routed records = %#v", records)
	}

	replaceMonitorLogLevel(t, monitorClient, "16")
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Debug("closing malformed LDAP connection")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message:  "closing malformed LDAP connection",
		category: "BER",
	}})

	captured.reset()
	replaceMonitorLogLevel(t, monitorClient, "Any")
	instance.config.Logger.Debug("closing malformed LDAP connection")
	instance.config.Logger.Error("unclassified structured event")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{
		{message: "closing malformed LDAP connection", category: "BER"},
		{message: "unclassified structured event", category: "ANY"},
	})

	captured.reset()
	replaceMonitorLogLevel(t, monitorClient, "None")
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Error("unclassified structured event")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message:  "unclassified structured event",
		category: "ANY",
	}})
}

func TestMonitorLogLevelConcurrentOnlineRouting(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedMonitorLogRoutingConfiguration(t, store)

	captured := &capturedMonitorLogState{}
	instance, address, stop := startMonitorLogRoutingServer(
		t,
		store,
		slog.New(capturedMonitorLogHandler{state: captured}),
	)
	defer stop()

	monitorClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(monitor): %v", err)
	}
	defer monitorClient.Close()
	if err := monitorClient.Bind("cn=admin,cn=Monitor", "monitor-secret"); err != nil {
		t.Fatalf("monitor Bind(): %v", err)
	}

	done := make(chan struct{})
	var writers sync.WaitGroup
	for index := 0; index < 8; index++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for {
				select {
				case <-done:
					return
				default:
					instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
					instance.config.Logger.Debug("closing malformed LDAP connection")
				}
			}
		}()
	}
	for index := 0; index < 100; index++ {
		level := "ACL"
		if index%2 != 0 {
			level = "BER"
		}
		replaceMonitorLogLevel(t, monitorClient, level)
	}
	close(done)
	writers.Wait()

	captured.reset()
	replaceMonitorLogLevel(t, monitorClient, "Sync")
	instance.config.Logger.Debug("SASL auxiliary credential lookup failed")
	instance.config.Logger.Debug("syncrepl consumer will retry")
	assertCapturedMonitorLogs(t, captured.snapshot(), []capturedMonitorLogRecord{{
		message:  "syncrepl consumer will retry",
		category: "SYNC",
	}})
}

func TestCompileMonitorLogMaskMatchesOpenLDAPValues(t *testing.T) {
	if got := compileMonitorLogMask([]string{
		"Trace", "PACKETS", "args", "Conns", "BER", "Filter", "Config",
		"ACL", "Stats", "Stats2", "Shell", "Parse", "Sync", "None",
	}); got != 0xcfff {
		t.Fatalf("compiled named monitor log mask = %#x, want %#x", got, monitorLogCategory(0xcfff))
	}
	if got := compileMonitorLogMask([]string{"-1"}); got != monitorLogAny {
		t.Fatalf("compiled Any numeric mask = %#x", got)
	}
	for _, value := range []string{"0xffffffff", "4294967295"} {
		if got := compileMonitorLogMask([]string{value}); got != monitorLogAny {
			t.Fatalf("compiled Any numeric mask %q = %#x", value, got)
		}
	}
	if got := compileMonitorLogMask([]string{"0", "unknown"}); got != 0 {
		t.Fatalf("compiled disabled/unknown mask = %#x", got)
	}
	if got := compileMonitorLogMask([]string{"0x10", "256"}); got != monitorLogBER|monitorLogStats {
		t.Fatalf("compiled numeric mask = %#x", got)
	}
}

func TestMonitorLogEventCategoryMapsExistingStructuredEvents(t *testing.T) {
	tests := []struct {
		category monitorLogCategory
		label    string
		messages []string
	}{
		{monitorLogConns, "CONNS", []string{
			"TLS handshake failed",
			"secure transport returned a nil connection",
			"LDAP Cancel request failed",
			"LDAP request failed",
		}},
		{monitorLogBER, "BER", []string{"closing malformed LDAP connection"}},
		{monitorLogConfig, "CONFIG", []string{
			"AutoCA entry issuance skipped",
			"AutoCA Search preparation failed",
			"close SQL backend",
		}},
		{monitorLogACL, "ACL", []string{
			"SASL auxiliary credential lookup failed",
			"SASL GSSAPI AP-REQ rejected",
			"SASL GSSAPI security selection rejected",
			"external password verification failed",
			"load remoteauth entry",
			"resolve remoteauth realm",
			"remoteauth provider failed",
			"remoteauth password hashing failed; storing cleartext for OpenLDAP compatibility",
			"store remoteauth password",
			"pbind provider failed",
			"OTP state transaction failed",
			"TOTP authentication state update failed",
			"TOTP root authentication state update failed",
			"forward password policy state update failed",
		}},
		{monitorLogStats, "STATS", []string{
			"write LDAP audit event",
			"write OpenLDAP auditlog record",
			"write accesslog operation",
			"accesslog purge failed",
			"LDAP dynamic refresh failed",
			"DDS expiration failed",
			"LDAP operation failed",
			"LDAP transaction operation preparation failed",
			"LDAP transaction operation accounting failed",
			"LDAP transaction seqmod acquisition failed",
			"LDAP transaction external password verification failed",
			"LDAP transaction failed",
			"rejecting delegated search with unverifiable candidate limit",
		}},
		{monitorLogShell, "SHELL", []string{
			"back-sock request encoding failed",
			"back-sock request write failed",
			"back-sock response parsing failed",
			"socket overlay response callback failed closed",
			"homedir overlay filesystem operation failed",
		}},
		{monitorLogSync, "SYNC", []string{
			"syncrepl consumer stopped after retry policy was exhausted",
			"syncrepl consumer will retry",
			"syncrepl StartTLS was rejected; continuing without TLS",
		}},
	}
	for _, test := range tests {
		for _, message := range test.messages {
			category, label := monitorLogEventCategory(message)
			if category != test.category || label != test.label {
				t.Errorf(
					"category for %q = %#x/%q, want %#x/%q",
					message,
					category,
					label,
					test.category,
					test.label,
				)
			}
		}
	}
	if category, label := monitorLogEventCategory("future structured event"); category != monitorLogAny || label != "ANY" {
		t.Fatalf("fallback category = %#x/%q, want ANY", category, label)
	}
}

func replaceMonitorLogLevel(t *testing.T, client *ldap.Conn, values ...string) {
	t.Helper()
	request := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	request.Replace("monitorLogLevel", values)
	if err := client.Modify(request); err != nil {
		t.Fatalf("replace monitorLogLevel with %v: %v", values, err)
	}
}

func seedMonitorLogRoutingConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={0}monitor,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcMonitorConfig")},
			{Description: "olcDatabase", Values: stringValues("{0}monitor")},
			{Description: "olcRootDN", Values: stringValues("cn=admin,cn=Monitor")},
			{Description: "olcRootPW", Values: stringValues("monitor-secret")},
			{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed monitor log routing configuration: %v", err)
	}
}

func assertMonitorLogLDAPResultCode(t *testing.T, err error, want uint16) {
	t.Helper()
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}

func assertCapturedMonitorLogs(
	t *testing.T,
	got, want []capturedMonitorLogRecord,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("captured logs = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("captured logs = %#v, want %#v", got, want)
		}
	}
}

func startMonitorLogRoutingServer(
	t *testing.T,
	store storage.Store,
	logger *slog.Logger,
) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := New(Config{Store: store, Logger: logger})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	return instance, listener.Addr().String(), func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
}
