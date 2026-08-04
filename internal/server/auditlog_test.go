package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRenderAuditlogRecordMatchesOpenLDAPLDIFShape(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	record := auditlogPendingRecord{
		operation:       accesslogModify,
		suffix:          "dc=example,dc=com",
		authorizationDN: "uid=proxy,dc=example,dc=com",
		realDN:          "cn=admin,dc=example,dc=com",
		peerName:        "IP=127.0.0.1:12345",
		connectionID:    7,
		requestDN:       "uid=alice,dc=example,dc=com",
		registry:        registry,
		modifications: []ldapwire.Modification{
			{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "cn",
					Values:      [][]byte{[]byte(" Leading")},
				},
			},
			{
				Operation: ldapwire.ModificationDelete,
				Attribute: directory.Attribute{Description: "description"},
			},
			{
				Operation: ldapwire.ModificationIncrement,
				Attribute: directory.Attribute{
					Description: "uidNumber",
					Values:      [][]byte{[]byte("2")},
				},
			},
			{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "userPassword",
					Values:      [][]byte{[]byte("{SM3}digest")},
				},
			},
		},
	}

	want := "# modify 123 dc=example,dc=com uid=proxy,dc=example,dc=com " +
		"IP=127.0.0.1:12345 conn=7\n" +
		"# realdn: cn=admin,dc=example,dc=com\n" +
		"dn: uid=alice,dc=example,dc=com\n" +
		"changetype: modify\n" +
		"replace: cn\n" +
		"cn:: IExlYWRpbmc=\n" +
		"-\n" +
		"delete: description\n" +
		"-\n" +
		"increment: uidNumber\n" +
		"uidNumber: 2\n" +
		"-\n" +
		"replace: userPassword\n" +
		"userPassword:: e1NNM31kaWdlc3Q=\n" +
		"-\n" +
		"# end modify 123\n\n"
	if got := string(renderAuditlogRecord(record, 123)); got != want {
		t.Fatalf("auditlog record:\n%s\nwant:\n%s", got, want)
	}
}

func TestAuditlogLDIFValueFoldingAndBinaryEncoding(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	value := []byte(strings.Repeat("x", 160))
	writeAuditlogLDIFValue(&output, "description", value)
	for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		if len(line) > auditlogLDIFLineWidth {
			t.Fatalf("folded line length = %d, want <= %d: %q", len(line), auditlogLDIFLineWidth, line)
		}
	}

	output.Reset()
	writeAuditlogLDIFValue(&output, "jpegPhoto", []byte{0x00, 0xff, 0x10})
	want := "jpegPhoto:: " + base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x10}) + "\n"
	if got := output.String(); got != want {
		t.Fatalf("binary LDIF = %q, want %q", got, want)
	}
}

func TestAuditlogOverlayRecordsCommittedWritesOnly(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	filename := filepath.Join(t.TempDir(), "audit.ldif")
	seedAuditlogOverlay(t, store, filename)

	const (
		rootDN       = "cn=admin,dc=example,dc=com"
		rootPassword = "admin-secret"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
	})
	defer stop()
	client := dialAuditlogClient(t, address, rootDN, rootPassword)
	defer client.Close()

	noOp := newPersonAddRequest("audit-noop")
	noOp.Controls = []ldap.Control{ldap.NewControlString(noOpControlOID, true, "")}
	assertLDAPResultCode(t, client.Add(noOp), uint16(ldapwire.ResultNoOperation))
	if _, err := os.Stat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("No-Op auditlog file error = %v, want not-exist", err)
	}

	add := newAccesslogPersonAddRequest("audit-user")
	if err := client.Add(add); err != nil {
		t.Fatalf("Add(): %v", err)
	}
	if err := client.Add(add); err == nil {
		t.Fatal("duplicate Add succeeded")
	}

	dn := add.DN
	modify := ldap.NewModifyRequest(dn, nil)
	modify.Replace("cn", []string{"Audit Updated"})
	modify.Add("description", []string{"first", "second"})
	modify.Delete("description", []string{"first"})
	modify.Increment("uidNumber", "5")
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(): %v", err)
	}
	if _, err := client.PasswordModify(
		ldap.NewPasswordModifyRequest(dn, "", "audit-secret"),
	); err != nil {
		t.Fatalf("PasswordModify(): %v", err)
	}

	renamedDN := "uid=audit-renamed,ou=archive,dc=example,dc=com"
	if err := client.ModifyDN(ldap.NewModifyDNRequest(
		dn,
		"uid=audit-renamed",
		true,
		"ou=archive,dc=example,dc=com",
	)); err != nil {
		t.Fatalf("ModifyDN(): %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("Delete(): %v", err)
	}

	log := readAuditlogFile(t, filename)
	if got := strings.Count(log, "\nchangetype: "); got != 5 {
		t.Fatalf("auditlog record count = %d, want 5:\n%s", got, log)
	}
	for _, fragment := range []string{
		"changetype: add\n",
		"objectClass: inetOrgPerson\n",
		"changetype: modify\nreplace: cn\ncn: Audit Updated\n-\n",
		"increment: uidNumber\nuidNumber: 5\n-\n",
		"replace: entryCSN\nentryCSN: ",
		"replace: modifiersName\nmodifiersName: " + rootDN + "\n-\n",
		"replace: modifyTimestamp\nmodifyTimestamp: ",
		"replace: userPassword\nuserPassword:: ",
		"changetype: modrdn\nnewrdn: uid=audit-renamed\ndeleteoldrdn: 1\n" +
			"newsuperior: ou=archive,dc=example,dc=com\n",
		"dn: " + renamedDN + "\nchangetype: delete\n",
	} {
		if !strings.Contains(log, fragment) {
			t.Fatalf("auditlog missing %q:\n%s", fragment, log)
		}
	}
	if strings.Contains(log, "audit-secret") {
		t.Fatal("Password Modify cleartext leaked to auditlog")
	}
}

func TestAuditlogOverlayLDAPTransactions(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	filename := filepath.Join(t.TempDir(), "audit.ldif")
	seedAuditlogOverlay(t, store, filename)

	const (
		rootDN       = "cn=admin,dc=example,dc=com"
		rootPassword = "admin-secret"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
	})
	defer stop()
	connection := dialAndBindRawLDAP(t, address, rootDN, rootPassword)
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("audit-committed")
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(entry),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		4,
		rawModifyReplaceRequest(entry.DN, "cn", "Audit Committed"),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	if _, err := os.Stat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted auditlog file error = %v, want not-exist", err)
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, true, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if got := auditlogRecordCount(t, filename); got != 2 {
		t.Fatalf("committed auditlog records = %d, want 2", got)
	}

	identifier = startRawLDAPTransaction(t, connection, 6)
	aborted := transactionTestPerson("audit-aborted")
	assertRawLDAPResult(t, sendRawLDAPOperation(
		t,
		connection,
		7,
		rawAddRequest(aborted),
		rawTransactionSpecificationControl(identifier, true, true),
	), int64(ldapwire.ResultSuccess))
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 8, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if got := auditlogRecordCount(t, filename); got != 2 {
		t.Fatalf("records after abort = %d, want 2", got)
	}

	identifier = startRawLDAPTransaction(t, connection, 9)
	duplicate := transactionTestPerson("audit-rollback")
	for _, messageID := range []int64{10, 11} {
		assertRawLDAPResult(t, sendRawLDAPOperation(
			t,
			connection,
			messageID,
			rawAddRequest(duplicate),
			rawTransactionSpecificationControl(identifier, true, true),
		), int64(ldapwire.ResultSuccess))
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 12, true, identifier),
		int64(ldapwire.ResultEntryAlreadyExists),
	)
	if got := auditlogRecordCount(t, filename); got != 3 {
		t.Fatalf("records after rollback = %d, want OpenLDAP-compatible 3", got)
	}
}

func TestAuditlogFrontendAndDatabaseOverlaysBothRecord(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	root := t.TempDir()
	databaseFilename := filepath.Join(root, "database.ldif")
	frontendFilename := filepath.Join(root, "frontend.ldif")
	seedAuditlogOverlay(t, store, databaseFilename)
	seedFrontendAuditlogOverlay(t, store, frontendFilename)

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newPersonAddRequest("audit-global-and-local")); err != nil {
		t.Fatalf("Add() with frontend and database auditlog: %v", err)
	}
	if got := auditlogRecordCount(t, databaseFilename); got != 1 {
		t.Fatalf("database auditlog records = %d, want 1", got)
	}
	if got := auditlogRecordCount(t, frontendFilename); got != 1 {
		t.Fatalf("frontend auditlog records = %d, want 1", got)
	}
}

func TestAuditlogOverlayOnlineLifecycleRotationAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	root := t.TempDir()
	firstFilename := filepath.Join(root, "first.ldif")
	secondFilename := filepath.Join(root, "second.ldif")
	rotatedFilename := filepath.Join(root, "second.ldif.rotated")
	config := Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	}
	address, stop := startServer(t, store, config)
	configClient := bindUniqueClient(t, address, "cn=config", "config-secret")
	dataClient := dialLDAPRoot(t, address)

	const overlayDN = "olcOverlay={0}auditlog,olcDatabase={1}mdb,cn=config"
	overlay := ldap.NewAddRequest(overlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcAuditlogConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}auditlog"})
	overlay.Attribute("olcAuditlogFile", []string{firstFilename})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("add online auditlog overlay: %v", err)
	}

	duplicate := ldap.NewAddRequest(
		"olcOverlay={1}auditlog,olcDatabase={1}mdb,cn=config",
		nil,
	)
	duplicate.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcAuditlogConfig"},
	)
	duplicate.Attribute("olcOverlay", []string{"{1}auditlog"})
	duplicate.Attribute("olcAuditlogFile", []string{secondFilename})
	assertLDAPResultCode(
		t,
		configClient.Add(duplicate),
		ldap.LDAPResultConstraintViolation,
	)

	if err := dataClient.Add(newPersonAddRequest("audit-online-one")); err != nil {
		t.Fatalf("add with online auditlog: %v", err)
	}
	if got := auditlogRecordCount(t, firstFilename); got != 1 {
		t.Fatalf("first online auditlog records = %d, want 1", got)
	}

	invalid := ldap.NewModifyRequest(overlayDN, nil)
	invalid.Replace(
		"olcAuditlogFile",
		[]string{secondFilename, filepath.Join(root, "third.ldif")},
	)
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	configured := readStoredEntry(t, store, overlayDN).Values("olcAuditlogFile")
	if len(configured) != 1 || string(configured[0]) != firstFilename {
		t.Fatalf("auditlog config after rollback = %q, want %q", configured, firstFilename)
	}
	if err := dataClient.Add(newPersonAddRequest("audit-online-two")); err != nil {
		t.Fatalf("add after auditlog config rollback: %v", err)
	}
	if got := auditlogRecordCount(t, firstFilename); got != 2 {
		t.Fatalf("first auditlog records after rollback = %d, want 2", got)
	}

	reconfigure := ldap.NewModifyRequest(overlayDN, nil)
	reconfigure.Replace("olcAuditlogFile", []string{secondFilename})
	if err := configClient.Modify(reconfigure); err != nil {
		t.Fatalf("reconfigure online auditlog: %v", err)
	}
	if err := dataClient.Add(newPersonAddRequest("audit-online-three")); err != nil {
		t.Fatalf("add after auditlog reconfiguration: %v", err)
	}
	if got := auditlogRecordCount(t, secondFilename); got != 1 {
		t.Fatalf("second online auditlog records = %d, want 1", got)
	}

	if err := os.Rename(secondFilename, rotatedFilename); err != nil {
		t.Fatalf("rotate online auditlog: %v", err)
	}
	if err := dataClient.Add(newPersonAddRequest("audit-online-four")); err != nil {
		t.Fatalf("add after external auditlog rotation: %v", err)
	}
	if got := auditlogRecordCount(t, rotatedFilename); got != 1 {
		t.Fatalf("rotated auditlog records = %d, want 1", got)
	}
	if got := auditlogRecordCount(t, secondFilename); got != 1 {
		t.Fatalf("reopened auditlog records = %d, want 1", got)
	}

	if err := configClient.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("delete online auditlog overlay: %v", err)
	}
	if err := dataClient.Add(newPersonAddRequest("audit-online-five")); err != nil {
		t.Fatalf("add after disabling auditlog: %v", err)
	}
	if got := auditlogRecordCount(t, secondFilename); got != 1 {
		t.Fatalf("auditlog records after disable = %d, want 1", got)
	}
	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = dialLDAPRoot(t, address)
	defer dataClient.Close()
	if err := dataClient.Add(newPersonAddRequest("audit-online-six")); err != nil {
		t.Fatalf("add after disabled auditlog restart: %v", err)
	}
	if got := auditlogRecordCount(t, secondFilename); got != 1 {
		t.Fatalf("auditlog records after disabled restart = %d, want 1", got)
	}
}

func TestAuditlogFileFailureDoesNotFailLDAPWrite(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	filename := filepath.Join(t.TempDir(), "missing", "audit.ldif")
	seedAuditlogOverlay(t, store, filename)
	var logs bytes.Buffer
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
		Logger: slog.New(slog.NewTextHandler(
			&logs,
			nil,
		)),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()

	const uid = "audit-file-failure"
	if err := client.Add(newPersonAddRequest(uid)); err != nil {
		t.Fatalf("Add() with unavailable auditlog file: %v", err)
	}
	readStoredEntry(
		t,
		store,
		"uid="+uid+",ou=people,dc=example,dc=com",
	)
	if _, err := os.Stat(filename); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unavailable auditlog file error = %v, want not-exist", err)
	}
	if !strings.Contains(logs.String(), "write OpenLDAP auditlog record") {
		t.Fatalf("auditlog file failure was not logged: %s", logs.String())
	}
}

func TestAuditlogConcurrentAppendsRemainComplete(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	filename := filepath.Join(t.TempDir(), "audit.ldif")
	seedAuditlogOverlay(t, store, filename)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	const writes = 24
	errors := make(chan error, writes)
	var wait sync.WaitGroup
	for index := 0; index < writes; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				errors <- err
				return
			}
			defer client.Close()
			if err := client.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
				errors <- err
				return
			}
			uid := fmt.Sprintf("audit-concurrent-%02d", index)
			if err := client.Add(newPersonAddRequest(uid)); err != nil {
				errors <- err
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent auditlog Add(): %v", err)
		}
	}

	records, err := parseAuditlogReferenceRecords(readAuditlogFile(t, filename))
	if err != nil {
		t.Fatalf("parse concurrent auditlog: %v", err)
	}
	if len(records) != writes {
		t.Fatalf("concurrent auditlog records = %d, want %d", len(records), writes)
	}
	seen := make(map[string]struct{}, writes)
	for _, record := range records {
		if record.operation != "add" || !record.hasEnd {
			t.Fatalf("incomplete concurrent auditlog record = %#v", record)
		}
		seen[record.targetDN] = struct{}{}
	}
	if len(seen) != writes {
		t.Fatalf("unique concurrent auditlog targets = %d, want %d", len(seen), writes)
	}
}

func TestAuditlogRuntimeConfigurationValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		values   []string
		wantFile string
		wantErr  string
	}{
		{name: "optional"},
		{name: "filename", values: []string{"/tmp/audit.ldif"}, wantFile: "/tmp/audit.ldif"},
		{name: "duplicate", values: []string{"one", "two"}, wantErr: "single-valued"},
		{name: "empty", values: []string{""}, wantErr: "invalid filename"},
		{name: "NUL", values: []string{"bad\x00name"}, wantErr: "invalid filename"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := directory.Entry{DN: "olcOverlay=auditlog,cn=config"}
			entry.ReplaceValues("olcAuditlogFile", stringValues(test.values...))
			configuration, err := loadAuditlogRuntimeConfiguration(entry)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || configuration.filename != test.wantFile {
				t.Fatalf("configuration = %#v, error = %v", configuration, err)
			}
		})
	}
}

func seedAuditlogOverlay(t *testing.T, store storage.Store, filename string) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcOverlay={0}auditlog,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcAuditlogConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}auditlog")},
			{Description: "olcAuditlogFile", Values: stringValues(filename)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed auditlog overlay: %v", err)
	}
}

func seedFrontendAuditlogOverlay(
	t *testing.T,
	store storage.Store,
	filename string,
) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		},
		{
			DN: "olcOverlay={0}auditlog,olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcAuditlogConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}auditlog")},
				{Description: "olcAuditlogFile", Values: stringValues(filename)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed frontend auditlog overlay: %v", err)
	}
}

func dialAuditlogClient(t *testing.T, address, bindDN, password string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(bindDN, password); err != nil {
		client.Close()
		t.Fatalf("Bind(): %v", err)
	}
	return client
}

func readAuditlogFile(t *testing.T, filename string) string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", filename, err)
	}
	return string(data)
}

func auditlogRecordCount(t *testing.T, filename string) int {
	t.Helper()
	return strings.Count(readAuditlogFile(t, filename), "\nchangetype: ")
}
