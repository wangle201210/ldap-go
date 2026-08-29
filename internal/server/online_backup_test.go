//go:build !windows

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPIOnlineBackupCreatesRestorableSnapshot(t *testing.T) {
	root := shortOnlineBackupRoot(t)
	databasePath := filepath.Join(root, "directory.db")
	backupDirectory := filepath.Join(root, "backups")
	if err := os.Mkdir(backupDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenBolt(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	listener, uri := listenOnlineBackupLDAPI(t, root)
	instance, err := New(Config{
		Store:           store,
		ListenerURLs:    []string{uri},
		RootDN:          "cn=admin,dc=example,dc=com",
		RootPassword:    []byte("secret"),
		OnlineBackupDir: backupDirectory,
		OnlineBackup: func(ctx context.Context, path string) (storage.CheckReport, error) {
			return store.Backup(ctx, path, false)
		},
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
		<-done
	})
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedExtension"}, nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 || !containsString(
		rootDSE.Entries[0].GetAttributeValues("supportedExtension"),
		onlineBackupOID,
	) {
		t.Fatalf("online backup Root DSE = %#v, %v", rootDSE, err)
	}
	response, err := client.Extended(ldap.NewExtendedRequest(onlineBackupOID, nil))
	if err != nil || response.Value == nil {
		t.Fatalf("online backup response = %#v, %v", response, err)
	}
	var report OnlineBackupReport
	if err := json.Unmarshal(response.Value.Data.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Filename == "" || strings.ContainsAny(report.Filename, `/\\`) ||
		report.Entries == 0 || report.FileSize == 0 {
		t.Fatalf("online backup report = %#v", report)
	}
	backupPath := filepath.Join(backupDirectory, report.Filename)
	if checked, err := storage.CheckBolt(t.Context(), backupPath); err != nil ||
		checked.Entries != report.Entries || checked.FileSize != report.FileSize {
		t.Fatalf("CheckBolt() = %#v, %v; report=%#v", checked, err, report)
	}
	if info, err := os.Stat(backupPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %#v, %v", info, err)
	}
	restored := filepath.Join(root, "restored.db")
	if _, err := storage.RestoreBolt(t.Context(), backupPath, restored, false); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.CheckBolt(t.Context(), restored); err != nil {
		t.Fatal(err)
	}
}

func TestOnlineBackupAuthorizationAndRequestValidation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	backupDirectory := t.TempDir()
	callback := func(context.Context, string) (storage.CheckReport, error) {
		return storage.CheckReport{}, nil
	}
	address, stop := startServer(t, store, Config{
		RootDN:          "cn=admin,dc=example,dc=com",
		RootPassword:    []byte("secret"),
		OnlineBackupDir: backupDirectory,
		OnlineBackup:    callback,
	})
	t.Cleanup(stop)
	tcpRoot, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpRoot.Close()
	if err := tcpRoot.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	_, err = tcpRoot.Extended(ldap.NewExtendedRequest(onlineBackupOID, nil))
	assertOnlineBackupLDAPCode(t, err, ldap.LDAPResultConfidentialityRequired)

	root := shortOnlineBackupRoot(t)
	listener, uri := listenOnlineBackupLDAPI(t, root)
	instance, err := New(Config{
		Store:           store,
		ListenerURLs:    []string{uri},
		RootDN:          "cn=admin,dc=example,dc=com",
		RootPassword:    []byte("secret"),
		OnlineBackupDir: backupDirectory,
		OnlineBackup:    callback,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); <-done })
	anonymous, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer anonymous.Close()
	_, err = anonymous.Extended(ldap.NewExtendedRequest(onlineBackupOID, nil))
	assertOnlineBackupLDAPCode(t, err, ldap.LDAPResultInsufficientAccessRights)
	rootClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer rootClient.Close()
	if err := rootClient.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	emptyValue := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "requestValue")
	_, err = rootClient.Extended(ldap.NewExtendedRequest(onlineBackupOID, emptyValue))
	assertOnlineBackupLDAPCode(t, err, ldap.LDAPResultProtocolError)
}

func TestOnlineBackupRejectsConcurrentInvocation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	root := shortOnlineBackupRoot(t)
	listener, uri := listenOnlineBackupLDAPI(t, root)
	entered := make(chan struct{})
	release := make(chan struct{})
	released := false
	instance, err := New(Config{
		Store:           store,
		ListenerURLs:    []string{uri},
		RootDN:          "cn=admin,dc=example,dc=com",
		RootPassword:    []byte("secret"),
		OnlineBackupDir: root,
		OnlineBackup: func(ctx context.Context, _ string) (storage.CheckReport, error) {
			select {
			case entered <- struct{}{}:
			case <-ctx.Done():
				return storage.CheckReport{}, ctx.Err()
			}
			select {
			case <-release:
				return storage.CheckReport{Entries: 1, FileSize: 1}, nil
			case <-ctx.Done():
				return storage.CheckReport{}, ctx.Err()
			}
		},
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		if !released {
			close(release)
		}
		cancel()
		<-done
	})
	clients := make([]*ldap.Conn, 2)
	for index := range clients {
		client, err := ldap.DialURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
			client.Close()
			t.Fatal(err)
		}
		clients[index] = client
		defer client.Close()
	}
	first := make(chan error, 1)
	go func() {
		_, err := clients[0].Extended(ldap.NewExtendedRequest(onlineBackupOID, nil))
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first online backup did not enter callback")
	}
	_, err = clients[1].Extended(ldap.NewExtendedRequest(onlineBackupOID, nil))
	assertOnlineBackupLDAPCode(t, err, ldap.LDAPResultBusy)
	close(release)
	released = true
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestOnlineBackupConfigurationMustBeComplete(t *testing.T) {
	for _, config := range []Config{
		{OnlineBackupDir: "/tmp/backups"},
		{OnlineBackup: func(context.Context, string) (storage.CheckReport, error) {
			return storage.CheckReport{}, nil
		}},
		{OnlineBackupDir: "relative", OnlineBackup: func(context.Context, string) (storage.CheckReport, error) {
			return storage.CheckReport{}, nil
		}},
	} {
		store := storage.NewMemory()
		config.Store = store
		if _, err := New(config); err == nil {
			store.Close()
			t.Fatalf("incomplete online backup config was accepted: %#v", config)
		}
		store.Close()
	}
	store := storage.NewMemory()
	defer store.Close()
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	root := instance.rootDSE(&connectionState{runtime: instance.runtime.Load()})
	if containsString(byteValuesToStrings(root.Values("supportedExtension")), onlineBackupOID) {
		t.Fatal("unconfigured online backup extension was advertised")
	}
}

func listenOnlineBackupLDAPI(t *testing.T, root string) (net.Listener, string) {
	t.Helper()
	path := filepath.Join(root, "ldapi")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener, "ldapi://" + url.PathEscape(path) + "/"
}

func shortOnlineBackupRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ldap-go-online-backup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func assertOnlineBackupLDAPCode(t *testing.T, err error, code uint16) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != code {
		t.Fatalf("LDAP error = %v, want code %d", err, code)
	}
}
