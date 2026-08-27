package server

import (
	"context"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadLocalSSFSignedCompatibility(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcLocalSSF",
				Values:      stringValues("-1"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	var got uint32
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		got, err = loadLocalSSF(reader)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got != math.MaxUint32 {
		t.Fatalf("olcLocalSSF -1 = %d, want %d", got, uint32(math.MaxUint32))
	}
}

func TestLocalSSFExistingConnectionSnapshot(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcLocalSSF", Values: stringValues("128")},
				{Description: "olcSecurity", Values: stringValues("transport=70")},
			},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}

	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	socketRoot, err := os.MkdirTemp("/tmp", "ldap-go-ssf-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketRoot) })
	path := filepath.Join(socketRoot, "ldapi")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
	})

	existing := dialRawLocalSSF(t, path)
	assertLocalSSFSearchResult(t, existing, 1, ldap.LDAPResultNoSuchObject)

	var next *runtimeState
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		configuration := storage.WriterInPartition(writer, storage.OpenLDAPConfigPartition)
		entry, err := configuration.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLocalSSF", stringValues("50"))
		if err := configuration.Put(entry, true); err != nil {
			return err
		}
		next, err = instance.validateRuntimeConfiguration(writer)
		return err
	}); err != nil {
		t.Fatalf("reload olcLocalSSF: %v", err)
	}
	instance.activateRuntime(next)

	assertLocalSSFSearchResult(t, existing, 2, ldap.LDAPResultNoSuchObject)
	newConnection := dialRawLocalSSF(t, path)
	assertLocalSSFSearchResult(t, newConnection, 3, ldap.LDAPResultConfidentialityRequired)

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		configuration := storage.WriterInPartition(writer, storage.OpenLDAPConfigPartition)
		entry, err := configuration.Get(configurationSuffix)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcLocalSSF", nil)
		if err := configuration.Put(entry, true); err != nil {
			return err
		}
		next, err = instance.validateRuntimeConfiguration(writer)
		return err
	}); err != nil {
		t.Fatalf("delete olcLocalSSF: %v", err)
	}
	instance.activateRuntime(next)
	restoredConnection := dialRawLocalSSF(t, path)
	assertLocalSSFSearchResult(t, restoredConnection, 4, ldap.LDAPResultNoSuchObject)
}

func TestLocalSSFOnlineValidation(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configuration.Close() })
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}

	replace := func(value string) error {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace("olcLocalSSF", []string{value})
		return configuration.Modify(request)
	}
	assertLDAPResultCode(t, replace("not-an-integer"), ldap.LDAPResultInvalidAttributeSyntax)
	assertLDAPResultCode(t, replace("2147483648"), ldap.LDAPResultConstraintViolation)
	if err := replace("-1"); err != nil {
		t.Fatalf("replace olcLocalSSF with -1: %v", err)
	}
	remove := ldap.NewModifyRequest("cn=config", nil)
	remove.Delete("olcLocalSSF", nil)
	if err := configuration.Modify(remove); err != nil {
		t.Fatalf("delete olcLocalSSF: %v", err)
	}
}

func dialRawLocalSSF(t *testing.T, path string) net.Conn {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	return connection
}

func assertLocalSSFSearchResult(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	want uint16,
) {
	t.Helper()
	writeRawLDAPRequest(
		t,
		connection,
		messageID,
		rawMaxFilterDepthSearch(rawNestedNotFilter(0)),
	)
	if got := readRawMaxFilterDepthSearchDone(t, connection); got != int64(want) {
		t.Fatalf("Search result = %d, want %d", got, want)
	}
}
