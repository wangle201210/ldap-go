package server

import (
	"context"
	"errors"
	"net"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type reverseLookupTestResolver struct {
	expected string
	names    []string
	err      error
	calls    int
}

func (resolver *reverseLookupTestResolver) LookupAddr(
	_ context.Context,
	address string,
) ([]string, error) {
	resolver.calls++
	if resolver.expected != "" && address != resolver.expected {
		return nil, errors.New("unexpected lookup address " + address)
	}
	return append([]string(nil), resolver.names...), resolver.err
}

func TestReverseLookupConfigurationAndACLSubject(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcReverseLookup",
				Values:      stringValues("TRUE"),
			}},
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	resolver := &reverseLookupTestResolver{expected: "192.0.2.25", names: []string{"CLIENT.Example.TEST."}}
	server, err := New(Config{Store: store, ReverseLookupResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	domain := server.connectionDomainName(
		context.Background(),
		&net.TCPAddr{IP: net.ParseIP("192.0.2.25"), Port: 43210},
	)
	if domain != "client.example.test" || resolver.calls != 1 {
		t.Fatalf("domain = %q, calls = %d", domain, resolver.calls)
	}
	subject := server.connectionACLSubject(&connectionState{domainName: domain})
	if subject.Domain != domain {
		t.Fatalf("ACL domain = %q", subject.Domain)
	}
}

func TestReverseLookupDisabledAndFailureAreEmpty(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	resolver := &reverseLookupTestResolver{expected: "192.0.2.25", names: []string{"unused.example."}}
	server, err := New(Config{Store: store, ReverseLookupResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	address := &net.TCPAddr{IP: net.ParseIP("192.0.2.25"), Port: 1234}
	if got := server.connectionDomainName(context.Background(), address); got != "" {
		t.Fatalf("disabled domain = %q", got)
	}
	if resolver.calls != 0 {
		t.Fatalf("disabled resolver calls = %d", resolver.calls)
	}

	server.runtime.Load().reverseLookup = true
	resolver.err = errors.New("PTR unavailable")
	resolver.names = nil
	if got := server.connectionDomainName(context.Background(), address); got != "" {
		t.Fatalf("failed lookup domain = %q", got)
	}
}

func TestReverseLookupExistingConnectionSnapshot(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		global, err := writer.Get(configurationSuffix)
		if err != nil {
			return err
		}
		global.ReplaceValues("olcReverseLookup", stringValues("TRUE"))
		if err := writer.Put(global, true); err != nil {
			return err
		}
		dataDN := staticRuntimeDN("olcDatabase={1}mdb,cn=config")
		data, err := writer.Get(dataDN)
		if err != nil {
			return err
		}
		data.ReplaceValues("olcAccess", stringValues(
			`{0}to * by domain.exact="client.example.test" read by * none`,
		))
		return writer.Put(data, true)
	}); err != nil {
		t.Fatal(err)
	}
	resolver := &reverseLookupTestResolver{
		expected: "127.0.0.1",
		names:    []string{"CLIENT.Example.TEST."},
	}
	address, stop := startServer(t, store, Config{ReverseLookupResolver: resolver})
	t.Cleanup(stop)

	oldConnection, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { oldConnection.Close() })
	search := func(client *ldap.Conn) error {
		_, err := client.Search(ldap.NewSearchRequest(
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
		return err
	}
	if err := search(oldConnection); err != nil {
		t.Fatalf("old connection before disable: %v", err)
	}

	configuration, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configuration.Close() })
	if err := configuration.Bind("cn=config", "config-secret"); err != nil {
		t.Fatal(err)
	}
	disable := ldap.NewModifyRequest("cn=config", nil)
	disable.Replace("olcReverseLookup", []string{"FALSE"})
	if err := configuration.Modify(disable); err != nil {
		t.Fatalf("disable reverse lookup: %v", err)
	}
	if err := search(oldConnection); err != nil {
		t.Fatalf("old connection after disable: %v", err)
	}

	newConnection, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer newConnection.Close()
	assertLDAPResultCode(t, search(newConnection), ldap.LDAPResultNoSuchObject)
}
