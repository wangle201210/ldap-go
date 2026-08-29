//go:build linux || darwin || freebsd

package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPIExternalIdentityUsesKernelPeerCredentials(t *testing.T) {
	listener, path := listenPeercredTestSocket(t)
	defer listener.Close()
	identity := make(chan string, 1)
	errors := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			errors <- err
			return
		}
		defer connection.Close()
		value, err := peercredExternalIdentity(connection)
		if err != nil {
			errors <- err
			return
		}
		identity <- value
	}()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	want := fmt.Sprintf(
		"gidNumber=%d+uidNumber=%d,cn=peercred,cn=external,cn=auth",
		os.Getegid(),
		os.Geteuid(),
	)
	select {
	case got := <-identity:
		if got != want {
			t.Fatalf("peercred identity = %q, want %q", got, want)
		}
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("peer credential lookup timed out")
	}
}

func TestLDAPIClientSASLExternalPeercredMapping(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcAuthzRegexp",
					Values: stringValues(fmt.Sprintf(
						`{0}^gidNumber=%d\+uidNumber=%d,cn=peercred,cn=external,cn=auth$ cn=admin,dc=example,dc=com`,
						os.Getegid(),
						os.Geteuid(),
					)),
				}},
			},
			{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("domain")},
					{Description: "dc", Values: stringValues("example")},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
	listener, path := listenPeercredTestSocket(t)
	uri := "ldapi://" + url.PathEscape(path) + "/"
	instance, err := New(Config{
		Store:        store,
		ListenerURLs: []string{uri},
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("unused"),
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
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("peercred test server did not stop")
		}
	})

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedSASLMechanisms"},
		nil,
	))
	if err != nil || len(root.Entries) != 1 || !containsString(
		root.Entries[0].GetAttributeValues("supportedSASLMechanisms"),
		"EXTERNAL",
	) {
		t.Fatalf("LDAPI supportedSASLMechanisms = %#v, %v", root, err)
	}
	if err := client.ExternalBind(); err != nil {
		t.Fatalf("LDAPI EXTERNAL Bind: %v", err)
	}
	identity, err := client.WhoAmI(nil)
	if err != nil || identity.AuthzID != "dn:cn=admin,dc=example,dc=com" {
		t.Fatalf("LDAPI EXTERNAL WhoAmI = %#v, %v", identity, err)
	}
}

func TestLDAPIExternalPeercredDoesNotGrantRootWithoutMapping(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "dc=example,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("domain")},
					{Description: "dc", Values: stringValues("example")},
				},
			},
			{
				DN: "olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "olcDatabase", Values: stringValues("{1}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
	listener, path := listenPeercredTestSocket(t)
	uri := "ldapi://" + url.PathEscape(path) + "/"
	instance, err := New(Config{
		Store:        store,
		ListenerURLs: []string{uri},
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("unused"),
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
	if err := client.ExternalBind(); err != nil {
		t.Fatalf("unmapped LDAPI EXTERNAL Bind: %v", err)
	}
	identity, err := client.WhoAmI(nil)
	want := fmt.Sprintf(
		"dn:gidnumber=%d+uidnumber=%d,cn=peercred,cn=external,cn=auth",
		os.Getegid(),
		os.Geteuid(),
	)
	if err != nil || identity.AuthzID != want {
		t.Fatalf("unmapped LDAPI WhoAmI = %#v, %v; want %q", identity, err, want)
	}
	add := ldap.NewAddRequest("uid=forged-root,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"forged-root"})
	add.Attribute("cn", []string{"Forged Root"})
	add.Attribute("sn", []string{"Root"})
	if err := client.Add(add); err == nil {
		t.Fatal("unmapped LDAPI peercred identity received root write access")
	}
}

func TestOpenLDAPPeercredIdentitySourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE is not set")
	}
	for _, relative := range []string{
		"servers/slapd/daemon.c",
		"libraries/libldap/cyrus.c",
	} {
		contents, err := os.ReadFile(filepath.Join(source, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(contents)
		for _, fragment := range []string{
			`gidNumber=%u+uidNumber=%u,`,
			`cn=peercred,cn=external,cn=auth`,
		} {
			if !strings.Contains(text, fragment) {
				t.Fatalf("%s is missing peercred source anchor %q", relative, fragment)
			}
		}
	}
}

func listenPeercredTestSocket(t *testing.T) (net.Listener, string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ldap-go-peercred-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	path := filepath.Join(root, "ldapi")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener, path
}
