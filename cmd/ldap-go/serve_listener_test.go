package main

import (
	"net"
	"testing"
	"time"
)

func TestServeImplicitTLSResolverUsesAcceptedListener(t *testing.T) {
	t.Parallel()

	plain := listenServeResolverTCP(t)
	secure := listenServeResolverTCP(t)
	listeners := []net.Listener{plain, secure}
	resolver := serveImplicitTLSResolver(
		listeners,
		[]bool{false, true},
	)
	if resolver == nil {
		t.Fatal("resolver is nil")
	}
	for _, test := range []struct {
		name     string
		listener net.Listener
		secure   bool
	}{
		{name: "plain", listener: listeners[0], secure: false},
		{name: "secure", listener: listeners[1], secure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted := make(chan net.Conn, 1)
			go func() {
				connection, _ := test.listener.Accept()
				accepted <- connection
			}()
			client, err := net.DialTimeout("tcp", test.listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatalf("Dial(): %v", err)
			}
			defer client.Close()
			connection := <-accepted
			if connection == nil {
				t.Fatal("Accept() returned nil")
			}
			defer connection.Close()
			if got := resolver(connection); got != test.secure {
				t.Fatalf("resolver() = %v, want %v", got, test.secure)
			}
		})
	}
}

func TestServeListenerSchemeResolverHandlesWildcardAddress(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	listeners := []net.Listener{listener}
	resolver := serveListenerSchemeResolver(
		listeners,
		[]string{"ldaps://0.0.0.0:636/"},
	)
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listeners[0].Accept()
		accepted <- connection
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(): %v", err)
	}
	client, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer client.Close()
	connection := <-accepted
	if connection == nil {
		t.Fatal("Accept() returned nil")
	}
	defer connection.Close()
	if got := resolver(connection); got != "ldaps" {
		t.Fatalf("scheme = %q, want ldaps", got)
	}
}

func TestServeImplicitTLSResolverReturnsNilForPlainListeners(t *testing.T) {
	t.Parallel()

	listener := listenServeResolverTCP(t)
	if resolver := serveImplicitTLSResolver(
		[]net.Listener{listener},
		[]bool{false},
	); resolver != nil {
		t.Fatal("plain-only resolver is not nil")
	}
}

func TestValidateServeListenerTransportMix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		urls []string
		tlcp bool
		ok   bool
	}{
		{name: "plain and TLS", urls: []string{"ldap://127.0.0.1:389/", "ldaps://127.0.0.1:636/"}, ok: true},
		{name: "plain and TLCP", urls: []string{"ldap://127.0.0.1:389/", "ldap+tlcp://127.0.0.1:1636/"}, tlcp: true, ok: true},
		{name: "TLS and TLCP", urls: []string{"ldaps://127.0.0.1:636/", "ldap+tlcp://127.0.0.1:1636/"}},
		{name: "TLS on TLCP transport", urls: []string{"ldaps://127.0.0.1:636/"}, tlcp: true},
		{name: "TLCP without transport", urls: []string{"ldap+tlcp://127.0.0.1:1636/"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateServeListenerTransportMix(test.urls, test.tlcp)
			if (err == nil) != test.ok {
				t.Fatalf("validateServeListenerTransportMix() = %v, ok=%v", err, test.ok)
			}
		})
	}
}

func listenServeResolverTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
