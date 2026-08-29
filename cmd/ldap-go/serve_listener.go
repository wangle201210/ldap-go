package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

type serveAcceptResult struct {
	connection net.Conn
	err        error
}

type serveMultiListener struct {
	listeners []net.Listener
	accepted  chan serveAcceptResult
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

type serveSchemeListener struct {
	net.Listener
	scheme string
}

type serveSchemeConnection struct {
	net.Conn
	scheme string
}

func (listener *serveSchemeListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &serveSchemeConnection{Conn: connection, scheme: listener.scheme}, nil
}

func (connection *serveSchemeConnection) listenerScheme() string {
	return connection.scheme
}

func newServeListener(listeners []net.Listener) net.Listener {
	if len(listeners) == 1 {
		return listeners[0]
	}
	multi := &serveMultiListener{
		listeners: append([]net.Listener(nil), listeners...),
		accepted:  make(chan serveAcceptResult),
		done:      make(chan struct{}),
	}
	for _, listener := range multi.listeners {
		go multi.accept(listener)
	}
	return multi
}

func serveImplicitTLSResolver(
	listeners []net.Listener,
	implicitTLS []bool,
) func(net.Conn) bool {
	if len(listeners) != len(implicitTLS) {
		panic("listener transport mode count does not match listeners")
	}
	urls := make([]string, len(listeners))
	for index := range listeners {
		if implicitTLS[index] {
			urls[index] = "ldaps://listener/"
		} else {
			urls[index] = "ldap://listener/"
		}
	}
	resolver := serveListenerSchemeResolver(listeners, urls)
	if resolver == nil {
		return nil
	}
	return func(connection net.Conn) bool {
		scheme := resolver(connection)
		return scheme == "ldaps" || scheme == "ldap+tlcp"
	}
}

func serveListenerSchemeResolver(
	listeners []net.Listener,
	listenerURLs []string,
) func(net.Conn) string {
	if len(listeners) != len(listenerURLs) {
		panic("listener URL count does not match listeners")
	}
	hasSecure := false
	for index, listenerURL := range listenerURLs {
		scheme, _, _ := strings.Cut(strings.ToLower(listenerURL), "://")
		if scheme != "ldaps" && scheme != "ldap+tlcp" {
			continue
		}
		hasSecure = true
		listeners[index] = &serveSchemeListener{
			Listener: listeners[index],
			scheme:   scheme,
		}
	}
	if !hasSecure {
		return nil
	}
	return func(connection net.Conn) string {
		if marked, ok := connection.(interface{ listenerScheme() string }); ok {
			return marked.listenerScheme()
		}
		if connection != nil && connection.LocalAddr() != nil {
			network := connection.LocalAddr().Network()
			if network == "unix" || network == "unixpacket" {
				return "ldapi"
			}
		}
		return "ldap"
	}
}

func validateServeListenerTransportMix(listenerURLs []string, tlcp bool) error {
	var hasTLS, hasTLCP bool
	for _, listenerURL := range listenerURLs {
		switch {
		case strings.HasPrefix(strings.ToLower(listenerURL), "ldaps://"):
			hasTLS = true
		case strings.HasPrefix(strings.ToLower(listenerURL), "ldap+tlcp://"):
			hasTLCP = true
		}
	}
	if hasTLS && hasTLCP {
		return errors.New("standard TLS and TLCP listeners cannot share one server process")
	}
	if hasTLS && tlcp {
		return errors.New("LDAPS listeners cannot use a TLCP transport")
	}
	if hasTLCP && !tlcp {
		return fmt.Errorf("TLCP listeners require TLCP certificate options")
	}
	return nil
}

func (listener *serveMultiListener) accept(source net.Listener) {
	for {
		connection, err := source.Accept()
		select {
		case listener.accepted <- serveAcceptResult{connection: connection, err: err}:
		case <-listener.done:
			if connection != nil {
				_ = connection.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

func (listener *serveMultiListener) Accept() (net.Conn, error) {
	select {
	case result := <-listener.accepted:
		return result.connection, result.err
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *serveMultiListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.done)
		var closeErrors []error
		for _, source := range listener.listeners {
			if err := source.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		listener.closeErr = errors.Join(closeErrors...)
	})
	return listener.closeErr
}

func (listener *serveMultiListener) Addr() net.Addr {
	return listener.listeners[0].Addr()
}
