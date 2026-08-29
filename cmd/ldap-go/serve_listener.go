package main

import (
	"errors"
	"net"
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
