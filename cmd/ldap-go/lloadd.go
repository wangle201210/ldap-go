package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/wangle201210/ldap-go/internal/lloadd"
)

func runLloadd(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("lloadd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("f", "lloadd.conf", "standalone lloadd configuration file")
	listenURLs := flags.String("h", "", "space-separated LDAP listener URLs overriding the configuration")
	logLevel := flags.String("log-level", "info", "debug, info, warn, error, or an integer")
	checkConfig := flags.Bool("test-config", false, "validate configuration and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	config, err := lloadd.ParseConfigFile(*configPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*listenURLs) != "" {
		config.ListenURLs = strings.Fields(*listenURLs)
		if err := config.Validate(); err != nil {
			return err
		}
	}
	if *checkConfig {
		for _, rawURL := range config.ListenURLs {
			if _, _, err := parseLloaddListenerURL(rawURL); err != nil {
				return err
			}
		}
		proxy, err := lloadd.New(*config)
		if err != nil {
			return err
		}
		_ = proxy.Close()
		_, err = fmt.Fprintf(stdout, "lloadd configuration is valid: %s\n", *configPath)
		return err
	}
	level, err := parseLogLevel(*logLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	proxy, err := lloadd.New(*config, lloadd.WithLogger(logger))
	if err != nil {
		return err
	}
	listeners := make([]net.Listener, 0, len(config.ListenURLs))
	listenerDescriptions := make([]string, 0, len(config.ListenURLs))
	for _, rawURL := range config.ListenURLs {
		listener, description, err := listenLloaddURL(rawURL)
		if err != nil {
			closeListeners(listeners)
			return err
		}
		listeners = append(listeners, listener)
		listenerDescriptions = append(listenerDescriptions, description)
	}
	listener, err := newCombinedListener(listeners)
	if err != nil {
		closeListeners(listeners)
		return err
	}
	defer listener.Close()
	defer proxy.Close()
	for _, description := range listenerDescriptions {
		if _, err := fmt.Fprintf(stdout, "ldap-go lloadd listening on %s\n", description); err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return proxy.Serve(ctx, listener)
}

func listenLloaddURL(raw string) (net.Listener, string, error) {
	network, address, err := parseLloaddListenerURL(raw)
	if err != nil {
		return nil, "", err
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, "", fmt.Errorf("listen on %s: %w", raw, err)
	}
	if network == "unix" {
		return listener, "ldapi://" + address, nil
	}
	return listener, "ldap://" + listener.Addr().String(), nil
}

func parseLloaddListenerURL(raw string) (string, string, error) {
	if strings.HasPrefix(strings.ToLower(raw), "ldapi://") {
		path, err := lloadd.ParseLDAPIAddress(raw)
		if err != nil {
			return "", "", fmt.Errorf("decode lloadd listener %q: %w", raw, err)
		}
		if path == "" || path == "/" {
			path = "/var/run/ldap-go/lloadd.sock"
		}
		return "unix", filepath.Clean(path), nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse lloadd listener %q: %w", raw, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ldap":
		address := parsed.Host
		if address == "" {
			address = ":389"
		} else if _, _, err := net.SplitHostPort(address); err != nil {
			address = net.JoinHostPort(parsed.Hostname(), "389")
		}
		return "tcp", address, nil
	case "ldaps", "pldap", "pldaps":
		return "", "", fmt.Errorf("lloadd listener scheme %q is not implemented", parsed.Scheme)
	default:
		return "", "", fmt.Errorf("unsupported lloadd listener scheme %q", parsed.Scheme)
	}
}

type combinedAccept struct {
	connection net.Conn
	err        error
}

type combinedListener struct {
	listeners []net.Listener
	accepted  chan combinedAccept
	done      chan struct{}
	once      sync.Once
}

func newCombinedListener(listeners []net.Listener) (*combinedListener, error) {
	if len(listeners) == 0 {
		return nil, errors.New("lloadd has no listeners")
	}
	combined := &combinedListener{
		listeners: append([]net.Listener(nil), listeners...),
		accepted:  make(chan combinedAccept),
		done:      make(chan struct{}),
	}
	for _, listener := range combined.listeners {
		go combined.accept(listener)
	}
	return combined, nil
}

func (listener *combinedListener) accept(source net.Listener) {
	for {
		connection, err := source.Accept()
		select {
		case listener.accepted <- combinedAccept{connection: connection, err: err}:
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

func (listener *combinedListener) Accept() (net.Conn, error) {
	select {
	case accepted := <-listener.accepted:
		return accepted.connection, accepted.err
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *combinedListener) Close() error {
	var closeErr error
	listener.once.Do(func() {
		close(listener.done)
		for _, source := range listener.listeners {
			closeErr = errors.Join(closeErr, source.Close())
		}
	})
	return closeErr
}

func (listener *combinedListener) Addr() net.Addr {
	return listener.listeners[0].Addr()
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}
