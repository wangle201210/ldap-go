package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wangle201210/ldap-go/internal/lloadd"
)

func runLloadd(args []string, stdout, stderr io.Writer) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	management := make(chan os.Signal, 2)
	signal.Notify(management, syscall.SIGHUP, syscall.SIGUSR1)
	defer signal.Stop(management)
	return runLloaddWithSignals(ctx, management, args, stdout, stderr)
}

func runLloaddWithSignals(
	ctx context.Context,
	management <-chan os.Signal,
	args []string,
	stdout, stderr io.Writer,
) error {
	if ctx == nil {
		return errors.New("lloadd context is required")
	}
	if management == nil {
		return errors.New("lloadd management signal channel is required")
	}
	flags := flag.NewFlagSet("lloadd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("f", "lloadd.conf", "standalone lloadd configuration file")
	listenURLs := flags.String("h", "", "space-separated LDAP listener URLs overriding the configuration")
	logLevel := flags.String("log-level", "info", "debug, info, warn, error, or an integer")
	tlsCertificate := flags.String("tls-cert", "", "PEM certificate for client StartTLS and LDAPS listeners")
	tlsKey := flags.String("tls-key", "", "PEM private key for client StartTLS and LDAPS listeners")
	checkConfig := flags.Bool("test-config", false, "validate configuration and exit")
	hotReload := flags.Bool("hot-reload", false, "reload configuration on SIGUSR1")
	drainTimeout := flags.Duration("drain-timeout", 30*time.Second, "maximum graceful drain duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *drainTimeout <= 0 {
		return errors.New("-drain-timeout must be positive")
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
	clientTLS, err := loadLloaddClientTLS(*tlsCertificate, *tlsKey)
	if err != nil {
		return err
	}
	if err := validateLloaddListeners(config.ListenURLs, clientTLS); err != nil {
		return err
	}
	if *checkConfig {
		proxy, err := newLloaddProxy(*config, nil, clientTLS)
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
	overrideURLs := strings.Fields(*listenURLs)
	daemon, err := lloadd.NewDaemon(lloadd.DaemonOptions{
		Load: func(context.Context) (lloadd.DaemonTopology, error) {
			candidate, err := lloadd.ParseConfigFile(*configPath)
			if err != nil {
				return lloadd.DaemonTopology{}, err
			}
			if len(overrideURLs) != 0 {
				candidate.ListenURLs = append([]string(nil), overrideURLs...)
				if err := candidate.Validate(); err != nil {
					return lloadd.DaemonTopology{}, err
				}
			}
			loadedTLS, err := loadLloaddClientTLS(*tlsCertificate, *tlsKey)
			if err != nil {
				return lloadd.DaemonTopology{}, err
			}
			if err := validateLloaddListeners(candidate.ListenURLs, loadedTLS); err != nil {
				return lloadd.DaemonTopology{}, err
			}
			runtime, err := candidate.RuntimeConfig()
			if err != nil {
				return lloadd.DaemonTopology{}, err
			}
			runtime.Logger = logger
			if loadedTLS != nil {
				runtime.ClientTLS = loadedTLS.Clone()
			}
			return lloadd.DaemonTopology{
				Runtime:    runtime,
				ListenURLs: append([]string(nil), candidate.ListenURLs...),
				GentleHUP:  candidate.GentleHUP,
			}, nil
		},
		ListenerKey: lloaddListenerKey,
		Listen: func(raw string) (net.Listener, string, error) {
			return listenLloaddRawURL(raw)
		},
		Prepare:      prepareLloaddAcceptedConnection,
		DrainTimeout: *drainTimeout,
		Logger:       logger,
	})
	if err != nil {
		return err
	}
	result, err := daemon.Start(ctx)
	if err != nil {
		return err
	}
	defer daemon.Close()
	for _, description := range result.Listeners {
		if _, err := fmt.Fprintf(stdout, "ldap-go lloadd listening on %s\n", description); err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-daemon.Errors():
			return err
		case received := <-management:
			switch received {
			case syscall.SIGHUP:
				gentle := daemon.Snapshot().GentleHUP
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), *drainTimeout)
				err := daemon.Shutdown(shutdownCtx, gentle)
				shutdownCancel()
				return err
			case syscall.SIGUSR1:
				if !*hotReload {
					logger.Warn("lloadd SIGUSR1 hot reload ignored; enable -hot-reload")
					continue
				}
				if _, err := daemon.Reload(ctx); err != nil {
					logger.Error("lloadd SIGUSR1 reload failed; keeping current topology", "error", err)
				}
			}
		}
	}
}

func listenLloaddRawURL(raw string) (net.Listener, string, error) {
	scheme, network, address, err := parseLloaddListenerURL(raw)
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
	return listener, scheme + "://" + listener.Addr().String(), nil
}

func prepareLloaddAcceptedConnection(
	raw string,
	runtime lloadd.RuntimeConfig,
	connection net.Conn,
) (net.Conn, error) {
	scheme, _, _, err := parseLloaddListenerURL(raw)
	if err != nil {
		return nil, err
	}
	if scheme == "pldap" || scheme == "pldaps" {
		connection, err = readLloaddProxyProtocol(connection, lloaddProxyProtocolTimeout)
		if err != nil {
			return nil, err
		}
	}
	if scheme == "ldaps" || scheme == "pldaps" {
		if runtime.ClientTLS == nil {
			return nil, errors.New("LDAPS listener has no TLS configuration")
		}
		secured := tls.Server(connection, runtime.ClientTLS.Clone())
		timeout := runtime.IOTimeout
		if timeout <= 0 {
			timeout = lloadd.DefaultIOTimeout
		}
		if err := secured.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, fmt.Errorf("set LDAPS handshake deadline: %w", err)
		}
		if err := secured.Handshake(); err != nil {
			return nil, fmt.Errorf("LDAPS handshake: %w", err)
		}
		if err := secured.SetDeadline(time.Time{}); err != nil {
			return nil, fmt.Errorf("clear LDAPS handshake deadline: %w", err)
		}
		connection = secured
	}
	return connection, nil
}

func loadLloaddClientTLS(certificatePath, keyPath string) (*tls.Config, error) {
	if (certificatePath == "") != (keyPath == "") {
		return nil, errors.New("-tls-cert and -tls-key must be configured together")
	}
	if certificatePath == "" {
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load lloadd listener TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func newLloaddProxy(
	config lloadd.Config,
	logger *slog.Logger,
	clientTLS *tls.Config,
) (*lloadd.Proxy, error) {
	runtime, err := config.RuntimeConfig()
	if err != nil {
		return nil, err
	}
	if logger != nil {
		runtime.Logger = logger
	}
	if clientTLS != nil {
		runtime.ClientTLS = clientTLS.Clone()
	}
	return lloadd.NewProxy(runtime)
}

func validateLloaddListeners(urls []string, clientTLS *tls.Config) error {
	for _, rawURL := range urls {
		scheme, _, _, err := parseLloaddListenerURL(rawURL)
		if err != nil {
			return err
		}
		if (scheme == "ldaps" || scheme == "pldaps") && clientTLS == nil {
			return fmt.Errorf(
				"lloadd listener %q requires -tls-cert and -tls-key",
				rawURL,
			)
		}
	}
	return nil
}

func listenLloaddURL(
	raw string,
	clientTLS *tls.Config,
) (net.Listener, string, error) {
	scheme, network, address, err := parseLloaddListenerURL(raw)
	if err != nil {
		return nil, "", err
	}
	secure := scheme == "ldaps" || scheme == "pldaps"
	proxied := scheme == "pldap" || scheme == "pldaps"
	if secure && clientTLS == nil {
		return nil, "", fmt.Errorf(
			"lloadd listener %q requires -tls-cert and -tls-key",
			raw,
		)
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, "", fmt.Errorf("listen on %s: %w", raw, err)
	}
	if network == "unix" {
		return listener, "ldapi://" + address, nil
	}
	if proxied {
		listener = newProxyProtocolListener(listener, lloaddProxyProtocolTimeout)
	}
	if secure {
		listener = tls.NewListener(listener, clientTLS.Clone())
	}
	return listener, scheme + "://" + listener.Addr().String(), nil
}

func parseLloaddListenerURL(raw string) (string, string, string, error) {
	if strings.HasPrefix(strings.ToLower(raw), "ldapi://") {
		path, err := lloadd.ParseLDAPIAddress(raw)
		if err != nil {
			return "", "", "", fmt.Errorf("decode lloadd listener %q: %w", raw, err)
		}
		if path == "" || path == "/" {
			path = "/var/run/ldap-go/lloadd.sock"
		}
		return "ldapi", "unix", filepath.Clean(path), nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("parse lloadd listener %q: %w", raw, err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "ldap", "ldaps", "pldap", "pldaps":
		if scheme == "pldap" || scheme == "pldaps" {
			host := parsed.Hostname()
			ip := net.ParseIP(host)
			if host == "" || ip != nil && ip.IsUnspecified() {
				return "", "", "", fmt.Errorf(
					"trusted PROXY listener %q requires an explicit non-wildcard address",
					raw,
				)
			}
		}
		address := parsed.Host
		defaultPort := "389"
		if scheme == "ldaps" || scheme == "pldaps" {
			defaultPort = "636"
		}
		if address == "" {
			address = ":" + defaultPort
		} else if _, _, err := net.SplitHostPort(address); err != nil {
			address = net.JoinHostPort(parsed.Hostname(), defaultPort)
		}
		return scheme, "tcp", address, nil
	default:
		return "", "", "", fmt.Errorf("unsupported lloadd listener scheme %q", parsed.Scheme)
	}
}

func lloaddListenerKey(raw string) (string, error) {
	scheme, network, address, err := parseLloaddListenerURL(raw)
	if err != nil {
		return "", err
	}
	return scheme + "|" + network + "|" + address, nil
}

const (
	lloaddProxyProtocolTimeout        = 5 * time.Second
	lloaddProxyProtocolV1MaxHeader    = 107
	lloaddProxyProtocolUnixPathBytes  = 108
	lloaddProxyProtocolUnixAddrBytes  = 2 * lloaddProxyProtocolUnixPathBytes
	lloaddProxyProtocolMaxOptionBytes = 520
	lloaddProxyProtocolMaxTLVs        = 128
	lloaddProxyProtocolParsers        = 128
)

var lloaddProxyProtocolV2Signature = []byte{
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
}

type proxyProtocolListener struct {
	source  net.Listener
	timeout time.Duration

	startOnce sync.Once
	closeOnce sync.Once
	done      chan struct{}
	accepted  chan combinedAccept
	parsers   chan struct{}
}

func newProxyProtocolListener(
	source net.Listener,
	timeout time.Duration,
) *proxyProtocolListener {
	return &proxyProtocolListener{
		source:   source,
		timeout:  timeout,
		done:     make(chan struct{}),
		accepted: make(chan combinedAccept),
		parsers:  make(chan struct{}, lloaddProxyProtocolParsers),
	}
}

func (listener *proxyProtocolListener) Accept() (net.Conn, error) {
	listener.startOnce.Do(func() { go listener.acceptLoop() })
	select {
	case accepted := <-listener.accepted:
		return accepted.connection, accepted.err
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *proxyProtocolListener) acceptLoop() {
	for {
		connection, err := listener.source.Accept()
		if err != nil {
			select {
			case listener.accepted <- combinedAccept{err: err}:
			case <-listener.done:
			}
			return
		}
		select {
		case listener.parsers <- struct{}{}:
		case <-listener.done:
			_ = connection.Close()
			return
		}
		go listener.prepare(connection)
	}
}

func (listener *proxyProtocolListener) prepare(connection net.Conn) {
	defer func() { <-listener.parsers }()
	prepared, err := readLloaddProxyProtocol(connection, listener.timeout)
	if err != nil {
		_ = connection.Close()
		return
	}
	select {
	case listener.accepted <- combinedAccept{connection: prepared}:
	case <-listener.done:
		_ = prepared.Close()
	}
}

func (listener *proxyProtocolListener) Close() error {
	var err error
	listener.closeOnce.Do(func() {
		close(listener.done)
		err = listener.source.Close()
	})
	return err
}

func (listener *proxyProtocolListener) Addr() net.Addr {
	return listener.source.Addr()
}

func readLloaddProxyProtocol(
	connection net.Conn,
	timeout time.Duration,
) (net.Conn, error) {
	if timeout <= 0 {
		return nil, errors.New("PROXY protocol header timeout must be positive")
	}
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set PROXY protocol header deadline: %w", err)
	}
	var first [1]byte
	if _, err := io.ReadFull(connection, first[:]); err != nil {
		return nil, fmt.Errorf("read PROXY protocol header: %w", err)
	}
	metadata := lloadd.ConnectionMetadata{
		ProxyProtocol:               true,
		SourceAddress:               connection.RemoteAddr(),
		DestinationAddress:          connection.LocalAddr(),
		TransportSourceAddress:      connection.RemoteAddr(),
		TransportDestinationAddress: connection.LocalAddr(),
	}
	switch first[0] {
	case 'P':
		source, destination, unknown, err := readLloaddProxyProtocolV1(connection, first[0])
		if err != nil {
			return nil, err
		}
		metadata.ProxyProtocolLocal = unknown
		if !unknown {
			metadata.SourceAddress = source
			metadata.DestinationAddress = destination
		}
	case lloaddProxyProtocolV2Signature[0]:
		command, familyProtocol, body, tlvs, err := readLloaddProxyProtocolV2(connection, first[0])
		if err != nil {
			return nil, err
		}
		metadata.ProxyProtocolLocal = command == 0
		metadata.TLVs = tlvs
		if command == 1 {
			metadata.SourceAddress, metadata.DestinationAddress, err =
				proxyProtocolAddresses(familyProtocol, body)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("invalid PROXY protocol signature")
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear PROXY protocol header deadline: %w", err)
	}
	prepared, err := lloadd.WithConnectionMetadata(connection, metadata)
	if err != nil {
		return nil, fmt.Errorf("attach PROXY protocol metadata: %w", err)
	}
	return prepared, nil
}

func readLloaddProxyProtocolV2(
	connection net.Conn,
	first byte,
) (byte, byte, []byte, []lloadd.ProxyProtocolTLV, error) {
	header := make([]byte, 16)
	header[0] = first
	if _, err := io.ReadFull(connection, header[1:]); err != nil {
		return 0, 0, nil, nil, fmt.Errorf("read PROXY protocol v2 header: %w", err)
	}
	if !bytes.Equal(header[:12], lloaddProxyProtocolV2Signature) {
		return 0, 0, nil, nil, errors.New("invalid PROXY protocol v2 signature")
	}
	if header[12]>>4 != 2 {
		return 0, 0, nil, nil, fmt.Errorf("unsupported PROXY protocol version %d", header[12]>>4)
	}
	command := header[12] & 0x0f
	familyProtocol := header[13]
	length := int(binary.BigEndian.Uint16(header[14:16]))

	addressLength := 0
	switch command {
	case 0:
		// OpenLDAP ignores LOCAL's family and consumes its payload as opaque options.
	case 1:
		switch familyProtocol {
		case 0x11:
			addressLength = 12
		case 0x21:
			addressLength = 36
		case 0x31:
			addressLength = lloaddProxyProtocolUnixAddrBytes
		case 0x12, 0x22, 0x32:
			return 0, 0, nil, nil, fmt.Errorf(
				"PROXY protocol DGRAM transport 0x%02x is not supported by a stream listener",
				familyProtocol,
			)
		default:
			return 0, 0, nil, nil, fmt.Errorf("unsupported PROXY protocol family/transport 0x%02x", familyProtocol)
		}
	default:
		return 0, 0, nil, nil, fmt.Errorf("unsupported PROXY protocol command %d", command)
	}
	if length < addressLength {
		return 0, 0, nil, nil, fmt.Errorf(
			"PROXY protocol address length %d is smaller than %d",
			length,
			addressLength,
		)
	}
	if length-addressLength > lloaddProxyProtocolMaxOptionBytes {
		return 0, 0, nil, nil, fmt.Errorf(
			"PROXY protocol options exceed %d bytes",
			lloaddProxyProtocolMaxOptionBytes,
		)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(connection, body); err != nil {
		return 0, 0, nil, nil, fmt.Errorf("read PROXY protocol payload: %w", err)
	}
	var tlvs []lloadd.ProxyProtocolTLV
	if command == 1 {
		// OpenLDAP treats bytes after the address block as opaque options. Keep
		// TLV metadata as a best-effort extension without making it part of
		// connection acceptance.
		if parsedTLVs, err := parseLloaddProxyProtocolTLVs(body[addressLength:]); err == nil {
			tlvs = parsedTLVs
		}
	}
	return command, familyProtocol, body[:addressLength], tlvs, nil
}

func readLloaddProxyProtocolV1(
	connection net.Conn,
	first byte,
) (net.Addr, net.Addr, bool, error) {
	header := make([]byte, 1, lloaddProxyProtocolV1MaxHeader)
	header[0] = first
	for len(header) < lloaddProxyProtocolV1MaxHeader {
		var next [1]byte
		if _, err := io.ReadFull(connection, next[:]); err != nil {
			return nil, nil, false, fmt.Errorf("read PROXY protocol v1 header: %w", err)
		}
		header = append(header, next[0])
		if next[0] != '\n' {
			continue
		}
		if len(header) < 2 || header[len(header)-2] != '\r' {
			return nil, nil, false, errors.New("PROXY protocol v1 header must end with CRLF")
		}
		return parseLloaddProxyProtocolV1(header[:len(header)-2])
	}
	return nil, nil, false, fmt.Errorf(
		"PROXY protocol v1 header exceeds %d bytes",
		lloaddProxyProtocolV1MaxHeader,
	)
}

func parseLloaddProxyProtocolV1(
	line []byte,
) (net.Addr, net.Addr, bool, error) {
	for _, character := range line {
		if character < 0x20 || character > 0x7e {
			return nil, nil, false, errors.New("PROXY protocol v1 header is not printable ASCII")
		}
	}
	fields := strings.Split(string(line), " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, nil, false, errors.New("invalid PROXY protocol v1 signature")
	}
	if fields[1] == "UNKNOWN" {
		return nil, nil, true, nil
	}
	if fields[1] != "TCP4" && fields[1] != "TCP6" {
		return nil, nil, false, fmt.Errorf("unsupported PROXY protocol v1 family %q", fields[1])
	}
	if len(fields) != 6 {
		return nil, nil, false, fmt.Errorf(
			"PROXY %s requires exactly four address fields",
			fields[1],
		)
	}
	sourceIP, err := parseLloaddProxyProtocolV1IP(fields[1], fields[2])
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid PROXY protocol source address: %w", err)
	}
	destinationIP, err := parseLloaddProxyProtocolV1IP(fields[1], fields[3])
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid PROXY protocol destination address: %w", err)
	}
	sourcePort, err := parseLloaddProxyProtocolV1Decimal(fields[4], 65535)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid PROXY protocol source port: %w", err)
	}
	destinationPort, err := parseLloaddProxyProtocolV1Decimal(fields[5], 65535)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid PROXY protocol destination port: %w", err)
	}
	return &net.TCPAddr{IP: sourceIP, Port: sourcePort},
		&net.TCPAddr{IP: destinationIP, Port: destinationPort}, false, nil
}

func parseLloaddProxyProtocolV1IP(family, encoded string) (net.IP, error) {
	if family == "TCP4" {
		parts := strings.Split(encoded, ".")
		if len(parts) != net.IPv4len {
			return nil, errors.New("TCP4 address must contain four decimal octets")
		}
		address := make(net.IP, net.IPv4len)
		for index, part := range parts {
			value, err := parseLloaddProxyProtocolV1Decimal(part, 255)
			if err != nil {
				return nil, fmt.Errorf("octet %d: %w", index+1, err)
			}
			address[index] = byte(value)
		}
		return address, nil
	}
	if strings.ContainsAny(encoded, ".%") {
		return nil, errors.New("TCP6 address must not use an IPv4 suffix or zone")
	}
	for _, character := range encoded {
		if character != ':' && !isLloaddProxyProtocolHex(character) {
			return nil, errors.New("TCP6 address contains a non-hexadecimal character")
		}
	}
	address, err := netip.ParseAddr(encoded)
	if err != nil || !address.Is6() {
		return nil, errors.New("TCP6 address is not a valid IPv6 address")
	}
	return net.IP(address.AsSlice()), nil
}

func parseLloaddProxyProtocolV1Decimal(encoded string, maximum int) (int, error) {
	if encoded == "" {
		return 0, errors.New("decimal value is empty")
	}
	if len(encoded) > 1 && encoded[0] == '0' {
		return 0, errors.New("decimal value has a leading zero")
	}
	value := 0
	for _, character := range encoded {
		if character < '0' || character > '9' {
			return 0, errors.New("decimal value contains a non-digit")
		}
		digit := int(character - '0')
		if value > (maximum-digit)/10 {
			return 0, fmt.Errorf("decimal value exceeds %d", maximum)
		}
		value = value*10 + digit
	}
	return value, nil
}

func isLloaddProxyProtocolHex(character rune) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'f' ||
		character >= 'A' && character <= 'F'
}

func proxyProtocolAddresses(familyProtocol byte, encoded []byte) (net.Addr, net.Addr, error) {
	expectedLength := 0
	switch familyProtocol {
	case 0x11:
		expectedLength = 12
	case 0x21:
		expectedLength = 36
	case 0x31:
		expectedLength = lloaddProxyProtocolUnixAddrBytes
	default:
		return nil, nil, fmt.Errorf("unsupported PROXY protocol address family 0x%02x", familyProtocol)
	}
	if len(encoded) != expectedLength {
		return nil, nil, fmt.Errorf(
			"PROXY protocol address block has %d bytes, want %d for 0x%02x",
			len(encoded),
			expectedLength,
			familyProtocol,
		)
	}

	switch familyProtocol {
	case 0x11:
		return &net.TCPAddr{
				IP:   append(net.IP(nil), encoded[:4]...),
				Port: int(binary.BigEndian.Uint16(encoded[8:10])),
			}, &net.TCPAddr{
				IP:   append(net.IP(nil), encoded[4:8]...),
				Port: int(binary.BigEndian.Uint16(encoded[10:12])),
			}, nil
	case 0x31:
		source, err := parseLloaddProxyProtocolUnixPath(encoded[:lloaddProxyProtocolUnixPathBytes])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid PROXY protocol UNIX source path: %w", err)
		}
		destination, err := parseLloaddProxyProtocolUnixPath(encoded[lloaddProxyProtocolUnixPathBytes:])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid PROXY protocol UNIX destination path: %w", err)
		}
		return &net.UnixAddr{Name: source, Net: "unix"},
			&net.UnixAddr{Name: destination, Net: "unix"}, nil
	default:
		return &net.TCPAddr{
				IP:   append(net.IP(nil), encoded[:16]...),
				Port: int(binary.BigEndian.Uint16(encoded[32:34])),
			}, &net.TCPAddr{
				IP:   append(net.IP(nil), encoded[16:32]...),
				Port: int(binary.BigEndian.Uint16(encoded[34:36])),
			}, nil
	}
}

func parseLloaddProxyProtocolUnixPath(encoded []byte) (string, error) {
	if len(encoded) != lloaddProxyProtocolUnixPathBytes {
		return "", fmt.Errorf("path field has %d bytes, want %d", len(encoded), lloaddProxyProtocolUnixPathBytes)
	}
	if encoded[0] == 0 {
		end := 1
		for end < len(encoded) && encoded[end] != 0 {
			end++
		}
		if end == 1 {
			return "", errors.New("abstract path is empty")
		}
		for _, padding := range encoded[end:] {
			if padding != 0 {
				return "", errors.New("abstract path contains data after padding")
			}
		}
		return "@" + string(encoded[1:end]), nil
	}
	terminator := bytes.IndexByte(encoded, 0)
	if terminator < 0 {
		terminator = len(encoded)
	}
	for _, character := range encoded[:terminator] {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("path contains control byte 0x%02x", character)
		}
	}
	paddingStart := min(terminator+1, len(encoded))
	for _, padding := range encoded[paddingStart:] {
		if padding != 0 {
			return "", errors.New("path contains data after its NUL terminator")
		}
	}
	return string(encoded[:terminator]), nil
}

func parseLloaddProxyProtocolTLVs(encoded []byte) ([]lloadd.ProxyProtocolTLV, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	tlvs := make([]lloadd.ProxyProtocolTLV, 0, min(len(encoded)/3, lloaddProxyProtocolMaxTLVs))
	for len(encoded) != 0 {
		if len(tlvs) == lloaddProxyProtocolMaxTLVs {
			return nil, fmt.Errorf("PROXY protocol has more than %d TLVs", lloaddProxyProtocolMaxTLVs)
		}
		if len(encoded) < 3 {
			return nil, errors.New("truncated PROXY protocol TLV header")
		}
		tlvType := encoded[0]
		length := int(binary.BigEndian.Uint16(encoded[1:3]))
		encoded = encoded[3:]
		if length > len(encoded) {
			return nil, errors.New("truncated PROXY protocol TLV value")
		}
		tlvs = append(tlvs, lloadd.ProxyProtocolTLV{
			Type:  tlvType,
			Value: append([]byte(nil), encoded[:length]...),
		})
		encoded = encoded[length:]
	}
	return tlvs, nil
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
