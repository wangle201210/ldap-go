package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/gmtransport"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	rootPasswordEnvironment = "LDAP_GO_ROOT_PASSWORD"
	passwordEnvironment     = "LDAP_GO_PASSWORD"
	maxPasswordInputSize    = 1 << 20
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

func run(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	getenv func(string) string,
) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	var err error
	switch args[0] {
	case "import":
		err = runImport(args[1:], stdin, stdout, stderr)
	case "export":
		err = runExport(args[1:], stdout, stderr)
	case "passwd":
		err = runPassword(args[1:], stdin, stdout, stderr, getenv)
	case "serve":
		err = runServe(args[1:], stdout, stderr, getenv)
	case "version":
		_, err = fmt.Fprintln(stdout, version)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func runPassword(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	getenv func(string) string,
) error {
	flags := flag.NewFlagSet("passwd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	iterations := flags.Int(
		"iterations",
		auth.DefaultSMPBKDF2Iterations,
		"PBKDF2-SM3 iteration count",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	password := []byte(getenv(passwordEnvironment))
	if len(password) == 0 {
		input, err := io.ReadAll(io.LimitReader(stdin, maxPasswordInputSize+1))
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		if len(input) > maxPasswordInputSize {
			clear(input)
			return fmt.Errorf("password input exceeds %d bytes", maxPasswordInputSize)
		}
		password = bytes.TrimSuffix(input, []byte{'\n'})
		password = bytes.TrimSuffix(password, []byte{'\r'})
	}
	defer clear(password)

	stored, err := auth.HashPasswordSMPBKDF2(password, *iterations, nil)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(stored))
	return err
}

func runExport(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "source database path")
	ldifPath := flags.String("ldif", "-", "destination LDIF path, or - for stdout")
	database := flags.String(
		"database",
		"",
		"OpenLDAP database index, olcDatabase value, or config entry DN",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	store, err := storage.OpenBolt(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	options := migration.ExportOptions{Database: *database}
	if *ldifPath == "-" {
		result, err := migration.ExportLDIFWithOptions(
			context.Background(),
			store,
			stdout,
			options,
		)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stderr, "exported %d entries\n", result.Entries)
		return err
	}
	return exportToFile(store, *ldifPath, stderr, options)
}

func exportToFile(
	store storage.Store,
	path string,
	stderr io.Writer,
	options migration.ExportOptions,
) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".ldap-go-export-*")
	if err != nil {
		return fmt.Errorf("create temporary export: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	result, exportErr := migration.ExportLDIFWithOptions(
		context.Background(),
		store,
		temp,
		options,
	)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if exportErr != nil {
		return exportErr
	}
	if syncErr != nil {
		return fmt.Errorf("sync export: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close export: %w", closeErr)
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return fmt.Errorf("secure export permissions: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish export: %w", err)
	}
	_, err = fmt.Fprintf(stderr, "exported %d entries to %s\n", result.Entries, path)
	return err
}

func runImport(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "destination database path")
	ldifPath := flags.String("ldif", "-", "slapcat LDIF path, or - for stdin")
	replace := flags.Bool("replace", false, "atomically replace existing directory content")
	database := flags.String(
		"database",
		"",
		"OpenLDAP database index, olcDatabase value, or config entry DN",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	reader := stdin
	var file *os.File
	if *ldifPath != "-" {
		var err error
		file, err = os.Open(*ldifPath)
		if err != nil {
			return fmt.Errorf("open LDIF: %w", err)
		}
		defer file.Close()
		reader = file
	}

	store, err := storage.OpenBolt(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	result, err := migration.ImportLDIF(
		context.Background(),
		store,
		reader,
		migration.ImportOptions{
			Replace:  *replace,
			Database: *database,
		},
	)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		stdout,
		"imported %d entries; naming contexts: %s\n",
		result.Entries,
		strings.Join(result.NamingContexts, ", "),
	)
	return err
}

func runServe(
	args []string,
	stdout, stderr io.Writer,
	getenv func(string) string,
) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "directory database path")
	listenAddress := flags.String("listen", "127.0.0.1:1389", "LDAP listen address")
	rootDN := flags.String("root-dn", "", "optional database root DN override")
	maxMessageSize := flags.Int64("max-message-size", 16<<20, "maximum BER message size in bytes")
	searchLimit := flags.Int("search-limit", 1000, "server-side maximum entries per search")
	logLevel := flags.String("log-level", "info", "debug, info, warn, or error")
	tlsCertificate := flags.String("tls-cert", "", "PEM server certificate for StartTLS or LDAPS")
	tlsPrivateKey := flags.String("tls-key", "", "PEM private key for StartTLS or LDAPS")
	implicitTLS := flags.Bool("ldaps", false, "negotiate TLS before reading LDAP messages")
	tlcpSignCertificate := flags.String(
		"tlcp-sign-cert",
		"",
		"PEM TLCP signing certificate",
	)
	tlcpSignPrivateKey := flags.String("tlcp-sign-key", "", "PEM TLCP signing private key")
	tlcpEncryptionCertificate := flags.String(
		"tlcp-enc-cert",
		"",
		"PEM TLCP encryption certificate",
	)
	tlcpEncryptionPrivateKey := flags.String(
		"tlcp-enc-key",
		"",
		"PEM TLCP encryption private key",
	)
	implicitTLCP := flags.Bool("tlcp-implicit", false, "negotiate TLCP before LDAP messages")
	secureHandshakeTimeout := 10 * time.Second
	flags.DurationVar(
		&secureHandshakeTimeout,
		"secure-handshake-timeout",
		secureHandshakeTimeout,
		"maximum TLS or TLCP handshake duration",
	)
	flags.DurationVar(
		&secureHandshakeTimeout,
		"tls-handshake-timeout",
		secureHandshakeTimeout,
		"alias for -secure-handshake-timeout",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	tlsConfig, err := loadServerTLSConfig(*tlsCertificate, *tlsPrivateKey)
	if err != nil {
		return err
	}
	tlcpTransport, err := loadServerTLCP(
		*tlcpSignCertificate,
		*tlcpSignPrivateKey,
		*tlcpEncryptionCertificate,
		*tlcpEncryptionPrivateKey,
	)
	if err != nil {
		return err
	}
	if tlsConfig != nil && tlcpTransport != nil {
		return errors.New("standard TLS and TLCP certificate options are mutually exclusive")
	}
	if *implicitTLCP && tlcpTransport == nil {
		return errors.New("-tlcp-implicit requires all four TLCP certificate/key options")
	}
	if *implicitTLS {
		if tlcpTransport != nil {
			return errors.New("use -tlcp-implicit instead of -ldaps with TLCP")
		}
		if tlsConfig == nil {
			return errors.New("-ldaps requires -tls-cert and -tls-key")
		}
	}
	if (tlsConfig != nil || tlcpTransport != nil) && secureHandshakeTimeout <= 0 {
		return errors.New("-secure-handshake-timeout must be positive")
	}

	store, err := storage.OpenBolt(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	instance, err := server.New(server.Config{
		Store:                  store,
		MaxMessageSize:         *maxMessageSize,
		MaxSearchEntries:       *searchLimit,
		RootDN:                 *rootDN,
		RootPassword:           []byte(getenv(rootPasswordEnvironment)),
		Logger:                 logger,
		TLSConfig:              tlsConfig,
		SecureTransport:        tlcpTransport,
		ImplicitTLS:            *implicitTLS || *implicitTLCP,
		SecureHandshakeTimeout: secureHandshakeTimeout,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddress, err)
	}
	defer listener.Close()

	scheme := "ldap"
	if *implicitTLS {
		scheme = "ldaps"
	} else if *implicitTLCP {
		scheme = "ldap+tlcp"
	}
	if _, err := fmt.Fprintf(stdout, "ldap-go listening on %s://%s\n", scheme, listener.Addr()); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return instance.Serve(ctx, listener)
}

func loadServerTLSConfig(certificateFile, privateKeyFile string) (*tls.Config, error) {
	if certificateFile == "" && privateKeyFile == "" {
		return nil, nil
	}
	if certificateFile == "" || privateKeyFile == "" {
		return nil, errors.New("-tls-cert and -tls-key must be provided together")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func loadServerTLCP(
	signCertificateFile,
	signPrivateKeyFile,
	encryptionCertificateFile,
	encryptionPrivateKeyFile string,
) (*gmtransport.TLCP, error) {
	if signCertificateFile == "" &&
		signPrivateKeyFile == "" &&
		encryptionCertificateFile == "" &&
		encryptionPrivateKeyFile == "" {
		return nil, nil
	}
	return gmtransport.LoadTLCP(
		signCertificateFile,
		signPrivateKeyFile,
		encryptionCertificateFile,
		encryptionPrivateKeyFile,
	)
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		if numeric, err := strconv.Atoi(value); err == nil {
			return slog.Level(numeric), nil
		}
		return 0, errors.New("log level must be debug, info, warn, error, or an integer")
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `usage: ldap-go <command> [options]

commands:
  import   atomically import slapcat-compatible LDIF
  export   atomically export a directory database as LDIF
  passwd   generate a PBKDF2-SM3 userPassword value
  serve    serve the persistent directory over LDAP
  version  print the build version`)
}
