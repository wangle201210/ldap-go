package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const rootPasswordEnvironment = "LDAP_GO_ROOT_PASSWORD"

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

func runImport(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "destination database path")
	ldifPath := flags.String("ldif", "-", "slapcat LDIF path, or - for stdin")
	replace := flags.Bool("replace", false, "atomically replace existing directory content")
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
		migration.ImportOptions{Replace: *replace},
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
	rootDN := flags.String("root-dn", "", "optional root DN")
	maxMessageSize := flags.Int64("max-message-size", 16<<20, "maximum BER message size in bytes")
	searchLimit := flags.Int("search-limit", 1000, "server-side maximum entries per search")
	logLevel := flags.String("log-level", "info", "debug, info, warn, or error")
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

	store, err := storage.OpenBolt(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	instance, err := server.New(server.Config{
		Store:            store,
		MaxMessageSize:   *maxMessageSize,
		MaxSearchEntries: *searchLimit,
		RootDN:           *rootDN,
		RootPassword:     []byte(getenv(rootPasswordEnvironment)),
		Logger:           logger,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddress, err)
	}
	defer listener.Close()

	if _, err := fmt.Fprintf(stdout, "ldap-go listening on ldap://%s\n", listener.Addr()); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return instance.Serve(ctx, listener)
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
  import   atomically import slapcat-compatible content LDIF
  serve    serve the persistent directory over LDAP
  version  print the build version`)
}
