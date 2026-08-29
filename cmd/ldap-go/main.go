package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/gmtransport"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	rootPasswordEnvironment = "LDAP_GO_ROOT_PASSWORD"
	passwordEnvironment     = "LDAP_GO_PASSWORD"
	auditKeyEnvironment     = "LDAP_GO_AUDIT_KEY"
	maxPasswordInputSize    = 1 << 20
)

var version = "dev"

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

func runMain(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	getenv func(string) string,
) int {
	shutdownSignals := mainShutdownSignals()
	var management chan os.Signal
	if len(args) != 0 && args[0] == "serve" {
		shutdownSignals = serveShutdownSignals()
		if signals := serveManagementSignals(); len(signals) != 0 {
			management = make(chan os.Signal, 2)
			signal.Notify(management, signals...)
			defer signal.Stop(management)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()
	return runWithContextAndSignals(
		ctx,
		management,
		args,
		stdin,
		stdout,
		stderr,
		getenv,
	)
}

func run(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	getenv func(string) string,
) int {
	return runWithContext(context.Background(), args, stdin, stdout, stderr, getenv)
}

func runWithContext(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	getenv func(string) string,
) int {
	return runWithContextAndSignals(ctx, nil, args, stdin, stdout, stderr, getenv)
}

func runWithContextAndSignals(
	ctx context.Context,
	management <-chan os.Signal,
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
	case "audit-verify":
		err = runAuditVerify(args[1:], stdout, stderr, getenv)
	case "backup":
		err = runBackup(ctx, args[1:], stdout, stderr)
	case "online-backup":
		err = runOnlineBackup(args[1:], stdin, stdout, stderr)
	case "production-check":
		err = runProductionCheck(args[1:], stdout, stderr)
	case "check":
		err = runCheck(args[1:], stdout, stderr)
	case "health":
		err = runHealth(args[1:], stdin, stdout, stderr)
	case "config-test", "slaptest":
		err = runConfigurationTest(args[0], args[1:], stdout, stderr)
	case "dn", "slapdn":
		err = runDN(args[0], args[1:], stdout, stderr)
	case "import", "slapadd":
		err = runImport(args[0], args[1:], stdin, stdout, stderr)
	case "slapauth":
		err = runSlapAuth(args[1:], stdout, stderr)
	case "slapschema":
		err = runSlapSchema(args[1:], stdout, stderr)
	case "slapmodify":
		err = runSlapModify(args[1:], stdin, stdout, stderr)
	case "ldapsearch":
		err = runLDAPSearch(args[1:], stdin, stdout, stderr)
	case "ldapwhoami":
		err = runLDAPWhoAmI(args[1:], stdin, stdout, stderr)
	case "ldapcompare":
		err = runLDAPCompare(args[1:], stdin, stdout, stderr)
	case "ldappasswd":
		err = runLDAPPasswd(args[1:], stdin, stdout, stderr)
	case "ldapexop":
		err = runLDAPExop(args[1:], stdin, stdout, stderr)
	case "ldapmodify", "ldapadd":
		err = runLDAPModify(args[0], args[1:], stdin, stdout, stderr)
	case "ldapdelete":
		err = runLDAPDelete(args[1:], stdin, stdout, stderr)
	case "ldapmodrdn":
		err = runLDAPModRDN(args[1:], stdin, stdout, stderr)
	case "lloadd":
		err = runLloadd(args[1:], stdout, stderr)
	case "export", "slapcat":
		err = runExport(args[0], args[1:], stdout, stderr)
	case "passwd", "slappasswd":
		err = runPassword(args[0], args[1:], stdin, stdout, stderr, getenv)
	case "rebuild", "reindex", "slapindex":
		err = runRebuild(args[0], args[1:], stdout, stderr)
	case "restore":
		err = runRestore(ctx, args[1:], stdout, stderr)
	case "serve":
		err = runServe(ctx, management, args[1:], stdout, stderr, getenv)
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
		if exitCode, cause, ok := ldapClientExitStatus(err); ok {
			if cause != nil {
				fmt.Fprintln(stderr, "error:", cause)
			}
			return exitCode
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func runDN(
	command string,
	args []string,
	stdout, stderr io.Writer,
) (runErr error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	normalizedOnly := flags.Bool("N", false, "print normalized DNs")
	prettyOnly := flags.Bool("P", false, "print pretty DNs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *normalizedOnly && *prettyOnly {
		return errors.New("-N and -P are mutually exclusive")
	}
	if flags.NArg() == 0 {
		return errors.New("at least one DN is required")
	}

	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, store.Close())
	}()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		return fmt.Errorf("initialize built-in schema: %w", err)
	}
	if _, err := schema.LoadOpenLDAPConfig(
		context.Background(),
		store,
		registry,
	); err != nil {
		return fmt.Errorf("load cn=config schema: %w", err)
	}

	for _, rawDN := range flags.Args() {
		pretty, normalized, err := formatLDAPDN(registry, rawDN)
		if err != nil {
			return fmt.Errorf("DN <%s> check failed: %w", rawDN, err)
		}
		switch {
		case *prettyOnly:
			_, err = fmt.Fprintln(stdout, pretty)
		case *normalizedOnly:
			_, err = fmt.Fprintln(stdout, normalized)
		default:
			_, err = fmt.Fprintf(
				stdout,
				"DN: <%s> check succeeded\nnormalized: <%s>\npretty:     <%s>\n",
				rawDN,
				normalized,
				pretty,
			)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func formatLDAPDN(
	registry *schema.Registry,
	raw string,
) (pretty, normalized string, err error) {
	parsed, err := ldap.ParseDN(raw)
	if err != nil {
		return "", "", err
	}
	prettyRDNs := make([]string, 0, len(parsed.RDNs))
	normalizedRDNs := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		prettyValues := make([]string, 0, len(rdn.Attributes))
		normalizedValues := make([]string, 0, len(rdn.Attributes))
		for _, value := range rdn.Attributes {
			if value.Value == "" {
				return "", "", fmt.Errorf(
					"attribute %q has an empty DN assertion value",
					value.Type,
				)
			}
			attribute, found := registry.AttributeType(value.Type)
			if !found {
				return "", "", fmt.Errorf(
					"undefined attribute type %q",
					value.Type,
				)
			}
			if err := registry.ValidateAttributeValue(
				value.Type,
				[]byte(value.Value),
			); err != nil {
				return "", "", err
			}
			normalizedValue, err := registry.NormalizeEqualityValue(
				value.Type,
				[]byte(value.Value),
			)
			if err != nil {
				return "", "", fmt.Errorf("%s: %w", attribute.Name(), err)
			}
			prettyValues = append(
				prettyValues,
				attribute.Name()+"="+escapeLDAPDNValue(value.Value),
			)
			normalizedValues = append(
				normalizedValues,
				attribute.Name()+"="+escapeLDAPDNValue(string(normalizedValue)),
			)
		}
		sort.Strings(prettyValues)
		sort.Strings(normalizedValues)
		prettyRDNs = append(prettyRDNs, strings.Join(prettyValues, "+"))
		normalizedRDNs = append(normalizedRDNs, strings.Join(normalizedValues, "+"))
	}
	return strings.Join(prettyRDNs, ","), strings.Join(normalizedRDNs, ","), nil
}

func escapeLDAPDNValue(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	validUTF8 := utf8.ValidString(value)
	var escaped strings.Builder
	escaped.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case (index == 0 && (character == ' ' || character == '#')) ||
			(index == len(value)-1 && character == ' ') ||
			strings.ContainsRune("\"+,;<>\\", rune(character)):
			escaped.WriteByte('\\')
			escaped.WriteByte(character)
		case character < 0x20 || character == 0x7f ||
			(character >= utf8.RuneSelf && !validUTF8):
			escaped.WriteByte('\\')
			escaped.WriteByte(hexadecimal[character>>4])
			escaped.WriteByte(hexadecimal[character&0x0f])
		default:
			escaped.WriteByte(character)
		}
	}
	return escaped.String()
}

func runConfigurationTest(
	command string,
	args []string,
	stdout, stderr io.Writer,
) (runErr error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	quiet := flags.Bool("Q", false, "suppress successful output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, store.Close())
	}()
	summary, err := server.ValidateConfiguration(
		context.Background(),
		server.Config{Store: store},
	)
	if err != nil {
		return err
	}
	if *quiet {
		return nil
	}
	_, err = fmt.Fprintf(
		stdout,
		"configuration OK: %d databases, %d overlays, %d syncrepl consumers; "+
			"schema: %d attribute types, %d object classes, %d DIT content rules; "+
			"ACL: %d rules; SASL authz: %d rules\n",
		summary.Databases,
		summary.Overlays,
		summary.SyncreplConsumers,
		summary.AttributeTypes,
		summary.ObjectClasses,
		summary.DITContentRules,
		summary.ACLRules,
		summary.SASLAuthzRules,
	)
	return err
}

func runBackup(ctx context.Context, args []string, stdout, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "source database path")
	backupPath := flags.String("out", "", "destination backup path")
	replace := flags.Bool("replace", false, "replace an existing backup")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *backupPath == "" {
		return errors.New("-out is required")
	}
	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, store.Close())
	}()
	report, err := store.Backup(ctx, *backupPath, *replace)
	if err != nil {
		return err
	}
	return printMaintenanceReport(stdout, "backed up", *backupPath, report)
}

func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	backupPath := flags.String("backup", "", "source backup path")
	databasePath := flags.String("db", "data/ldap-go.db", "destination database path")
	replace := flags.Bool("replace", false, "replace an existing database")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *backupPath == "" {
		return errors.New("-backup is required")
	}
	report, err := restoreBoltValidated(
		ctx,
		*backupPath,
		*databasePath,
		*replace,
	)
	if err != nil {
		return err
	}
	return printMaintenanceReport(stdout, "restored", *databasePath, report)
}

func runCheck(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	report, err := storage.CheckBolt(context.Background(), *databasePath)
	if err != nil {
		return err
	}
	return printMaintenanceReport(stdout, "checked", *databasePath, report)
}

func runRebuild(command string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "database path")
	var database, suffix, configFile, configDirectory string
	var databaseNumber int
	var disableSubordinateGlue, quick bool
	if command == "slapindex" {
		flags.StringVar(&database, "database", "", "OpenLDAP database selector")
		flags.StringVar(&suffix, "b", "", "select a database by suffix")
		databaseNumber = -1
		flags.IntVar(&databaseNumber, "n", -1, "select a database by number")
		flags.StringVar(&configFile, "f", "", "unsupported OpenLDAP slapd.conf path")
		flags.StringVar(&configDirectory, "F", "", "unsupported OpenLDAP config directory")
		registerUnsupportedBool(flags, "c", "continue after index errors")
		flags.BoolVar(&disableSubordinateGlue, "g", false, "disable subordinate gluing")
		flags.BoolVar(&quick, "q", false, "commit index rebuilds in quick mode")
		registerUnsupportedBool(flags, "t", "truncate attribute indexes")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if command == "slapindex" {
		if err := rejectUnsupportedFlags(command, flags, []unsupportedFlag{
			{name: "f", reason: "ldap-go loads cn=config from -db and cannot consume slapd.conf"},
			{name: "F", reason: "ldap-go loads cn=config from -db and cannot consume an OpenLDAP config directory"},
			{name: "c", reason: "the atomic rebuild stops on the first error"},
			{name: "t", reason: "each partition index is already truncated and rebuilt atomically"},
		}); err != nil {
			return err
		}
		selected, err := resolveOfflineDatabaseSelection(
			command,
			flags,
			*databasePath,
			database,
			suffix,
			databaseNumber,
			"",
		)
		if err != nil {
			return err
		}
		store, err := storage.OpenBolt(*databasePath)
		if err != nil {
			return err
		}
		defer store.Close()
		count, err := server.ReindexOfflineSelected(
			context.Background(), store, server.OfflineReindexOptions{
				Database: selected, IncludeSubordinates: !disableSubordinateGlue,
				Attributes: flags.Args(), Quick: quick,
			},
		)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "reindexed %d database(s)\n", count)
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	report, err := storage.RebuildBolt(context.Background(), *databasePath)
	if err != nil {
		return err
	}
	return printMaintenanceReport(stdout, "rebuilt", *databasePath, report)
}

type unsupportedFlag struct {
	name   string
	reason string
}

func registerUnsupportedBool(flags *flag.FlagSet, name, description string) {
	flags.Bool(name, false, "unsupported: "+description)
}

func rejectUnsupportedFlags(
	command string,
	flags *flag.FlagSet,
	unsupported []unsupportedFlag,
) error {
	for _, option := range unsupported {
		if flagWasSet(flags, option.name) {
			return fmt.Errorf(
				"%s option -%s is not supported: %s",
				command,
				option.name,
				option.reason,
			)
		}
	}
	return nil
}

func flagWasSet(flags *flag.FlagSet, name string) bool {
	found := false
	flags.Visit(func(candidate *flag.Flag) {
		if candidate.Name == name {
			found = true
		}
	})
	return found
}

func printMaintenanceReport(
	writer io.Writer,
	action,
	path string,
	report storage.CheckReport,
) error {
	_, err := fmt.Fprintf(
		writer,
		"%s %d entries in %d partitions with %d metadata records (%d bytes): %s\n",
		action,
		report.Entries,
		len(report.Partitions),
		report.Metadata,
		report.FileSize,
		path,
	)
	return err
}

func runPassword(
	command string,
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	getenv func(string) string,
) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	iterations := flags.Int(
		"iterations",
		auth.DefaultSMPBKDF2Iterations,
		"PBKDF2-SM3 iteration count",
	)
	scheme := auth.SMPBKDF2HashScheme
	var directSecret secretFlagValue
	var generate, omitNewline, rfc2307 bool
	var cryptSaltFormat, passwordFile string
	if command == "slappasswd" {
		scheme = auth.OpenLDAPDefaultHashScheme
		flags.StringVar(&scheme, "h", scheme, "RFC 2307 password scheme")
		flags.Var(&directSecret, "s", "password to hash")
		flags.BoolVar(&generate, "g", false, "generate a random cleartext password")
		flags.BoolVar(&omitNewline, "n", false, "omit the trailing newline")
		flags.BoolVar(&rfc2307, "u", true, "generate an RFC 2307 value")
		flags.StringVar(&passwordFile, "T", "", "read the password from a file")
		flags.StringVar(&cryptSaltFormat, "c", "", "crypt(3) salt format")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	defer directSecret.clear()
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if command == "slappasswd" {
		if flagWasSet(flags, "c") {
			if flagWasSet(flags, "h") {
				return errors.New("slappasswd options -c and -h are mutually exclusive")
			}
			scheme = auth.OpenLDAPCryptHashScheme
		}
		if flagWasSet(flags, "u") && !rfc2307 {
			return errors.New(
				"slappasswd option -u=false is not supported: output is always RFC 2307",
			)
		}
		if flagWasSet(flags, "g") && !generate {
			return errors.New("slappasswd option -g=false is not supported")
		}
		if flagWasSet(flags, "n") && !omitNewline {
			return errors.New("slappasswd option -n=false is not supported")
		}
		sources := 0
		for _, name := range []string{"g", "s", "T"} {
			if flagWasSet(flags, name) {
				sources++
			}
		}
		if sources > 1 {
			return errors.New("slappasswd options -g, -s, and -T are mutually exclusive")
		}
		if directSecret.count > 1 {
			return errors.New("slappasswd password was provided more than once")
		}
		if generate && flagWasSet(flags, "h") {
			return errors.New("slappasswd options -g and -h are mutually exclusive")
		}
		if generate && flagWasSet(flags, "iterations") {
			return errors.New("slappasswd options -g and -iterations are mutually exclusive")
		}
	}

	if generate {
		password, err := generateRandomPassword()
		if err != nil {
			return err
		}
		defer clear(password)
		return writePasswordOutput(stdout, password, omitNewline)
	}

	var password []byte
	var err error
	switch {
	case flagWasSet(flags, "s"):
		password = directSecret.take()
	case flagWasSet(flags, "T"):
		password, err = readPasswordFile(passwordFile)
	default:
		if environmentPassword := getenv(passwordEnvironment); environmentPassword != "" {
			password = []byte(environmentPassword)
		} else {
			password, err = readPasswordInput(stdin, true, "password")
		}
	}
	if err != nil {
		return err
	}
	defer clear(password)

	normalizedScheme, err := auth.NormalizePasswordHashScheme(scheme)
	if err != nil {
		return err
	}
	var stored []byte
	if normalizedScheme == auth.SMPBKDF2HashScheme {
		stored, err = auth.HashPasswordSMPBKDF2(password, *iterations, nil)
	} else if normalizedScheme == auth.OpenLDAPCryptHashScheme &&
		flagWasSet(flags, "c") {
		if flagWasSet(flags, "iterations") {
			return fmt.Errorf(
				"-iterations is only valid with %s",
				auth.SMPBKDF2HashScheme,
			)
		}
		stored, err = auth.HashPasswordOpenLDAPCrypt(password, cryptSaltFormat, nil)
	} else {
		if flagWasSet(flags, "iterations") {
			return fmt.Errorf(
				"-iterations is only valid with %s",
				auth.SMPBKDF2HashScheme,
			)
		}
		stored, err = auth.HashPassword(password, normalizedScheme, nil)
	}
	if err != nil {
		return err
	}
	defer clear(stored)
	return writePasswordOutput(stdout, stored, omitNewline)
}

type secretFlagValue struct {
	value []byte
	count int
}

func (value *secretFlagValue) String() string {
	return ""
}

func (value *secretFlagValue) Set(secret string) error {
	clear(value.value)
	value.value = []byte(secret)
	value.count++
	return nil
}

func (value *secretFlagValue) take() []byte {
	secret := value.value
	value.value = nil
	return secret
}

func (value *secretFlagValue) clear() {
	clear(value.value)
	value.value = nil
	value.count = 0
}

func readPasswordFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open password file: %w", err)
	}
	defer file.Close()
	return readPasswordInput(file, false, "password file")
}

func readPasswordInput(reader io.Reader, trimLineEnding bool, source string) ([]byte, error) {
	input, err := io.ReadAll(io.LimitReader(reader, maxPasswordInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if len(input) > maxPasswordInputSize {
		clear(input)
		return nil, fmt.Errorf("%s exceeds %d bytes", source, maxPasswordInputSize)
	}
	if trimLineEnding {
		for len(input) > 0 && (input[len(input)-1] == '\n' || input[len(input)-1] == '\r') {
			input[len(input)-1] = 0
			input = input[:len(input)-1]
		}
	}
	return input, nil
}

func generateRandomPassword() ([]byte, error) {
	random := make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, fmt.Errorf("generate random password: %w", err)
	}
	defer clear(random)
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(random)))
	base64.RawStdEncoding.Encode(encoded, random)
	return encoded, nil
}

func writePasswordOutput(writer io.Writer, password []byte, omitNewline bool) error {
	written, err := writer.Write(password)
	if err != nil {
		return err
	}
	if written != len(password) {
		return io.ErrShortWrite
	}
	if omitNewline {
		return nil
	}
	_, err = io.WriteString(writer, "\n")
	return err
}

func runExport(command string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "source database path")
	ldifPath := flags.String("ldif", "-", "destination LDIF path, or - for stdout")
	database := flags.String(
		"database",
		"",
		"OpenLDAP database index, olcDatabase value, or config entry DN",
	)
	var openLDAPLDIFPath, suffix, subtree string
	var disableSubordinateGlue bool
	databaseNumber := -1
	if command == "slapcat" {
		flags.StringVar(&openLDAPLDIFPath, "l", "", "destination LDIF path")
		flags.StringVar(&suffix, "b", "", "select the database containing this suffix")
		flags.IntVar(&databaseNumber, "n", -1, "select a database by number")
		flags.StringVar(&subtree, "s", "", "export only this subtree")
		registerUnsupportedBool(flags, "c", "continue after export errors")
		flags.BoolVar(&disableSubordinateGlue, "g", false, "disable subordinate gluing")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if command == "slapcat" {
		if err := rejectUnsupportedFlags(command, flags, []unsupportedFlag{
			{name: "c", reason: "the structured export stops on the first error"},
		}); err != nil {
			return err
		}
		if flagWasSet(flags, "l") && flagWasSet(flags, "ldif") {
			return errors.New("slapcat options -l and -ldif are mutually exclusive")
		}
		if flagWasSet(flags, "l") {
			*ldifPath = openLDAPLDIFPath
		}
		if flagWasSet(flags, "s") && strings.TrimSpace(subtree) == "" {
			return errors.New("slapcat option -s requires a non-empty subtree DN")
		}
	}
	selectedDatabase, err := resolveOfflineDatabaseSelection(
		command,
		flags,
		*databasePath,
		*database,
		suffix,
		databaseNumber,
		subtree,
	)
	if err != nil {
		return err
	}

	store, err := storage.OpenBoltReadOnly(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	options := migration.ExportOptions{
		Database:              selectedDatabase,
		SelectDefaultDatabase: command == "slapcat",
		IncludeSubordinates:   command == "slapcat" && !disableSubordinateGlue,
	}
	if *ldifPath == "-" {
		result, err := exportLDIFWithSubtree(
			context.Background(),
			store,
			stdout,
			options,
			subtree,
		)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stderr, "exported %d entries\n", result.Entries)
		return err
	}
	return exportToFile(store, *ldifPath, stderr, options, subtree)
}

func exportToFile(
	store storage.Store,
	path string,
	stderr io.Writer,
	options migration.ExportOptions,
	subtree string,
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

	result, exportErr := exportLDIFWithSubtree(
		context.Background(),
		store,
		temp,
		options,
		subtree,
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

func exportLDIFWithSubtree(
	ctx context.Context,
	store storage.Store,
	writer io.Writer,
	options migration.ExportOptions,
	subtree string,
) (migration.ExportResult, error) {
	if strings.TrimSpace(subtree) == "" {
		return migration.ExportLDIFWithOptions(ctx, store, writer, options)
	}
	base, err := directory.ParseDN(subtree)
	if err != nil || base.Depth() == 0 {
		if err == nil {
			err = errors.New("subtree DN must not be empty")
		}
		return migration.ExportResult{}, fmt.Errorf("invalid slapcat subtree %q: %w", subtree, err)
	}

	type exportOutcome struct {
		result migration.ExportResult
		err    error
	}
	reader, pipeWriter := io.Pipe()
	done := make(chan exportOutcome, 1)
	go func() {
		result, exportErr := migration.ExportLDIFWithOptions(
			ctx,
			store,
			pipeWriter,
			options,
		)
		_ = pipeWriter.CloseWithError(exportErr)
		done <- exportOutcome{result: result, err: exportErr}
	}()

	fail := func(filterErr error) (migration.ExportResult, error) {
		_ = reader.CloseWithError(filterErr)
		outcome := <-done
		if outcome.err != nil {
			return migration.ExportResult{}, outcome.err
		}
		return migration.ExportResult{}, filterErr
	}

	selected := 0
	document := &ldif.LDIF{}
	for record, parseErr := range ldif.UnmarshalEntries(reader, document) {
		if parseErr != nil {
			return fail(fmt.Errorf("parse generated LDIF: %w", parseErr))
		}
		if record == nil || record.Entry == nil {
			return fail(errors.New("generated LDIF contains a non-entry record"))
		}
		entryDN, err := directory.ParseDN(record.Entry.DN)
		if err != nil {
			return fail(fmt.Errorf("parse exported DN %q: %w", record.Entry.DN, err))
		}
		if !base.Equal(entryDN) && !base.AncestorOf(entryDN) {
			continue
		}
		if err := ldif.Dump(writer, 76, record.Entry); err != nil {
			return fail(fmt.Errorf("export %q: %w", record.Entry.DN, err))
		}
		selected++
	}
	_ = reader.Close()
	outcome := <-done
	if outcome.err != nil {
		return migration.ExportResult{}, outcome.err
	}
	return migration.ExportResult{Entries: selected}, nil
}

func runImport(command string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "destination database path")
	ldifPath := flags.String("ldif", "-", "slapcat LDIF path, or - for stdin")
	replace := flags.Bool("replace", false, "atomically replace existing directory content")
	database := flags.String(
		"database",
		"",
		"OpenLDAP database index, olcDatabase value, or config entry DN",
	)
	var openLDAPLDIFPath, suffix string
	var continueOnError, dryRun, quickMode, skipSchemaValidation bool
	var updateContextCSN, disableSubordinateGlue bool
	var valueCheckExplicit, valueCheckEnabled bool
	skipValueValidation := command == "slapadd"
	databaseNumber := -1
	csnServerID := 0
	if command == "slapadd" {
		flags.StringVar(&openLDAPLDIFPath, "l", "", "source LDIF path")
		flags.StringVar(&suffix, "b", "", "select the database containing this suffix")
		flags.IntVar(&databaseNumber, "n", -1, "select a database by number")
		flags.BoolVar(&dryRun, "u", false, "validate without modifying the database")
		flags.IntVar(&csnServerID, "S", 0, "server ID for generated entryCSN values")
		flags.BoolVar(&updateContextCSN, "w", false, "update the suffix contextCSN")
		flags.BoolVar(&continueOnError, "c", false, "continue after import errors")
		flags.BoolVar(&disableSubordinateGlue, "g", false, "disable subordinate gluing")
		flags.BoolVar(&quickMode, "q", false, "skip value checks")
		flags.BoolVar(&skipSchemaValidation, "s", false, "disable schema checking")
		flags.Func("o", "set slapadd tool option", func(raw string) error {
			name, value, found := strings.Cut(raw, "=")
			if !found || strings.TrimSpace(name) == "" {
				return fmt.Errorf("invalid slapadd option %q; expected name=yes|no", raw)
			}
			enabled := false
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "yes":
				enabled = true
			case "no":
			default:
				return fmt.Errorf("invalid slapadd option %q; value must be yes or no", raw)
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "schema-check":
				skipSchemaValidation = !enabled
			case "value-check":
				valueCheckExplicit = true
				valueCheckEnabled = enabled
				skipValueValidation = !enabled
			default:
				return fmt.Errorf("unsupported slapadd option %q", name)
			}
			return nil
		})
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if command == "slapadd" {
		if flagWasSet(flags, "l") && flagWasSet(flags, "ldif") {
			return errors.New("slapadd options -l and -ldif are mutually exclusive")
		}
		if flagWasSet(flags, "l") {
			*ldifPath = openLDAPLDIFPath
		}
		if flagWasSet(flags, "u") && !dryRun {
			return errors.New("slapadd option -u=false is not supported")
		}
		if flagWasSet(flags, "c") && !continueOnError {
			return errors.New("slapadd option -c=false is not supported")
		}
		if flagWasSet(flags, "q") && !quickMode {
			return errors.New("slapadd option -q=false is not supported")
		}
		if csnServerID < 0 || csnServerID > 0x0fff {
			return fmt.Errorf("slapadd server ID must be between 0 and %d", 0x0fff)
		}
		if quickMode {
			if valueCheckExplicit && valueCheckEnabled {
				if _, err := fmt.Fprintln(
					stderr,
					"slapadd: value-check incompatible with quick mode; disabled.",
				); err != nil {
					return err
				}
			}
			skipValueValidation = true
		}
	}
	selectedDatabase, err := resolveOfflineDatabaseSelection(
		command,
		flags,
		*databasePath,
		*database,
		suffix,
		databaseNumber,
		"",
	)
	if err != nil {
		return err
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

	effectiveDatabasePath := *databasePath
	cleanup := func() {}
	if dryRun {
		effectiveDatabasePath, cleanup, err = prepareDryRunDatabase(*databasePath)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	store, err := storage.OpenBolt(effectiveDatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	importOptions := migration.ImportOptions{
		Replace:                       *replace,
		Database:                      selectedDatabase,
		SelectDefaultDatabase:         command == "slapadd",
		DisableSubordinateGlue:        disableSubordinateGlue,
		DryRun:                        dryRun,
		SkipSchemaValidation:          skipSchemaValidation,
		SkipValueValidation:           skipValueValidation,
		RequireObjectClass:            command == "slapadd",
		ValidateConfigurationEntries:  command == "slapadd",
		GenerateOperationalAttributes: command == "slapadd",
		CSNServerID:                   uint16(csnServerID),
		UpdateContextCSN:              updateContextCSN && !dryRun,
	}
	if command == "slapadd" {
		importOptions.ValidateTransaction = func(reader storage.Reader) error {
			_, err := server.ValidateConfigurationReader(
				context.Background(),
				server.Config{},
				reader,
			)
			return err
		}
	}
	var result migration.ImportResult
	continuedFailures := 0
	if continueOnError {
		continueOptions := importOptions
		// The dry-run destination is already an isolated copy. Committing each
		// successful record there is necessary for child dependency checks.
		continueOptions.DryRun = false
		continued, err := migration.ImportLDIFContinue(
			context.Background(),
			store,
			reader,
			continueOptions,
		)
		if err != nil {
			return err
		}
		result = continued.ImportResult
		continuedFailures = len(continued.Failures)
		for _, failure := range continued.Failures {
			identity := ""
			if failure.DN != "" {
				identity = fmt.Sprintf(" dn=%q", failure.DN)
			}
			if _, err := fmt.Fprintf(
				stderr,
				"slapadd: line %d:%s %v\n",
				failure.Line,
				identity,
				failure.Err,
			); err != nil {
				return err
			}
		}
	} else {
		var err error
		result, err = migration.ImportLDIF(
			context.Background(),
			store,
			reader,
			importOptions,
		)
		if err != nil {
			return err
		}
	}
	action := "imported"
	if dryRun {
		action = "validated"
	}
	_, err = fmt.Fprintf(
		stdout,
		"%s %d entries; naming contexts: %s\n",
		action,
		result.Entries,
		strings.Join(result.NamingContexts, ", "),
	)
	if err != nil {
		return err
	}
	if continuedFailures > 0 {
		return fmt.Errorf(
			"slapadd completed with %d record errors; %d entries retained",
			continuedFailures,
			result.Entries,
		)
	}
	return nil
}

func prepareDryRunDatabase(databasePath string) (string, func(), error) {
	directoryPath, err := os.MkdirTemp("", "ldap-go-slapadd-")
	if err != nil {
		return "", nil, fmt.Errorf("create slapadd dry-run directory: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(directoryPath)
	}
	temporaryPath := filepath.Join(directoryPath, "directory.db")
	if _, err := os.Stat(databasePath); err == nil {
		if _, err := storage.BackupBolt(
			context.Background(),
			databasePath,
			temporaryPath,
			false,
		); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("prepare slapadd dry run: %w", err)
		}
	} else if !os.IsNotExist(err) {
		cleanup()
		return "", nil, fmt.Errorf("inspect destination database: %w", err)
	}
	return temporaryPath, cleanup, nil
}

func resolveOfflineDatabaseSelection(
	command string,
	flags *flag.FlagSet,
	databasePath,
	nativeSelector,
	suffix string,
	databaseNumber int,
	subtree string,
) (string, error) {
	selectors := 0
	for _, name := range []string{"database", "b", "n"} {
		if flagWasSet(flags, name) {
			selectors++
		}
	}
	if selectors > 1 {
		return "", fmt.Errorf(
			"%s options -database, -b, and -n are mutually exclusive",
			command,
		)
	}
	if flagWasSet(flags, "n") {
		if databaseNumber < 0 {
			return "", errors.New("OpenLDAP database number must be non-negative")
		}
		return strconv.Itoa(databaseNumber), nil
	}
	if flagWasSet(flags, "database") {
		if strings.TrimSpace(nativeSelector) == "" {
			return "", errors.New("-database must not be empty")
		}
		return nativeSelector, nil
	}
	if flagWasSet(flags, "b") && strings.TrimSpace(suffix) == "" {
		return "", fmt.Errorf("%s option -b requires a non-empty suffix DN", command)
	}

	targetDN := ""
	if flagWasSet(flags, "b") {
		targetDN = suffix
	} else if (command == "slapcat" || command == "slapschema") &&
		strings.TrimSpace(subtree) != "" {
		targetDN = subtree
	}
	if targetDN == "" {
		return nativeSelector, nil
	}
	return databaseSelectorForDN(databasePath, targetDN)
}

func databaseSelectorForDN(databasePath, rawDN string) (string, error) {
	target, err := directory.ParseDN(rawDN)
	if err != nil || target.Depth() == 0 {
		if err == nil {
			err = errors.New("DN must not be empty")
		}
		return "", fmt.Errorf("invalid database suffix %q: %w", rawDN, err)
	}
	configDN, err := directory.ParseDN("cn=config")
	if err != nil {
		return "", err
	}
	if configDN.Equal(target) || configDN.AncestorOf(target) {
		return "0", nil
	}

	store, err := storage.OpenBoltReadOnly(databasePath)
	if err != nil {
		return "", err
	}
	type candidate struct {
		selector string
		depth    int
	}
	var matches []candidate
	err = store.View(context.Background(), func(reader storage.Reader) error {
		return reader.ForEachIn(storage.OpenLDAPConfigPartition, func(entry directory.Entry) error {
			entryDN, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			parent, hasParent := entryDN.Parent()
			if !hasParent || !configDN.Equal(parent) {
				return nil
			}
			for _, attribute := range []string{"olcHidden", "olcDisabled"} {
				disabled, present, err := openLDAPBooleanAttribute(entry, attribute)
				if err != nil {
					return err
				}
				if present && disabled {
					return nil
				}
			}
			names := entry.Values("olcDatabase")
			if len(names) == 0 {
				return nil
			}
			if len(names) != 1 {
				return fmt.Errorf("%s olcDatabase must be single-valued", entry.DN)
			}
			for _, encodedSuffix := range entry.Values("olcSuffix") {
				configured, err := directory.ParseDN(string(encodedSuffix))
				if err != nil {
					return fmt.Errorf("%s has invalid olcSuffix: %w", entry.DN, err)
				}
				if configured.Equal(target) || configured.AncestorOf(target) {
					matches = append(matches, candidate{
						selector: string(names[0]),
						depth:    configured.Depth(),
					})
				}
			}
			return nil
		})
	})
	closeErr := store.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(matches) == 0 {
		return "", fmt.Errorf(
			"OpenLDAP database containing suffix %q is not present in cn=config",
			rawDN,
		)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].depth != matches[j].depth {
			return matches[i].depth > matches[j].depth
		}
		return matches[i].selector < matches[j].selector
	})
	best := matches[0]
	for _, match := range matches[1:] {
		if match.depth != best.depth {
			break
		}
		if !strings.EqualFold(match.selector, best.selector) {
			return "", fmt.Errorf(
				"OpenLDAP database suffix %q is ambiguous",
				rawDN,
			)
		}
	}
	return best.selector, nil
}

func openLDAPBooleanAttribute(
	entry directory.Entry,
	description string,
) (bool, bool, error) {
	values := entry.Values(description)
	if len(values) == 0 {
		return false, false, nil
	}
	if len(values) != 1 {
		return false, true, fmt.Errorf(
			"%s %s must be single-valued",
			entry.DN,
			description,
		)
	}
	switch strings.ToLower(strings.TrimSpace(string(values[0]))) {
	case "true", "yes", "on", "1":
		return true, true, nil
	case "false", "no", "off", "0":
		return false, true, nil
	default:
		return false, true, fmt.Errorf(
			"%s %s has invalid boolean value %q",
			entry.DN,
			description,
			values[0],
		)
	}
}

func runServe(
	ctx context.Context,
	management <-chan os.Signal,
	args []string,
	stdout, stderr io.Writer,
	getenv func(string) string,
) (runErr error) {
	if ctx == nil {
		return errors.New("serve context is required")
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "data/ldap-go.db", "directory database path")
	listenAddress := flags.String(
		"listen",
		"127.0.0.1:1389",
		"LDAP listen address (empty disables TCP when -ldapi is set)",
	)
	ldapsListenAddress := flags.String(
		"ldaps-listen",
		"",
		"additional implicit TLS listen address",
	)
	tlcpListenAddress := flags.String(
		"tlcp-listen",
		"",
		"additional implicit TLCP listen address",
	)
	ldapiPath := flags.String("ldapi", "", "additional LDAPI Unix socket path")
	ldapiMode := flags.Uint("ldapi-mode", 0o660, "LDAPI Unix socket permission mode")
	systemdActivation := flags.Bool(
		"systemd-activation",
		false,
		"adopt systemd LISTEN_FDS instead of creating listeners",
	)
	serveUser := flags.String("user", "", "Unix user name or ID to switch to after listening")
	serveGroup := flags.String("group", "", "Unix group name or ID to switch to after listening")
	serveChroot := flags.String("chroot", "", "Unix directory to chroot into after listening")
	pidFilePath := flags.String("pidfile", "", "absolute process ID file path")
	onlineBackupDirectory := flags.String(
		"online-backup-dir",
		"",
		"private directory for root-authorized LDAPI online backups",
	)
	flags.StringVar(serveUser, "u", "", "alias for -user")
	flags.StringVar(serveGroup, "g", "", "alias for -group")
	flags.StringVar(serveChroot, "r", "", "alias for -chroot")
	rootDN := flags.String("root-dn", "", "optional database root DN override")
	maxMessageSize := flags.Int64(
		"max-message-size",
		0,
		"additional maximum BER frame size in bytes (0 uses OpenLDAP incoming limits)",
	)
	searchLimit := flags.Int("search-limit", 1000, "server-side maximum entries per search")
	searchCandidateLimit := flags.Int(
		"search-candidate-limit",
		100000,
		"maximum retained candidates for a sorted search",
	)
	searchCandidateBytes := flags.Int64(
		"search-candidate-bytes",
		64<<20,
		"maximum retained bytes for a sorted search",
	)
	searchResponseBytes := flags.Int64(
		"search-response-bytes",
		128<<20,
		"maximum encoded response bytes for a finite search",
	)
	searchMemoryBytes := flags.Int64(
		"search-memory-bytes",
		512<<20,
		"maximum retained search memory across the process",
	)
	responsePDUBytes := flags.Int64(
		"response-pdu-bytes",
		16<<20,
		"maximum encoded bytes in one Search response PDU",
	)
	inFlightResponseBytes := flags.Int64(
		"in-flight-response-bytes",
		256<<20,
		"maximum Search response bytes being written across the process",
	)
	transactionMaxOperations := flags.Int(
		"transaction-max-operations",
		1000,
		"maximum queued operations per LDAP transaction",
	)
	transactionMaxQueuedBytes := flags.Int64(
		"transaction-max-queued-bytes",
		16<<20,
		"maximum encoded queued bytes per LDAP transaction",
	)
	maxConnections := flags.Int("max-connections", 4096, "maximum simultaneous client connections")
	maxConcurrentOperations := flags.Int(
		"max-concurrent-operations",
		256,
		"maximum operations executing across all connections",
	)
	maxOperationsPerConnection := flags.Int(
		"max-operations-per-connection",
		8,
		"maximum operations executing concurrently on one connection",
	)
	maxPendingBytesPerConnection := flags.Int64(
		"max-pending-bytes-per-connection",
		64<<20,
		"maximum decoded operation bytes retained by one connection",
	)
	maxPendingOperationBytes := flags.Int64(
		"max-pending-operation-bytes",
		256<<20,
		"maximum decoded operation bytes retained across the process",
	)
	maxConcurrentHandshakes := flags.Int(
		"max-concurrent-handshakes",
		64,
		"maximum simultaneous TLS or TLCP handshakes",
	)
	logLevel := flags.String("log-level", "info", "debug, info, warn, or error")
	auditLogPath := flags.String("audit-log", "", "append-only JSON audit log path")
	auditKeyFile := flags.String("audit-key-file", "", "file containing the audit HMAC key")
	radiusConfigPath := flags.String(
		"radius-config",
		"",
		"RADIUS client configuration override for {RADIUS} passwords",
	)
	radiusNASIdentifier := flags.String(
		"radius-nas-identifier",
		"",
		"NAS-Identifier override for {RADIUS} password verification",
	)
	gssapiKeytab := flags.String(
		"gssapi-keytab",
		"",
		"FILE keytab for the SASL GSSAPI acceptor; defaults to KRB5_KTNAME",
	)
	gssapiChannelBinding := flags.String(
		"gssapi-channel-binding",
		"",
		"explicit GSSAPI channel binding extension: tls-server-end-point",
	)
	tlsCertificate := flags.String("tls-cert", "", "PEM server certificate for StartTLS or LDAPS")
	tlsPrivateKey := flags.String("tls-key", "", "PEM private key for StartTLS or LDAPS")
	tlsClientCA := flags.String("tls-client-ca", "", "PEM CA bundle for TLS client certificates")
	tlsRequireClientCertificate := flags.Bool(
		"tls-require-client-cert",
		false,
		"require and verify a TLS client certificate",
	)
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
	tlcpClientCA := flags.String(
		"tlcp-client-ca",
		"",
		"PEM SM2 CA bundle for TLCP client certificates",
	)
	tlcpRequireClientCertificate := flags.Bool(
		"tlcp-require-client-cert",
		false,
		"require and verify a TLCP client certificate",
	)
	implicitTLCP := flags.Bool("tlcp-implicit", false, "negotiate TLCP before LDAP messages")
	secureHandshakeTimeout := 10 * time.Second
	shutdownTimeout := 30 * time.Second
	flags.DurationVar(
		&secureHandshakeTimeout,
		"secure-handshake-timeout",
		secureHandshakeTimeout,
		"maximum TLS or TLCP handshake duration",
	)
	flags.DurationVar(
		&shutdownTimeout,
		"shutdown-timeout",
		shutdownTimeout,
		"maximum graceful shutdown duration",
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
	for _, aliases := range [][2]string{{"user", "u"}, {"group", "g"}, {"chroot", "r"}} {
		if flagWasSet(flags, aliases[0]) && flagWasSet(flags, aliases[1]) {
			return fmt.Errorf("-%s and -%s are aliases and cannot both be set", aliases[0], aliases[1])
		}
	}
	if *gssapiKeytab == "" {
		*gssapiKeytab = getenv("KRB5_KTNAME")
	}

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	standardTLSRequested := *tlsCertificate != "" || *tlsPrivateKey != "" ||
		*tlsClientCA != "" || *tlsRequireClientCertificate
	tlcpRequested := *tlcpSignCertificate != "" || *tlcpSignPrivateKey != "" ||
		*tlcpEncryptionCertificate != "" || *tlcpEncryptionPrivateKey != "" ||
		*tlcpClientCA != "" || *tlcpRequireClientCertificate
	if standardTLSRequested && tlcpRequested {
		return errors.New("standard TLS and TLCP certificate options are mutually exclusive")
	}
	if *implicitTLCP && (*tlcpSignCertificate == "" || *tlcpSignPrivateKey == "" ||
		*tlcpEncryptionCertificate == "" || *tlcpEncryptionPrivateKey == "") {
		return errors.New("-tlcp-implicit requires all four TLCP certificate/key options")
	}
	if *implicitTLS {
		if tlcpRequested {
			return errors.New("use -tlcp-implicit instead of -ldaps with TLCP")
		}
		if *tlsCertificate == "" || *tlsPrivateKey == "" {
			return errors.New("-ldaps requires -tls-cert and -tls-key")
		}
	}
	if *ldapsListenAddress != "" {
		if tlcpRequested {
			return errors.New("-ldaps-listen cannot use TLCP certificate options")
		}
		if *tlsCertificate == "" || *tlsPrivateKey == "" {
			return errors.New("-ldaps-listen requires -tls-cert and -tls-key")
		}
	}
	if *tlcpListenAddress != "" {
		if standardTLSRequested {
			return errors.New("-tlcp-listen cannot use standard TLS certificate options")
		}
		if *tlcpSignCertificate == "" || *tlcpSignPrivateKey == "" ||
			*tlcpEncryptionCertificate == "" || *tlcpEncryptionPrivateKey == "" {
			return errors.New("-tlcp-listen requires all four TLCP certificate/key options")
		}
	}
	if *systemdActivation && (flagWasSet(flags, "listen") ||
		flagWasSet(flags, "ldaps-listen") || flagWasSet(flags, "tlcp-listen") ||
		flagWasSet(flags, "ldapi") || flagWasSet(flags, "ldapi-mode")) {
		return errors.New("-systemd-activation cannot be combined with manual listener options")
	}
	if *ldapiPath == "" && flagWasSet(flags, "ldapi-mode") {
		return errors.New("-ldapi-mode requires -ldapi")
	}
	if !*systemdActivation && *listenAddress == "" && *ldapsListenAddress == "" &&
		*tlcpListenAddress == "" && *ldapiPath == "" {
		return errors.New("at least one listener is required")
	}
	if *ldapiMode > 0o777 {
		return errors.New("-ldapi-mode must be between 0000 and 0777")
	}
	if (standardTLSRequested || tlcpRequested) && secureHandshakeTimeout <= 0 {
		return errors.New("-secure-handshake-timeout must be positive")
	}
	if shutdownTimeout <= 0 {
		return errors.New("-shutdown-timeout must be positive")
	}
	if *transactionMaxOperations <= 0 {
		return errors.New("-transaction-max-operations must be positive")
	}
	if *transactionMaxQueuedBytes <= 0 {
		return errors.New("-transaction-max-queued-bytes must be positive")
	}
	if *maxConnections <= 0 {
		return errors.New("-max-connections must be positive")
	}
	if *maxConcurrentOperations <= 0 {
		return errors.New("-max-concurrent-operations must be positive")
	}
	if *maxOperationsPerConnection <= 0 {
		return errors.New("-max-operations-per-connection must be positive")
	}
	if *maxPendingBytesPerConnection <= 0 {
		return errors.New("-max-pending-bytes-per-connection must be positive")
	}
	if *maxPendingOperationBytes <= 0 {
		return errors.New("-max-pending-operation-bytes must be positive")
	}
	if *maxConcurrentHandshakes <= 0 {
		return errors.New("-max-concurrent-handshakes must be positive")
	}
	if *searchCandidateLimit <= 0 {
		return errors.New("-search-candidate-limit must be positive")
	}
	if *searchCandidateBytes <= 0 {
		return errors.New("-search-candidate-bytes must be positive")
	}
	if *searchResponseBytes <= 0 {
		return errors.New("-search-response-bytes must be positive")
	}
	if *searchMemoryBytes <= 0 {
		return errors.New("-search-memory-bytes must be positive")
	}
	if *responsePDUBytes <= 0 {
		return errors.New("-response-pdu-bytes must be positive")
	}
	if *inFlightResponseBytes <= 0 {
		return errors.New("-in-flight-response-bytes must be positive")
	}
	privileges, err := resolveServePrivileges(*serveUser, *serveGroup, *serveChroot)
	if err != nil {
		return err
	}
	defer privileges.Close()
	if *serveChroot != "" && *ldapiPath != "" && !*systemdActivation {
		return errors.New("-chroot with LDAPI requires -systemd-activation to preserve socket ownership")
	}

	listeners := make([]net.Listener, 0, 4)
	listenerURLs := make([]string, 0, 4)
	listenerImplicitTLS := make([]bool, 0, 4)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()

	tcpScheme := "ldap"
	if *implicitTLS {
		tcpScheme = "ldaps"
	} else if *implicitTLCP {
		tcpScheme = "ldap+tlcp"
	}
	if *systemdActivation {
		listeners, listenerURLs, listenerImplicitTLS, err = listenServeSystemd(getenv, tcpScheme)
		if err != nil {
			return err
		}
	} else {
		listenTCP := func(address, scheme string, implicit bool) error {
			if address == "" {
				return nil
			}
			tcpListener, listenErr := net.Listen("tcp", address)
			if listenErr != nil {
				return fmt.Errorf("listen on %s: %w", address, listenErr)
			}
			listeners = append(listeners, tcpListener)
			listenerImplicitTLS = append(listenerImplicitTLS, implicit)
			listenerHost, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return fmt.Errorf("parse listen address %s: %w", address, splitErr)
			}
			_, listenerPort, splitErr := net.SplitHostPort(tcpListener.Addr().String())
			if splitErr != nil {
				return fmt.Errorf("parse bound listen address %s: %w", tcpListener.Addr(), splitErr)
			}
			listenerURLs = append(listenerURLs, fmt.Sprintf(
				"%s://%s/",
				scheme,
				net.JoinHostPort(listenerHost, listenerPort),
			))
			return nil
		}
		if err := listenTCP(*listenAddress, tcpScheme, *implicitTLS || *implicitTLCP); err != nil {
			return err
		}
		if err := listenTCP(*ldapsListenAddress, "ldaps", true); err != nil {
			return err
		}
		if err := listenTCP(*tlcpListenAddress, "ldap+tlcp", true); err != nil {
			return err
		}
	}
	if !*systemdActivation && *ldapiPath != "" {
		ldapiListener, ldapiURL, err := listenServeLDAPI(
			*ldapiPath,
			os.FileMode(*ldapiMode),
		)
		if err != nil {
			return err
		}
		listeners = append(listeners, ldapiListener)
		listenerURLs = append(listenerURLs, ldapiURL)
		listenerImplicitTLS = append(listenerImplicitTLS, false)
	}
	if err := validateServeListenerTransportMix(listenerURLs, tlcpRequested); err != nil {
		return err
	}
	listenerSchemeForConnection := serveListenerSchemeResolver(
		listeners,
		listenerURLs,
	)
	listener := newServeListener(listeners)
	defer listener.Close()
	notifier, notifyConfigured, notifyErr := openSystemdNotifier(getenv)
	if notifyErr != nil {
		logger.Warn("systemd notification setup failed", "error", notifyErr)
		notifier = nil
		notifyErr = nil
	}
	if notifier != nil {
		defer notifier.Close()
	}
	if err := applyServePrivileges(privileges); err != nil {
		return err
	}
	if samePath(*auditLogPath, *databasePath) {
		return errors.New("audit log and directory database must use different paths")
	}
	preparedBackupDirectory, err := prepareServeOnlineBackupDirectory(*onlineBackupDirectory)
	if err != nil {
		return err
	}
	var pidfile *servePIDFile
	if *pidFilePath != "" {
		pidfile, err = acquireServePIDFile(*pidFilePath)
		if err != nil {
			return err
		}
		defer func() {
			runErr = errors.Join(runErr, pidfile.Close())
		}()
	}
	tlsConfig, err := loadServerTLSConfigWithClientAuth(
		*tlsCertificate,
		*tlsPrivateKey,
		*tlsClientCA,
		*tlsRequireClientCertificate,
	)
	if err != nil {
		return err
	}
	tlcpTransport, err := loadServerTLCPWithClientAuth(
		*tlcpSignCertificate,
		*tlcpSignPrivateKey,
		*tlcpEncryptionCertificate,
		*tlcpEncryptionPrivateKey,
		*tlcpClientCA,
		*tlcpRequireClientCertificate,
	)
	if err != nil {
		return err
	}
	var configuredSecureTransport server.SecureTransport
	if tlcpTransport != nil {
		configuredSecureTransport = tlcpTransport
	}
	auditSink, err := openAuditSink(*auditLogPath, *auditKeyFile, getenv)
	if err != nil {
		return err
	}
	if auditSink != nil {
		defer func() {
			runErr = errors.Join(runErr, auditSink.Close())
		}()
	}
	var configuredAuditSink audit.Sink
	if auditSink != nil {
		configuredAuditSink = auditSink
	}
	store, err := storage.OpenBolt(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	var onlineBackup server.OnlineBackupFunc
	if preparedBackupDirectory != "" {
		onlineBackup = func(ctx context.Context, path string) (storage.CheckReport, error) {
			return store.Backup(ctx, path, false)
		}
	}
	ready := make(chan struct{})
	instance, err := server.New(server.Config{
		Store:                        store,
		ListenerURLs:                 listenerURLs,
		MaxMessageSize:               *maxMessageSize,
		MaxSearchEntries:             *searchLimit,
		MaxTransactionOperations:     *transactionMaxOperations,
		MaxTransactionQueuedBytes:    *transactionMaxQueuedBytes,
		MaxConnections:               *maxConnections,
		MaxConcurrentOperations:      *maxConcurrentOperations,
		MaxOperationsPerConnection:   *maxOperationsPerConnection,
		MaxPendingBytesPerConnection: *maxPendingBytesPerConnection,
		MaxPendingOperationBytes:     *maxPendingOperationBytes,
		MaxConcurrentHandshakes:      *maxConcurrentHandshakes,
		MaxSearchCandidates:          *searchCandidateLimit,
		MaxSearchCandidateBytes:      *searchCandidateBytes,
		MaxSearchResponseBytes:       *searchResponseBytes,
		MaxSearchMemoryBytes:         *searchMemoryBytes,
		MaxResponsePDUBytes:          *responsePDUBytes,
		MaxInFlightResponseBytes:     *inFlightResponseBytes,
		RootDN:                       *rootDN,
		RootPassword:                 []byte(getenv(rootPasswordEnvironment)),
		Logger:                       logger,
		AuditSink:                    configuredAuditSink,
		TLSConfig:                    tlsConfig,
		SecureTransport:              configuredSecureTransport,
		ListenerSchemeForConnection:  listenerSchemeForConnection,
		SecureHandshakeTimeout:       secureHandshakeTimeout,
		ShutdownTimeout:              shutdownTimeout,
		RADIUSConfigPath:             *radiusConfigPath,
		RADIUSNASIdentifier:          *radiusNASIdentifier,
		GSSAPIKeytabPath:             *gssapiKeytab,
		GSSAPIChannelBinding:         *gssapiChannelBinding,
		Ready:                        func() { close(ready) },
		OnlineBackupDir:              preparedBackupDirectory,
		OnlineBackup:                 onlineBackup,
	})
	if err != nil {
		return err
	}
	var stoppingOnce sync.Once
	notifyStopping := func() {
		stoppingOnce.Do(func() {
			if notifier == nil {
				return
			}
			if err := notifier.Notify("STOPPING=1\nSTATUS=ldap-go shutting down"); err != nil {
				logger.Warn("systemd STOPPING notification failed", "error", err)
			}
		})
	}
	if notifyConfigured {
		defer notifyStopping()
	}

	serveContext, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- instance.Serve(serveContext, listener)
	}()
	select {
	case <-ready:
	case err := <-serveDone:
		notifyStopping()
		return err
	case <-ctx.Done():
		notifyStopping()
		stopServe()
		return <-serveDone
	}
	for _, listenerURL := range listenerURLs {
		displayURL := listenerURL
		if !strings.HasPrefix(strings.ToLower(displayURL), "ldapi://") {
			displayURL = strings.TrimSuffix(displayURL, "/")
		}
		if _, err := fmt.Fprintf(stdout, "ldap-go listening on %s\n", displayURL); err != nil {
			return err
		}
	}
	if notifier != nil {
		notifyErr = notifier.Notify("READY=1\nSTATUS=ldap-go accepting connections")
	}
	if notifyErr != nil {
		logger.Warn("systemd READY notification failed", "error", notifyErr)
	}
	contextDone := ctx.Done()
	gentle := false
	for {
		select {
		case err := <-serveDone:
			notifyStopping()
			return err
		case <-contextDone:
			notifyStopping()
			stopServe()
			contextDone = nil
		case received, ok := <-management:
			if !ok {
				management = nil
				continue
			}
			if !serveIsGentleSignal(received) {
				continue
			}
			if gentle || !instance.BeginGentleShutdown(listener) {
				notifyStopping()
				logger.Info("SIGHUP shutdown requested", "gentle", false)
				stopServe()
				contextDone = nil
				continue
			}
			gentle = true
			notifyStopping()
			logger.Info("SIGHUP shutdown requested", "gentle", true)
		}
	}
}

func runAuditVerify(
	args []string,
	stdout, stderr io.Writer,
	getenv func(string) string,
) error {
	flags := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	auditLogPath := flags.String("audit-log", "", "JSON audit log path")
	auditKeyFile := flags.String("audit-key-file", "", "file containing the audit HMAC key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *auditLogPath == "" {
		return errors.New("-audit-log is required")
	}
	key, err := loadAuditKey(*auditKeyFile, getenv)
	if err != nil {
		return err
	}
	defer clear(key)
	verified, err := audit.VerifyFile(*auditLogPath, key)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified %d audit records\n", verified.Records)
	return err
}

func openAuditSink(
	logPath,
	keyFile string,
	getenv func(string) string,
) (*audit.FileSink, error) {
	environmentKey := getenv(auditKeyEnvironment)
	if logPath == "" {
		if keyFile != "" || environmentKey != "" {
			return nil, errors.New("-audit-log is required when an audit key is configured")
		}
		return nil, nil
	}
	if samePath(logPath, keyFile) {
		return nil, errors.New("audit log and audit key must use different paths")
	}
	key, err := loadAuditKey(keyFile, getenv)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	sink, err := audit.OpenFile(logPath, key)
	if err != nil {
		return nil, err
	}
	return sink, nil
}

func loadAuditKey(keyFile string, getenv func(string) string) ([]byte, error) {
	environmentKey := getenv(auditKeyEnvironment)
	if keyFile != "" && environmentKey != "" {
		return nil, fmt.Errorf(
			"-%s and %s are mutually exclusive",
			"audit-key-file",
			auditKeyEnvironment,
		)
	}
	if keyFile == "" && environmentKey == "" {
		return nil, fmt.Errorf(
			"-audit-key-file or %s is required",
			auditKeyEnvironment,
		)
	}
	if environmentKey != "" {
		return bytes.Clone([]byte(environmentKey)), nil
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, fmt.Errorf("stat audit key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("audit key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("audit key file permissions must not allow group or other access")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read audit key file: %w", err)
	}
	return bytes.Clone(bytes.TrimSpace(key)), nil
}

func samePath(first, second string) bool {
	if first == "" || second == "" {
		return false
	}
	firstPath, firstErr := filepath.Abs(first)
	secondPath, secondErr := filepath.Abs(second)
	return firstErr == nil && secondErr == nil && firstPath == secondPath
}

func loadServerTLSConfig(certificateFile, privateKeyFile string) (*tls.Config, error) {
	return loadServerTLSConfigWithClientAuth(
		certificateFile,
		privateKeyFile,
		"",
		false,
	)
}

func loadServerTLSConfigWithClientAuth(
	certificateFile,
	privateKeyFile,
	clientCAFile string,
	requireClientCertificate bool,
) (*tls.Config, error) {
	if certificateFile == "" &&
		privateKeyFile == "" &&
		clientCAFile == "" &&
		!requireClientCertificate {
		return nil, nil
	}
	if certificateFile == "" || privateKeyFile == "" {
		return nil, errors.New("-tls-cert and -tls-key must be provided together")
	}
	if requireClientCertificate && clientCAFile == "" {
		return nil, errors.New("-tls-require-client-cert requires -tls-client-ca")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCAFile != "" {
		pemData, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read TLS client CA: %w", err)
		}
		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(pemData) {
			return nil, errors.New("TLS client CA file contains no certificates")
		}
		config.ClientCAs = clientCAs
		config.ClientAuth = tls.VerifyClientCertIfGiven
		if requireClientCertificate {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return config, nil
}

func loadServerTLCP(
	signCertificateFile,
	signPrivateKeyFile,
	encryptionCertificateFile,
	encryptionPrivateKeyFile string,
) (*gmtransport.TLCP, error) {
	return loadServerTLCPWithClientAuth(
		signCertificateFile,
		signPrivateKeyFile,
		encryptionCertificateFile,
		encryptionPrivateKeyFile,
		"",
		false,
	)
}

func loadServerTLCPWithClientAuth(
	signCertificateFile,
	signPrivateKeyFile,
	encryptionCertificateFile,
	encryptionPrivateKeyFile,
	clientCAFile string,
	requireClientCertificate bool,
) (*gmtransport.TLCP, error) {
	if signCertificateFile == "" &&
		signPrivateKeyFile == "" &&
		encryptionCertificateFile == "" &&
		encryptionPrivateKeyFile == "" &&
		clientCAFile == "" &&
		!requireClientCertificate {
		return nil, nil
	}
	if requireClientCertificate && clientCAFile == "" {
		return nil, errors.New("-tlcp-require-client-cert requires -tlcp-client-ca")
	}
	return gmtransport.LoadTLCPWithClientAuth(
		signCertificateFile,
		signPrivateKeyFile,
		encryptionCertificateFile,
		encryptionPrivateKeyFile,
		clientCAFile,
		requireClientCertificate,
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
  audit-verify  verify an HMAC-chained audit log
  backup   create and validate an atomic bbolt backup (offline)
  online-backup  request a root-authorized backup from a running LDAPI server
  production-check  validate offline production readiness and emit a report
  check    check bbolt pages, buckets, keys, entries, and metadata (offline)
  health   check LDAP liveness and syncrepl consumer health
  config-test  validate runtime configuration without modifying the database
  slaptest alias for config-test
  dn       validate, normalize, or pretty-print DNs using database schema
  slapdn   alias for dn
  import   atomically import slapcat-compatible LDIF
  slapadd  OpenLDAP-style alias for import
	  slapauth  check configured SASL authentication and authorization identities
	  slapschema  check stored entries against the configured schema
	  slapmodify  atomically apply offline LDIF change records
	  ldapsearch  search a remote LDAP directory and print LDIF
	  ldapwhoami  print the authorization identity reported by an LDAP server
	  ldapcompare  compare an LDAP attribute assertion
	  ldappasswd  change or generate an LDAP user password
	  ldapexop  issue an LDAP extended operation
	  ldapmodify  apply ordered LDAP LDIF change records
  ldapadd  add LDIF entries or apply explicit change records
  ldapdelete  delete LDAP entries by DN
  ldapmodrdn  rename or move LDAP entries
  lloadd   run the LDAP-aware reverse proxy/load balancer
  export   atomically export a directory database as LDIF
  slapcat  OpenLDAP-style alias for export
  passwd   generate a PBKDF2-SM3 userPassword value
  slappasswd  generate OpenLDAP-compatible and national-crypto password values
  rebuild  compact and atomically rebuild the bbolt database (offline)
  reindex  alias for rebuild
  slapindex  whole-database bbolt rebuild alias
  restore  validate and atomically restore a bbolt backup (offline)
  serve    serve the persistent directory over LDAP
  version  print the build version`)
}
