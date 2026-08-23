package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/term"
)

const (
	defaultLDAPClientURI     = "ldap://localhost:389"
	defaultLDAPClientTimeout = 10 * time.Second
	defaultLDAPReferralHops  = 5
	maxClientCAFileSize      = 16 << 20
	ldapSearchLDIFLineWidth  = 76
)

type ldapClientOptions struct {
	uri                 string
	simple              bool
	bindDN              string
	saslMechanism       string
	saslAuthentication  string
	saslAuthorization   string
	saslRealm           string
	directPassword      secretFlagValue
	promptPassword      bool
	passwordFile        string
	tryStartTLS         bool
	requireStartTLS     bool
	timeout             time.Duration
	tlsCAFile           string
	tlsCertificateFile  string
	tlsPrivateKeyFile   string
	tlsServerName       string
	dryRun              bool
	generalControlSpecs repeatedStringFlag
	generalControls     []ldap.Control
	chaseReferrals      bool
	referralHopLimit    int
	unsupportedFlags    []unsupportedFlag
}

func (options *ldapClientOptions) register(flags *flag.FlagSet) {
	options.uri = defaultLDAPClientURI
	options.timeout = defaultLDAPClientTimeout
	options.referralHopLimit = defaultLDAPReferralHops
	flags.StringVar(&options.uri, "H", options.uri, "LDAP URI")
	flags.BoolVar(&options.simple, "x", false, "use simple authentication")
	flags.StringVar(&options.bindDN, "D", "", "bind DN")
	flags.StringVar(&options.saslMechanism, "Y", "", "SASL mechanism")
	flags.StringVar(&options.saslAuthentication, "U", "", "SASL authentication identity")
	flags.StringVar(&options.saslAuthorization, "X", "", "SASL authorization identity")
	flags.StringVar(&options.saslRealm, "R", "", "SASL realm")
	flags.Var(
		&options.directPassword,
		"w",
		"bind password (insecure: visible in process arguments; prefer -W or -y)",
	)
	flags.BoolVar(&options.promptPassword, "W", false, "read the bind password from stdin")
	flags.StringVar(&options.passwordFile, "y", "", "read the bind password from a file")
	flags.BoolVar(&options.tryStartTLS, "Z", false, "try StartTLS and allow cleartext fallback")
	flags.BoolVar(&options.requireStartTLS, "ZZ", false, "require StartTLS")
	flags.BoolVar(&options.tryStartTLS, "starttls-try", false, "alias for -Z")
	flags.BoolVar(&options.requireStartTLS, "starttls", false, "alias for -ZZ")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "network and request timeout")
	flags.DurationVar(
		&options.timeout,
		"network-timeout",
		options.timeout,
		"alias for -timeout",
	)
	flags.StringVar(&options.tlsCAFile, "tls-ca", "", "PEM CA bundle for TLS")
	flags.StringVar(
		&options.tlsCertificateFile,
		"tls-cert",
		"",
		"PEM client certificate for SASL EXTERNAL",
	)
	flags.StringVar(
		&options.tlsPrivateKeyFile,
		"tls-key",
		"",
		"PEM client private key for SASL EXTERNAL",
	)
	flags.StringVar(
		&options.tlsServerName,
		"tls-server-name",
		"",
		"TLS certificate hostname override",
	)
	flags.BoolVar(&options.dryRun, "n", false, "parse and validate without connecting")
	flags.Var(
		&options.generalControlSpecs,
		"e",
		"general LDAP control: [!]<oid>[=<base64>|:<string>|:<file URI>]",
	)
	flags.BoolVar(&options.chaseReferrals, "C", false, "chase LDAP referrals")
	flags.BoolVar(
		&options.chaseReferrals,
		"referrals",
		false,
		"chase LDAP referrals; use -referrals=false to disable",
	)
	flags.BoolVar(
		&options.chaseReferrals,
		"chase-referrals",
		false,
		"alias for -referrals",
	)
	flags.IntVar(
		&options.referralHopLimit,
		"referral-hop-limit",
		options.referralHopLimit,
		"maximum number of referral hops",
	)
	flags.IntVar(
		&options.referralHopLimit,
		"refhoplimit",
		options.referralHopLimit,
		"alias for -referral-hop-limit",
	)

	for _, option := range []struct {
		name, reason string
	}{
		{"d", "LDAP library debug output is not implemented"},
		{"h", "legacy host selection is not implemented; use -H"},
		{"O", "SASL security properties are not implemented"},
		{"o", "generic LDAP library options are not implemented"},
		{"p", "legacy port selection is not implemented; use -H"},
		{"P", "only LDAPv3 is implemented"},
	} {
		flags.String(option.name, "", "unsupported: "+option.reason)
		options.unsupportedFlags = append(options.unsupportedFlags, unsupportedFlag(option))
	}
	for _, option := range []struct {
		name, reason string
	}{
		{"I", "SASL interactive mode is not implemented"},
		{"M", "ManageDsaIT is not implemented by these client commands"},
		{"N", "SASL reverse-DNS control is not implemented"},
		{"Q", "SASL quiet mode is not implemented"},
		{"v", "verbose result rendering is not implemented"},
		{"V", "per-command version output is not implemented; use ldap-go version"},
	} {
		flags.Bool(option.name, false, "unsupported: "+option.reason)
		options.unsupportedFlags = append(options.unsupportedFlags, unsupportedFlag(option))
	}
}

func (options *ldapClientOptions) clear() {
	options.directPassword.clear()
	clearLDAPControls(options.generalControls)
	options.generalControls = nil
}

func (options *ldapClientOptions) validate(flags *flag.FlagSet) error {
	if options.dryRun {
		return fmt.Errorf("%s option -n is not supported", flags.Name())
	}
	return options.validateForWrite(flags, true)
}

func (options *ldapClientOptions) validateWrite(flags *flag.FlagSet) error {
	if err := options.validateForWrite(flags, !options.dryRun); err != nil {
		return err
	}
	if !options.dryRun {
		return nil
	}
	_, _, _, err := options.connectionConfiguration(flags)
	return err
}

func (options *ldapClientOptions) validateForWrite(
	flags *flag.FlagSet,
	requireConnection bool,
) error {
	if err := rejectUnsupportedFlags(flags.Name(), flags, options.unsupportedFlags); err != nil {
		return err
	}
	if options.referralHopLimit < 0 {
		return errors.New("-referral-hop-limit must be non-negative")
	}
	if flagWasSet(flags, "referral-hop-limit") && flagWasSet(flags, "refhoplimit") {
		return errors.New("-referral-hop-limit and -refhoplimit are aliases and cannot both be set")
	}
	controls, err := parseLDAPControlSpecs(
		options.generalControlSpecs,
		ldapControlValueOpenLDAPGeneral,
	)
	if err != nil {
		return fmt.Errorf("%s -e: %w", flags.Name(), err)
	}
	clearLDAPControls(options.generalControls)
	options.generalControls = controls
	if flagWasSet(flags, "n") && !options.dryRun {
		return errors.New("-n=false is not supported")
	}
	if options.dryRun {
		for _, name := range []string{"Y", "U", "X", "R"} {
			if flagWasSet(flags, name) {
				return fmt.Errorf(
					"%s option -%s is not supported with -n: SASL mechanisms are not implemented for dry runs because no authentication is performed",
					flags.Name(),
					name,
				)
			}
		}
	}
	if options.tryStartTLS && options.requireStartTLS {
		return errors.New("-Z and -ZZ are mutually exclusive")
	}
	if flagWasSet(flags, "timeout") && flagWasSet(flags, "network-timeout") {
		return errors.New("-timeout and -network-timeout are aliases and cannot both be set")
	}
	if options.timeout <= 0 {
		return errors.New("-timeout must be positive")
	}
	if flagWasSet(flags, "W") && !options.promptPassword {
		return errors.New("-W=false is not supported")
	}
	if flagWasSet(flags, "Z") && !options.tryStartTLS {
		return errors.New("-Z=false is not supported")
	}
	if flagWasSet(flags, "ZZ") && !options.requireStartTLS {
		return errors.New("-ZZ=false is not supported")
	}
	if options.directPassword.count > 1 {
		return errors.New("bind password was provided more than once")
	}

	passwordSources := 0
	if options.directPassword.count > 0 {
		passwordSources++
	}
	if flagWasSet(flags, "W") {
		passwordSources++
	}
	if flagWasSet(flags, "y") {
		passwordSources++
	}
	if passwordSources > 1 {
		return errors.New("-w, -W, and -y are mutually exclusive")
	}
	saslFlagsSet := flagWasSet(flags, "Y") || flagWasSet(flags, "U") ||
		flagWasSet(flags, "X") || flagWasSet(flags, "R")
	authenticationRequested := requireConnection || options.simple || saslFlagsSet ||
		options.bindDN != "" || passwordSources > 0
	if options.simple {
		if saslFlagsSet {
			return errors.New("-x cannot be combined with -Y, -U, -X, or -R")
		}
		if options.bindDN == "" && passwordSources > 0 {
			return errors.New("a bind password requires a non-empty -D bind DN")
		}
		if options.bindDN != "" && passwordSources == 0 {
			return errors.New("a non-empty -D bind DN requires one of -w, -W, or -y")
		}
	} else if authenticationRequested {
		if options.bindDN != "" {
			return errors.New("-D requires -x; use -U for a SASL authentication identity")
		}
		if err := options.validateSASL(flags, passwordSources); err != nil {
			return fmt.Errorf("%s: %w", flags.Name(), err)
		}
	}
	if flagWasSet(flags, "y") && options.passwordFile == "" {
		return errors.New("-y requires a non-empty password file path")
	}
	if flagWasSet(flags, "tls-ca") && options.tlsCAFile == "" {
		return errors.New("-tls-ca requires a non-empty path")
	}
	if (options.tlsCertificateFile == "") != (options.tlsPrivateKeyFile == "") {
		return errors.New("-tls-cert and -tls-key must be provided together")
	}
	if flagWasSet(flags, "tls-server-name") && options.tlsServerName == "" {
		return errors.New("-tls-server-name requires a non-empty hostname")
	}
	return nil
}

func (options *ldapClientOptions) loadPassword(
	flags *flag.FlagSet,
	stdin io.Reader,
	stderr io.Writer,
) ([]byte, bool, error) {
	passwordIdentity := options.bindDN
	if !options.simple {
		passwordIdentity = options.saslAuthentication
	}
	if passwordIdentity == "" || strings.EqualFold(options.saslMechanism, "EXTERNAL") {
		return nil, false, nil
	}

	var password []byte
	var err error
	switch {
	case options.directPassword.count > 0:
		password = options.directPassword.take()
	case flagWasSet(flags, "W"):
		if _, err := fmt.Fprint(stderr, "Enter LDAP Password: "); err != nil {
			return nil, false, err
		}
		password, err = readLDAPPromptPassword(stdin, stderr)
	case flagWasSet(flags, "y"):
		password, err = readLDAPPasswordFile(options.passwordFile, stderr)
	default:
		return nil, false, errors.New("bind password source is required")
	}
	if err != nil {
		return nil, false, err
	}
	if !options.simple && bytesContainNUL(password) {
		clear(password)
		return nil, false, errors.New("SASL password must not contain NUL")
	}
	return password, true, nil
}

func readLDAPPromptPassword(reader io.Reader, stderr io.Writer) ([]byte, error) {
	file, isFile := reader.(*os.File)
	if !isFile || !term.IsTerminal(int(file.Fd())) {
		password, err := readLDAPPasswordLine(reader)
		if err != nil {
			return nil, err
		}
		if len(password) == 0 {
			clear(password)
			return nil, errors.New("password input is empty")
		}
		return password, nil
	}

	password, readErr := term.ReadPassword(int(file.Fd()))
	_, newlineErr := fmt.Fprintln(stderr)
	if readErr != nil {
		clear(password)
		return nil, errors.Join(fmt.Errorf("read password: %w", readErr), newlineErr)
	}
	if newlineErr != nil {
		clear(password)
		return nil, newlineErr
	}
	if len(password) > maxPasswordInputSize {
		clear(password)
		return nil, fmt.Errorf("password exceeds %d bytes", maxPasswordInputSize)
	}
	if len(password) == 0 {
		clear(password)
		return nil, errors.New("password input is empty")
	}
	return password, nil
}

func readLDAPPasswordLine(reader io.Reader) ([]byte, error) {
	password := make([]byte, 0, 64)
	var one [1]byte
	for {
		count, err := reader.Read(one[:])
		if count > 0 {
			if one[0] == '\n' {
				if len(password) > 0 && password[len(password)-1] == '\r' {
					password[len(password)-1] = 0
					password = password[:len(password)-1]
				}
				return password, nil
			}
			if len(password) >= maxPasswordInputSize {
				clear(password)
				return nil, fmt.Errorf("password exceeds %d bytes", maxPasswordInputSize)
			}
			password = append(password, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(password) == 0 {
					clear(password)
					return nil, errors.New("password input ended before a password was read")
				}
				return password, nil
			}
			clear(password)
			return nil, fmt.Errorf("read password: %w", err)
		}
		if count == 0 {
			clear(password)
			return nil, io.ErrNoProgress
		}
	}
}

func readLDAPPasswordFile(path string, stderr io.Writer) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open password file: %w", err)
	}
	defer file.Close()

	if runtime.GOOS != "windows" {
		if info, statErr := file.Stat(); statErr == nil && info.Mode().Perm()&0o006 != 0 {
			if _, err := fmt.Fprintf(
				stderr,
				"Warning: Password file %s is publicly readable/writeable\n",
				path,
			); err != nil {
				return nil, err
			}
		}
	}
	return readPasswordInput(file, false, "password file")
}

func (options *ldapClientOptions) connectAndBind(
	flags *flag.FlagSet,
	stdin io.Reader,
	stderr io.Writer,
) (*ldap.Conn, error) {
	parsedURI, dialURI, tlsConfig, err := options.connectionConfiguration(flags)
	if err != nil {
		return nil, err
	}
	password, hasPassword, err := options.loadPassword(flags, stdin, stderr)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	if !options.simple {
		return options.connectAndBindSASL(
			parsedURI,
			dialURI,
			tlsConfig,
			password,
			hasPassword,
			stderr,
		)
	}

	dial := func(useTLS bool) (*ldap.Conn, error) {
		dialOptions := []ldap.DialOpt{
			ldap.DialWithDialer(&net.Dialer{Timeout: options.timeout}),
		}
		if useTLS {
			dialOptions = append(dialOptions, ldap.DialWithTLSConfig(tlsConfig.Clone()))
		}
		connection, err := ldap.DialURL(dialURI, dialOptions...)
		if err != nil {
			return nil, err
		}
		connection.SetTimeout(options.timeout)
		return connection, nil
	}

	connection, err := dial(parsedURI.Scheme == "ldaps")
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", dialURI, err)
	}
	closeOnError := func(err error) (*ldap.Conn, error) {
		_ = connection.Close()
		return nil, err
	}

	if options.tryStartTLS || options.requireStartTLS {
		if err := connection.StartTLS(tlsConfig.Clone()); err != nil {
			if options.requireStartTLS {
				return closeOnError(fmt.Errorf("StartTLS with %s: %w", dialURI, err))
			}
			_ = connection.Close()
			if _, writeErr := fmt.Fprintf(
				stderr,
				"warning: StartTLS with %s failed; continuing over cleartext LDAP: %v\n",
				dialURI,
				err,
			); writeErr != nil {
				return nil, writeErr
			}
			connection, err = dial(false)
			if err != nil {
				return nil, fmt.Errorf("reconnect to %s after StartTLS failure: %w", dialURI, err)
			}
		}
	}

	if !hasPassword {
		if err := connection.UnauthenticatedBind(""); err != nil {
			return closeOnError(fmt.Errorf("anonymous bind: %w", err))
		}
		return connection, nil
	}

	request := ldap.NewSimpleBindRequest(options.bindDN, string(password), nil)
	request.AllowEmptyPassword = true
	defer func() { request.Password = "" }()
	if _, err := connection.SimpleBind(request); err != nil {
		return closeOnError(fmt.Errorf("bind as %s: %w", options.bindDN, err))
	}
	return connection, nil
}

func (options *ldapClientOptions) connectionConfiguration(
	flags *flag.FlagSet,
) (*url.URL, string, *tls.Config, error) {
	parsed, err := url.Parse(options.uri)
	if err != nil {
		return nil, "", nil, fmt.Errorf("parse LDAP URI: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
		return nil, "", nil, errors.New("-H must use an ldap:// or ldaps:// URI")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, "", nil, errors.New("-H LDAP URI requires a network host")
	}
	if parsed.User != nil {
		return nil, "", nil, errors.New("LDAP URI userinfo is not supported; use -D and a password option")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, "", nil, errors.New("LDAP URI DN paths are not supported; use ldapsearch -b")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, "", nil, errors.New("LDAP URI query and fragment components are not supported")
	}
	if parsed.Scheme == "ldaps" && (options.tryStartTLS || options.requireStartTLS) {
		return nil, "", nil, errors.New("-Z and -ZZ cannot be used with an ldaps:// URI")
	}
	tlsRequested := parsed.Scheme == "ldaps" || options.tryStartTLS || options.requireStartTLS
	if !tlsRequested && (flagWasSet(flags, "tls-ca") ||
		flagWasSet(flags, "tls-cert") || flagWasSet(flags, "tls-key") ||
		flagWasSet(flags, "tls-server-name")) {
		return nil, "", nil, errors.New("TLS options require ldaps://, -Z, or -ZZ")
	}

	tlsConfig, err := options.clientTLSConfig(parsed.Hostname())
	if err != nil {
		return nil, "", nil, err
	}
	return parsed, parsed.String(), tlsConfig, nil
}

func (options *ldapClientOptions) clientTLSConfig(hostname string) (*tls.Config, error) {
	serverName := options.tlsServerName
	if serverName == "" {
		serverName = hostname
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if options.tlsCertificateFile != "" {
		certificate, err := tls.LoadX509KeyPair(
			options.tlsCertificateFile,
			options.tlsPrivateKeyFile,
		)
		if err != nil {
			return nil, fmt.Errorf("load TLS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	if options.tlsCAFile != "" {
		roots, systemErr := x509.SystemCertPool()
		if systemErr != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pemData, err := readLimitedClientFile(
			options.tlsCAFile,
			maxClientCAFileSize,
			"TLS CA file",
		)
		if err != nil {
			return nil, err
		}
		defer clear(pemData)
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("TLS CA file contains no PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}
	return tlsConfig, nil
}

func readLimitedClientFile(path string, maximum int64, source string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", source, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	if int64(len(data)) > maximum {
		clear(data)
		return nil, fmt.Errorf("%s exceeds %d bytes", source, maximum)
	}
	return data, nil
}

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedStringFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runLDAPSearch(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldapsearch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()

	baseDN := flags.String("b", "", "search base DN")
	scopeName := flags.String("s", "sub", "search scope: base, one, sub, or children")
	derefName := flags.String("a", "never", "alias dereference mode: never, search, find, or always")
	sizeLimit := flags.Int("z", 0, "search size limit")
	timeLimit := flags.Int("l", 0, "server-side search time limit in seconds")
	typesOnly := flags.Bool("A", false, "request attribute names without values")
	minimalLDIF := flags.Bool("LLL", false, "omit LDIF version and comments")
	pageSize := flags.Uint64("page-size", 0, "RFC 2696 page size")
	var extensions repeatedStringFlag
	flags.Var(&extensions, "E", "search extension; pr=<size>[/noprompt] is supported")

	searchUnsupported := []unsupportedFlag{
		{name: "c", reason: "continuous operation mode is not implemented"},
		{name: "f", reason: "batch searches from a file are not implemented"},
		{name: "F", reason: "value-file URL prefixes are not implemented"},
		{name: "L", reason: "only -LLL is implemented"},
		{name: "LL", reason: "only -LLL is implemented"},
		{name: "S", reason: "client-side sorting is not implemented"},
		{name: "t", reason: "writing values to temporary files is not implemented"},
		{name: "T", reason: "temporary-file directory selection is not implemented"},
		{name: "u", reason: "user-friendly DN output is not implemented"},
	}
	flags.Bool("c", false, "unsupported: continuous operation mode")
	flags.String("f", "", "unsupported: batch search file")
	flags.String("F", "", "unsupported: value-file URL prefix")
	flags.Bool("L", false, "unsupported: use -LLL")
	flags.Bool("LL", false, "unsupported: use -LLL")
	flags.String("S", "", "unsupported: client-side sort attribute")
	flags.Bool("t", false, "unsupported: write values to files")
	flags.String("T", "", "unsupported: temporary-file directory")
	flags.Bool("u", false, "unsupported: user-friendly DN output")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validate(flags); err != nil {
		return err
	}
	if err := rejectUnsupportedFlags("ldapsearch", flags, searchUnsupported); err != nil {
		return err
	}
	if *sizeLimit < 0 {
		return errors.New("-z must be non-negative")
	}
	if *timeLimit < 0 {
		return errors.New("-l must be non-negative")
	}
	if flagWasSet(flags, "A") && !*typesOnly {
		return errors.New("-A=false is not supported")
	}
	if flagWasSet(flags, "LLL") && !*minimalLDIF {
		return errors.New("-LLL=false is not supported")
	}

	scope, err := parseLDAPSearchScope(*scopeName)
	if err != nil {
		return err
	}
	derefAliases, err := parseLDAPSearchDeref(*derefName)
	if err != nil {
		return err
	}
	if *baseDN != "" {
		if _, err := ldap.ParseDN(*baseDN); err != nil {
			return fmt.Errorf("parse search base DN: %w", err)
		}
	}
	filter := "(objectClass=*)"
	attributes := []string(nil)
	if flags.NArg() > 0 {
		filter = flags.Arg(0)
		attributes = flags.Args()[1:]
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		return fmt.Errorf("parse search filter: %w", err)
	}
	for _, attribute := range attributes {
		if attribute == "" || strings.ContainsAny(attribute, "\x00\r\n") {
			return fmt.Errorf("invalid empty or control-containing attribute selection %q", attribute)
		}
	}

	resolvedPageSize, extensionControls, err := resolveLDAPSearchExtensions(
		flags,
		*pageSize,
		extensions,
	)
	if err != nil {
		return err
	}
	defer clearLDAPControls(extensionControls)
	controls, err := mergeLDAPControls(client.generalControls, extensionControls)
	if err != nil {
		return fmt.Errorf("ldapsearch controls: %w", err)
	}
	connection, err := client.connectAndBind(flags, stdin, stderr)
	if err != nil {
		return err
	}
	defer connection.Close()

	request := ldap.NewSearchRequest(
		*baseDN,
		scope,
		derefAliases,
		*sizeLimit,
		*timeLimit,
		*typesOnly,
		filter,
		attributes,
		controls,
	)
	result, searchErr := client.searchWithReferrals(connection, request, resolvedPageSize)
	var outputErr error
	if result != nil {
		outputErr = writeLDAPSearchLDIF(stdout, result.Entries, *typesOnly, *minimalLDIF)
	}
	if searchErr != nil {
		if code, name, ok := ldapReferralClientResult(searchErr); ok {
			_, diagnosticErr := fmt.Fprintf(stderr, "ldap_result: %s (%d)\n", name, code)
			return &ldapClientExitError{
				code:  int(code),
				cause: errors.Join(outputErr, diagnosticErr),
			}
		}
		searchErr = fmt.Errorf("search: %w", searchErr)
	}
	return errors.Join(outputErr, searchErr)
}

func runLDAPWhoAmI(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldapwhoami", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validate(flags); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	connection, err := client.connectAndBind(flags, stdin, stderr)
	if err != nil {
		return err
	}
	defer connection.Close()
	authzID, err := ldapWhoAmIRequest(&client, connection, client.generalControls)
	if err != nil {
		return fmt.Errorf("Who Am I operation: %w", err)
	}
	defer clear(authzID)
	if len(authzID) == 0 {
		_, err = io.WriteString(stdout, "anonymous\n")
		return err
	}
	return writePasswordOutput(stdout, authzID, false)
}

func parseLDAPSearchScope(value string) (int, error) {
	switch strings.ToLower(value) {
	case "base":
		return ldap.ScopeBaseObject, nil
	case "one":
		return ldap.ScopeSingleLevel, nil
	case "sub":
		return ldap.ScopeWholeSubtree, nil
	case "children", "subordinate":
		return ldap.ScopeChildren, nil
	default:
		return 0, errors.New("-s must be base, one, sub, or children")
	}
}

func parseLDAPSearchDeref(value string) (int, error) {
	switch strings.ToLower(value) {
	case "never":
		return ldap.NeverDerefAliases, nil
	case "search":
		return ldap.DerefInSearching, nil
	case "find":
		return ldap.DerefFindingBaseObj, nil
	case "always":
		return ldap.DerefAlways, nil
	default:
		return 0, errors.New("-a must be never, search, find, or always")
	}
}

func resolveLDAPSearchExtensions(
	flags *flag.FlagSet,
	pageSize uint64,
	extensions repeatedStringFlag,
) (uint32, []ldap.Control, error) {
	pageExtension := ""
	controlSpecs := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		name := strings.TrimLeft(extension, "!")
		name, _, _ = strings.Cut(name, "=")
		if strings.EqualFold(name, "pr") {
			if pageExtension != "" {
				return 0, nil, errors.New(
					"ldapsearch paging extension was provided more than once",
				)
			}
			pageExtension = extension
			continue
		}
		controlSpecs = append(controlSpecs, extension)
	}
	if flagWasSet(flags, "page-size") && pageExtension != "" {
		return 0, nil, errors.New("-page-size and -E pr=... are mutually exclusive")
	}
	controls, err := parseLDAPControlSpecs(controlSpecs, ldapControlValueLDIF)
	if err != nil {
		return 0, nil, fmt.Errorf("ldapsearch -E: %w", err)
	}
	resolvedPageSize := uint32(0)
	if pageExtension != "" {
		resolvedPageSize, err = parseLDAPSearchPagingExtension(pageExtension)
		if err != nil {
			clearLDAPControls(controls)
			return 0, nil, err
		}
	} else if flagWasSet(flags, "page-size") {
		if pageSize == 0 || pageSize > uint64(^uint32(0)) {
			clearLDAPControls(controls)
			return 0, nil, errors.New("-page-size must be between 1 and 4294967295")
		}
		resolvedPageSize = uint32(pageSize)
	}
	return resolvedPageSize, controls, nil
}

func parseLDAPSearchPagingExtension(value string) (uint32, error) {
	if strings.HasPrefix(value, "!") {
		return 0, errors.New("critical -E !pr paging is not implemented")
	}
	name, parameter, found := strings.Cut(value, "=")
	if !found || !strings.EqualFold(name, "pr") {
		return 0, fmt.Errorf(
			"ldapsearch extension %q is not supported; use pr=<size>[/noprompt]",
			value,
		)
	}
	parts := strings.Split(parameter, "/")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("invalid paging extension %q", value)
	}
	if len(parts) == 2 {
		switch strings.ToLower(parts[1]) {
		case "noprompt":
		case "prompt":
			return 0, errors.New("interactive paging prompts are not implemented; use /noprompt")
		default:
			return 0, fmt.Errorf("invalid paging prompt mode %q", parts[1])
		}
	}
	size, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || size == 0 {
		return 0, fmt.Errorf("invalid paging size %q", parts[0])
	}
	return uint32(size), nil
}

func writeLDAPSearchLDIF(
	writer io.Writer,
	entries []*ldap.Entry,
	typesOnly,
	minimal bool,
) error {
	if !minimal {
		if err := writeFoldedLDIFLine(writer, []byte("version: 1")); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, "\n"); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if entry == nil {
			return errors.New("search returned a nil LDAP entry")
		}
		if err := writeLDIFAttribute(writer, "dn", []byte(entry.DN)); err != nil {
			return err
		}
		for _, attribute := range entry.Attributes {
			if attribute == nil {
				return fmt.Errorf("search entry %q contains a nil attribute", entry.DN)
			}
			if !validLDIFAttributeDescription(attribute.Name) {
				return fmt.Errorf(
					"search entry %q contains invalid attribute description %q",
					entry.DN,
					attribute.Name,
				)
			}
			if typesOnly {
				if err := writeLDIFAttribute(writer, attribute.Name, nil); err != nil {
					return err
				}
				continue
			}
			values := attribute.ByteValues
			if len(values) == 0 && len(attribute.Values) > 0 {
				values = make([][]byte, len(attribute.Values))
				for index := range attribute.Values {
					values[index] = []byte(attribute.Values[index])
				}
			}
			for _, value := range values {
				if err := writeLDIFAttribute(writer, attribute.Name, value); err != nil {
					return err
				}
			}
		}
		if _, err := io.WriteString(writer, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func writeLDIFAttribute(writer io.Writer, name string, value []byte) error {
	line := make([]byte, 0, len(name)+3+len(value)*2)
	line = append(line, name...)
	line = append(line, ':')
	if len(value) > 0 {
		if ldifValueRequiresBase64(value) {
			line = append(line, ':', ' ')
			encodedLength := base64.StdEncoding.EncodedLen(len(value))
			start := len(line)
			line = append(line, make([]byte, encodedLength)...)
			base64.StdEncoding.Encode(line[start:], value)
		} else {
			line = append(line, ' ')
			line = append(line, value...)
		}
	}
	return writeFoldedLDIFLine(writer, line)
}

func ldifValueRequiresBase64(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	if value[0] == ' ' || value[0] == ':' || value[0] == '<' || value[len(value)-1] == ' ' {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return true
		}
	}
	return false
}

func writeFoldedLDIFLine(writer io.Writer, line []byte) error {
	first := true
	for len(line) > 0 {
		width := ldapSearchLDIFLineWidth
		if !first {
			if _, err := writer.Write([]byte{' '}); err != nil {
				return err
			}
			width--
		}
		if width > len(line) {
			width = len(line)
		}
		if _, err := writer.Write(line[:width]); err != nil {
			return err
		}
		if _, err := writer.Write([]byte{'\n'}); err != nil {
			return err
		}
		line = line[width:]
		first = false
	}
	if first {
		_, err := writer.Write([]byte{'\n'})
		return err
	}
	return nil
}

func validLDIFAttributeDescription(value string) bool {
	parts := strings.Split(value, ";")
	if len(parts) == 0 || (!validLDAPKeyString(parts[0]) && !validNumericOID(parts[0])) {
		return false
	}
	for _, option := range parts[1:] {
		if !validLDAPKeyString(option) {
			return false
		}
	}
	return true
}

func validLDAPKeyString(value string) bool {
	if value == "" || !isASCIIAlpha(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isASCIIAlpha(value[index]) && (value[index] < '0' || value[index] > '9') && value[index] != '-' {
			return false
		}
	}
	return true
}

func validNumericOID(value string) bool {
	if value == "" {
		return false
	}
	expectDigit := true
	for index := 0; index < len(value); index++ {
		switch {
		case value[index] >= '0' && value[index] <= '9':
			expectDigit = false
		case value[index] == '.' && !expectDigit:
			expectDigit = true
		default:
			return false
		}
	}
	return !expectDigit
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
