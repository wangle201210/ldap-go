package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/lloadd"
	"golang.org/x/term"
)

const (
	defaultLDAPClientURI     = "ldap://localhost:389"
	defaultLDAPClientTimeout = 10 * time.Second
	defaultLDAPReferralHops  = 5
	maxClientCAFileSize      = 16 << 20
	ldapSearchLDIFLineWidth  = 78
	maxLDAPSearchBatchSize   = 8 << 20
	maxLDAPSearchBatchLine   = 1 << 20
	maxLDAPSearchBatchCount  = 100000
	maxLDAPSearchValueSize   = 64 << 20
	maxLDAPSearchPromptLine  = 32
)

type ldapClientOptions struct {
	uri                  string
	simple               bool
	bindDN               string
	saslMechanism        string
	saslAuthentication   string
	saslAuthorization    string
	saslRealm            string
	saslSecurity         string
	gssapiChannelBinding string
	directPassword       secretFlagValue
	promptPassword       bool
	passwordFile         string
	tryStartTLS          bool
	requireStartTLS      bool
	timeout              time.Duration
	tlsCAFile            string
	tlsCertificateFile   string
	tlsPrivateKeyFile    string
	tlsServerName        string
	dryRun               bool
	generalControlSpecs  repeatedStringFlag
	generalControls      []ldap.Control
	chaseReferrals       bool
	referralHopLimit     int
	unsupportedFlags     []unsupportedFlag
	observeSearch        bool
	searchObserver       *ldapSearchResponseObserver
	searchObserverMu     sync.Mutex
	referralObservers    []*ldapSearchResponseObserver
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
	flags.StringVar(&options.saslSecurity, "O", "", "SASL security properties")
	flags.StringVar(
		&options.gssapiChannelBinding,
		"gssapi-channel-binding",
		"",
		"explicit GSSAPI channel binding extension: tls-server-end-point",
	)
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
	options.searchObserver = nil
	options.searchObserverMu.Lock()
	options.referralObservers = nil
	options.searchObserverMu.Unlock()
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
		for _, name := range []string{"Y", "U", "X", "R", "O"} {
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
		flagWasSet(flags, "X") || flagWasSet(flags, "R") || flagWasSet(flags, "O")
	authenticationRequested := requireConnection || options.simple || saslFlagsSet ||
		options.bindDN != "" || passwordSources > 0
	if options.simple {
		if saslFlagsSet {
			return errors.New("-x cannot be combined with -Y, -U, -X, -R, or -O")
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
		if options.observeSearch {
			connection, observer, err := dialObservedLDAPConnection(
				dialURI,
				useTLS,
				false,
				tlsConfig,
				options.timeout,
			)
			if err == nil {
				options.searchObserver = observer
			}
			return connection, err
		}
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

	var connection *ldap.Conn
	if options.observeSearch && (options.tryStartTLS || options.requireStartTLS) {
		connection, options.searchObserver, err = dialObservedLDAPConnection(
			dialURI,
			false,
			true,
			tlsConfig,
			options.timeout,
		)
	} else {
		connection, err = dial(parsedURI.Scheme == "ldaps")
	}
	if err != nil {
		if !(options.observeSearch && options.tryStartTLS) {
			return nil, fmt.Errorf("connect to %s: %w", dialURI, err)
		}
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
	closeOnError := func(err error) (*ldap.Conn, error) {
		_ = connection.Close()
		return nil, err
	}

	if (options.tryStartTLS || options.requireStartTLS) && !options.observeSearch {
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
	if len(options.uri) >= len("ldapi://") &&
		strings.EqualFold(options.uri[:len("ldapi://")], "ldapi://") {
		path, err := lloadd.ParseLDAPIAddress(options.uri)
		if err != nil {
			return nil, "", nil, fmt.Errorf("parse LDAPI URI: %w", err)
		}
		if path == "" || path == "/" {
			path = "/var/run/slapd/ldapi"
		}
		if options.tryStartTLS || options.requireStartTLS {
			return nil, "", nil, errors.New("-Z and -ZZ cannot be used with an ldapi:// URI")
		}
		if flagWasSet(flags, "tls-ca") || flagWasSet(flags, "tls-cert") ||
			flagWasSet(flags, "tls-key") || flagWasSet(flags, "tls-server-name") {
			return nil, "", nil, errors.New("TLS options cannot be used with an ldapi:// URI")
		}
		return &url.URL{Scheme: "ldapi", Path: path}, options.uri, &tls.Config{
			MinVersion: tls.VersionTLS12,
		}, nil
	}
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

type ldapSearchResponseControl struct {
	oid      string
	critical bool
	value    []byte
	hasValue bool
}

type ldapSearchWireResponse struct {
	tag                 ber.Tag
	controls            []ldapSearchResponseControl
	intermediateOID     string
	intermediateData    []byte
	hasIntermediateData bool
}

type ldapSearchResponseObserver struct {
	mu          sync.Mutex
	readBuffer  []byte
	writeBuffer []byte
	searchIDs   []int64
	responses   map[int64][]ldapSearchWireResponse
}

type ldapSearchObservedConn struct {
	net.Conn
	observer *ldapSearchResponseObserver
}

func dialObservedLDAPConnection(
	rawURI string,
	directTLS,
	startTLS bool,
	tlsConfig *tls.Config,
	timeout time.Duration,
) (*ldap.Conn, *ldapSearchResponseObserver, error) {
	if len(rawURI) >= len("ldapi://") &&
		strings.EqualFold(rawURI[:len("ldapi://")], "ldapi://") {
		if directTLS || startTLS {
			return nil, nil, errors.New("TLS cannot be used with an ldapi:// URI")
		}
		path, err := lloadd.ParseLDAPIAddress(rawURI)
		if err != nil {
			return nil, nil, err
		}
		if path == "" || path == "/" {
			path = "/var/run/slapd/ldapi"
		}
		raw, err := (&net.Dialer{Timeout: timeout}).Dial("unix", path)
		if err != nil {
			return nil, nil, err
		}
		observer := &ldapSearchResponseObserver{
			responses: make(map[int64][]ldapSearchWireResponse),
		}
		connection := ldap.NewConn(
			&ldapSearchObservedConn{Conn: raw, observer: observer},
			false,
		)
		connection.SetTimeout(timeout)
		connection.Start()
		return connection, observer, nil
	}
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return nil, nil, err
	}
	port := parsed.Port()
	if port == "" {
		if directTLS {
			port = "636"
		} else {
			port = "389"
		}
	}
	raw, err := (&net.Dialer{Timeout: timeout}).Dial(
		"tcp",
		net.JoinHostPort(parsed.Hostname(), port),
	)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := func(err error) (*ldap.Conn, *ldapSearchResponseObserver, error) {
		return nil, nil, errors.Join(err, raw.Close())
	}

	transport := raw
	if startTLS {
		if err := requestLDAPStartTLS(raw, timeout); err != nil {
			return closeOnError(err)
		}
	}
	if directTLS || startTLS {
		secured := tls.Client(raw, tlsConfig.Clone())
		if err := secured.SetDeadline(time.Now().Add(timeout)); err != nil {
			return closeOnError(err)
		}
		if err := secured.Handshake(); err != nil {
			return closeOnError(err)
		}
		if err := secured.SetDeadline(time.Time{}); err != nil {
			return closeOnError(err)
		}
		transport = secured
	}

	observer := &ldapSearchResponseObserver{
		responses: make(map[int64][]ldapSearchWireResponse),
	}
	connection := ldap.NewConn(
		&ldapSearchObservedConn{Conn: transport, observer: observer},
		directTLS || startTLS,
	)
	connection.SetTimeout(timeout)
	connection.Start()
	return connection, observer, nil
}

func requestLDAPStartTLS(connection net.Conn, timeout time.Duration) error {
	request := ber.NewSequence("LDAP Request")
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"Message ID",
	))
	extended := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldap.ApplicationExtendedRequest,
		nil,
		"Extended Request",
	)
	extended.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"1.3.6.1.4.1.1466.20037",
		"Request Name",
	))
	request.AppendChild(extended)
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	encoded := request.Bytes()
	for len(encoded) > 0 {
		written, err := connection.Write(encoded)
		if err != nil {
			return fmt.Errorf("send StartTLS request: %w", err)
		}
		if written == 0 {
			return fmt.Errorf("send StartTLS request: %w", io.ErrNoProgress)
		}
		encoded = encoded[written:]
	}
	response, err := ber.ReadPacket(connection)
	if err != nil {
		return fmt.Errorf("read StartTLS response: %w", err)
	}
	if err := ldap.GetLDAPError(response); err != nil {
		return fmt.Errorf("StartTLS request: %w", err)
	}
	return connection.SetDeadline(time.Time{})
}

func (connection *ldapSearchObservedConn) Read(buffer []byte) (int, error) {
	count, err := connection.Conn.Read(buffer)
	if count > 0 {
		connection.observer.observeRead(buffer[:count])
	}
	return count, err
}

func (connection *ldapSearchObservedConn) Write(buffer []byte) (int, error) {
	count, err := connection.Conn.Write(buffer)
	if count > 0 {
		connection.observer.observeWrite(buffer[:count])
	}
	return count, err
}

func (observer *ldapSearchResponseObserver) observeRead(data []byte) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.readBuffer = append(observer.readBuffer, data...)
	observer.consumeFrames(&observer.readBuffer, false)
}

func (observer *ldapSearchResponseObserver) observeWrite(data []byte) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.writeBuffer = append(observer.writeBuffer, data...)
	observer.consumeFrames(&observer.writeBuffer, true)
}

func (observer *ldapSearchResponseObserver) consumeFrames(buffer *[]byte, request bool) {
	for {
		length, complete, valid := ldapBERFrameLength(*buffer)
		if !valid {
			*buffer = nil
			return
		}
		if !complete {
			return
		}
		frame := append([]byte(nil), (*buffer)[:length]...)
		*buffer = (*buffer)[length:]
		packet, err := ber.DecodePacketErr(frame)
		if err != nil || len(packet.Children) < 2 {
			continue
		}
		messageID, ok := packet.Children[0].Value.(int64)
		if !ok {
			continue
		}
		operation := packet.Children[1]
		if request {
			if operation.ClassType == ber.ClassApplication &&
				operation.Tag == ldap.ApplicationSearchRequest {
				observer.searchIDs = append(observer.searchIDs, messageID)
			}
			continue
		}
		if operation.ClassType != ber.ClassApplication {
			continue
		}
		switch operation.Tag {
		case ldap.ApplicationSearchResultEntry,
			ldap.ApplicationSearchResultDone,
			ldap.ApplicationSearchResultReference,
			ldap.ApplicationIntermediateResponse:
		default:
			continue
		}
		response := ldapSearchWireResponse{tag: operation.Tag}
		response.controls = parseLDAPSearchResponseControls(packet)
		if operation.Tag == ldap.ApplicationIntermediateResponse {
			for _, child := range operation.Children {
				switch {
				case child.ClassType == ber.ClassContext && child.Tag == 0:
					response.intermediateOID = ldapBERString(child)
				case child.ClassType == ber.ClassContext && child.Tag == 1:
					response.intermediateData = ldapBERBytes(child)
					response.hasIntermediateData = true
				}
			}
		}
		observer.responses[messageID] = append(observer.responses[messageID], response)
	}
}

func ldapBERFrameLength(data []byte) (int, bool, bool) {
	if len(data) < 2 {
		return 0, false, true
	}
	if data[0] != 0x30 {
		return 0, false, false
	}
	lengthBytes := int(data[1] & 0x7f)
	header := 2
	content := 0
	if data[1]&0x80 == 0 {
		content = int(data[1])
	} else {
		if lengthBytes == 0 || lengthBytes > 4 {
			return 0, false, false
		}
		if len(data) < 2+lengthBytes {
			return 0, false, true
		}
		header += lengthBytes
		for _, value := range data[2:header] {
			content = content<<8 | int(value)
		}
	}
	if content < 0 || content > maxLDAPSearchValueSize*4 {
		return 0, false, false
	}
	total := header + content
	return total, len(data) >= total, true
}

func parseLDAPSearchResponseControls(packet *ber.Packet) []ldapSearchResponseControl {
	if len(packet.Children) < 3 || packet.Children[2].ClassType != ber.ClassContext ||
		packet.Children[2].Tag != 0 {
		return nil
	}
	controls := make([]ldapSearchResponseControl, 0, len(packet.Children[2].Children))
	for _, encoded := range packet.Children[2].Children {
		if encoded == nil || len(encoded.Children) == 0 {
			continue
		}
		control := ldapSearchResponseControl{oid: ldapBERString(encoded.Children[0])}
		if control.oid == "" {
			continue
		}
		index := 1
		if index < len(encoded.Children) {
			if critical, ok := encoded.Children[index].Value.(bool); ok {
				control.critical = critical
				index++
			}
		}
		if index < len(encoded.Children) {
			control.value = ldapBERBytes(encoded.Children[index])
			control.hasValue = true
		}
		controls = append(controls, control)
	}
	return controls
}

func ldapBERString(packet *ber.Packet) string {
	if packet == nil {
		return ""
	}
	if value, ok := packet.Value.(string); ok {
		return value
	}
	return string(ldapBERBytes(packet))
}

func ldapBERBytes(packet *ber.Packet) []byte {
	if packet == nil {
		return nil
	}
	if packet.Data != nil {
		return append([]byte(nil), packet.Data.Bytes()...)
	}
	if value, ok := packet.Value.(string); ok {
		return []byte(value)
	}
	if value, ok := packet.Value.([]byte); ok {
		return append([]byte(nil), value...)
	}
	return nil
}

func (observer *ldapSearchResponseObserver) takeSearchResponses() []ldapSearchWireResponse {
	if observer == nil {
		return nil
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.searchIDs) == 0 {
		return nil
	}
	var responses []ldapSearchWireResponse
	for _, messageID := range observer.searchIDs {
		responses = append(responses, observer.responses[messageID]...)
		delete(observer.responses, messageID)
	}
	observer.searchIDs = nil
	return responses
}

func (options *ldapClientOptions) addReferralSearchObserver(
	observer *ldapSearchResponseObserver,
) {
	if observer == nil {
		return
	}
	options.searchObserverMu.Lock()
	options.referralObservers = append(options.referralObservers, observer)
	options.searchObserverMu.Unlock()
}

func (options *ldapClientOptions) takeSearchResponses() []ldapSearchWireResponse {
	responses := options.searchObserver.takeSearchResponses()
	options.searchObserverMu.Lock()
	referrals := options.referralObservers
	options.referralObservers = nil
	options.searchObserverMu.Unlock()
	for _, observer := range referrals {
		responses = append(responses, observer.takeSearchResponses()...)
	}
	return responses
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
) (runErr error) {
	args, ldifLevel, valuesToFilesLevel := normalizeLDAPSearchArgs(args)
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
	continuous := flags.Bool("c", false, "continue batch searches after LDAP operation errors")
	ldifOutput := flags.Bool("L", false, "increase LDIF output level")
	pageSize := flags.Uint64("page-size", 0, "RFC 2696 page size")
	batchPath := flags.String("f", "", "read batch filter values from a file, or - for stdin")
	valueURLPrefix := flags.String("F", "", "URL prefix for temporary value files")
	valuesToFiles := flags.Bool("t", false, "write attribute values to temporary files")
	temporaryDirectory := flags.String("T", "", "directory for temporary value files")
	sortAttribute := flags.String("S", "", "sort results by attribute; empty sorts by DN")
	includeUFN := flags.Bool("u", false, "include User Friendly entry names")
	var extensions repeatedStringFlag
	flags.Var(&extensions, "E", "search extension; [!]pr=<size>[/prompt|noprompt] is supported")

	if err := flags.Parse(args); err != nil {
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
	if flagWasSet(flags, "c") && !*continuous {
		return errors.New("-c=false is not supported")
	}
	if flagWasSet(flags, "L") && !*ldifOutput {
		return errors.New("-L=false is not supported")
	}
	if flagWasSet(flags, "f") && *batchPath == "" {
		return errors.New("-f requires a non-empty batch file path or - for stdin")
	}
	if flagWasSet(flags, "F") && *valueURLPrefix == "" {
		return errors.New("-F requires a non-empty URL prefix")
	}
	if flagWasSet(flags, "t") && !*valuesToFiles {
		return errors.New("-t=false is not supported")
	}
	if flagWasSet(flags, "T") && *temporaryDirectory == "" {
		return errors.New("-T requires a non-empty directory path")
	}
	if flagWasSet(flags, "u") && !*includeUFN {
		return errors.New("-u=false is not supported")
	}
	if flagWasSet(flags, "S") && *sortAttribute != "" &&
		!validLDIFAttributeDescription(*sortAttribute) {
		return fmt.Errorf("invalid -S attribute %q", *sortAttribute)
	}

	scope, err := parseLDAPSearchScope(*scopeName)
	if err != nil {
		return err
	}
	derefAliases, err := parseLDAPSearchDeref(*derefName)
	if err != nil {
		return err
	}
	directURL, err := parseLDAPSearchDirectURL(client.uri)
	if err != nil {
		return err
	}
	if directURL.direct {
		client.uri = directURL.dialURI
	}
	if err := client.validate(flags); err != nil {
		return err
	}

	resolvedBaseDN := *baseDN
	if directURL.direct && !flagWasSet(flags, "b") {
		resolvedBaseDN = directURL.baseDN
	}
	if resolvedBaseDN != "" {
		if _, err := ldap.ParseDN(resolvedBaseDN); err != nil {
			return fmt.Errorf("parse search base DN: %w", err)
		}
	}
	if directURL.direct && !flagWasSet(flags, "s") {
		scope = directURL.scope
	}
	filter := "(objectClass=*)"
	attributes := []string(nil)
	if directURL.direct {
		filter = directURL.filter
		attributes = append(attributes, directURL.attributes...)
		positionalFilter, positionalAttributes := splitLDAPSearchArguments(flags.Args())
		if positionalFilter != "" {
			filter = positionalFilter
		}
		if positionalAttributes != nil {
			attributes = positionalAttributes
		}
	} else if flags.NArg() > 0 {
		filter = flags.Arg(0)
		attributes = flags.Args()[1:]
	}
	batchPatternIndex := -1
	if *batchPath != "" {
		batchPatternIndex, err = validateLDAPSearchBatchPattern(filter)
		if err != nil {
			return err
		}
	}
	for _, attribute := range attributes {
		if attribute == "" || strings.ContainsAny(attribute, "\x00\r\n") {
			return fmt.Errorf("invalid empty or control-containing attribute selection %q", attribute)
		}
	}

	paging, extensionControls, err := resolveLDAPSearchExtensions(
		flags,
		*pageSize,
		extensions,
	)
	if err != nil {
		return err
	}
	defer clearLDAPControls(extensionControls)
	if client.chaseReferrals && paging.size > 0 && (paging.critical || paging.prompt) {
		return errors.New(
			"critical or prompt RFC 2696 paging cannot be combined with referral chasing; use non-critical pr=<size>/noprompt or disable -C",
		)
	}
	controls, err := mergeLDAPControls(client.generalControls, extensionControls)
	if err != nil {
		return fmt.Errorf("ldapsearch controls: %w", err)
	}
	valueFiles, err := openLDAPSearchValueFiles(
		valuesToFilesLevel > 0,
		*temporaryDirectory,
		*valueURLPrefix,
	)
	if err != nil {
		return err
	}
	if valueFiles != nil {
		defer func() {
			runErr = errors.Join(runErr, valueFiles.Close())
		}()
	}
	client.observeSearch = true

	queries := []string{filter}
	if *batchPath != "" && *batchPath != "-" {
		queries, err = readLDAPSearchBatchFileForSearch(*batchPath, filter, batchPatternIndex)
		if err != nil {
			return err
		}
	}
	connection, err := client.connectAndBind(flags, stdin, stderr)
	if err != nil {
		return err
	}
	defer connection.Close()
	if *batchPath == "-" {
		queries, err = readLDAPSearchBatchForSearch(
			stdin,
			filter,
			batchPatternIndex,
			"standard input",
		)
		if err != nil {
			return err
		}
	}

	output := &ldapSearchLDIFOutput{
		writer:        stdout,
		typesOnly:     *typesOnly,
		level:         ldifLevel,
		valueFiles:    valueFiles,
		allValueFiles: valuesToFilesLevel > 1,
		sort:          flagWasSet(flags, "S"),
		sortAttribute: *sortAttribute,
		includeUFN:    *includeUFN,
	}
	if err := output.start(ldapSearchOutputMetadata{
		baseDN:        resolvedBaseDN,
		scope:         scope,
		filterPattern: filter,
		attributes:    attributes,
		batch:         *batchPath != "",
	}); err != nil {
		return err
	}
	var promptReader *bufio.Reader
	if paging.prompt {
		promptReader = bufio.NewReader(stdin)
	}
	var continuousErr error
	for index, query := range queries {
		if err := output.startQuery(query, index); err != nil {
			return err
		}
		if _, err := ldap.CompileFilter(query); err != nil {
			queryErr := ldapSearchFilterCompileError(stderr)
			if !*continuous {
				return queryErr
			}
			continuousErr = queryErr
			continue
		}
		request := ldap.NewSearchRequest(
			resolvedBaseDN,
			scope,
			derefAliases,
			*sizeLimit,
			*timeLimit,
			*typesOnly,
			query,
			attributes,
			controls,
		)
		if err := runLDAPSearchQuery(
			&client,
			connection,
			request,
			paging,
			promptReader,
			stdout,
			stderr,
			output,
		); err != nil {
			if !*continuous || !ldapSearchCanContinue(err) {
				return err
			}
			continuousErr = err
		}
	}
	return continuousErr
}

func normalizeLDAPSearchArgs(args []string) ([]string, int, int) {
	normalized := make([]string, 0, len(args))
	ldifLevel := 0
	valueFileLevel := 0
	options := true
	for _, argument := range args {
		if options && argument == "--" {
			options = false
			normalized = append(normalized, argument)
			continue
		}
		if options && len(argument) > 1 && argument[0] == '-' &&
			strings.Trim(argument[1:], "L") == "" {
			count := len(argument) - 1
			ldifLevel += count
			for range count {
				normalized = append(normalized, "-L")
			}
			continue
		}
		if options && len(argument) > 1 && argument[0] == '-' &&
			strings.Trim(argument[1:], "t") == "" {
			count := len(argument) - 1
			valueFileLevel += count
			for range count {
				normalized = append(normalized, "-t")
			}
			continue
		}
		normalized = append(normalized, argument)
	}
	return normalized, min(ldifLevel, 3), min(valueFileLevel, 2)
}

func normalizeLDAPSearchLDIFArgs(args []string) ([]string, int) {
	normalized, level, _ := normalizeLDAPSearchArgs(args)
	return normalized, level
}

type ldapSearchDirectURL struct {
	direct     bool
	dialURI    string
	baseDN     string
	attributes []string
	scope      int
	filter     string
}

func parseLDAPSearchDirectURL(rawURI string) (ldapSearchDirectURL, error) {
	if len(rawURI) >= len("ldapi://") &&
		strings.EqualFold(rawURI[:len("ldapi://")], "ldapi://") {
		if _, err := lloadd.ParseLDAPIAddress(rawURI); err != nil {
			return ldapSearchDirectURL{}, fmt.Errorf("parse LDAPI search URL: %w", err)
		}
		return ldapSearchDirectURL{}, nil
	}
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return ldapSearchDirectURL{}, fmt.Errorf("parse LDAP search URL: %w", err)
	}
	if parsed.Opaque != "" {
		return ldapSearchDirectURL{}, errors.New("LDAP search URL must use // authority syntax")
	}
	if strings.Contains(rawURI, "#") {
		return ldapSearchDirectURL{}, errors.New("LDAP search URL fragments are not permitted by RFC 4516")
	}

	escapedPath := parsed.EscapedPath()
	direct := (escapedPath != "" && escapedPath != "/") || parsed.RawQuery != "" || parsed.ForceQuery
	if !direct {
		return ldapSearchDirectURL{}, nil
	}
	if escapedPath == "" || escapedPath[0] != '/' {
		return ldapSearchDirectURL{}, errors.New("LDAP search URL query requires a / before the DN")
	}
	rawDN := escapedPath[1:]
	if strings.Contains(rawDN, "/") {
		return ldapSearchDirectURL{}, errors.New("LDAP search URL DN must percent-encode reserved / characters")
	}
	baseDN, err := decodeLDAPSearchURLComponent(rawDN, "DN")
	if err != nil {
		return ldapSearchDirectURL{}, err
	}
	if baseDN != "" {
		if _, err := ldap.ParseDN(baseDN); err != nil {
			return ldapSearchDirectURL{}, fmt.Errorf("parse LDAP search URL DN: %w", err)
		}
	}

	components := []string(nil)
	if parsed.RawQuery != "" || parsed.ForceQuery {
		components = strings.Split(parsed.RawQuery, "?")
		if len(components) > 4 {
			return ldapSearchDirectURL{}, errors.New("LDAP search URL has more than four query components")
		}
	}

	attributes := []string(nil)
	if len(components) > 0 && components[0] != "" {
		for _, rawAttribute := range strings.Split(components[0], ",") {
			attribute, err := decodeLDAPSearchURLComponent(rawAttribute, "attribute")
			if err != nil {
				return ldapSearchDirectURL{}, err
			}
			if !validLDIFAttributeDescription(attribute) {
				return ldapSearchDirectURL{}, fmt.Errorf(
					"invalid LDAP search URL attribute description %q",
					attribute,
				)
			}
			attributes = append(attributes, attribute)
		}
	}

	scope := ldap.ScopeBaseObject
	if len(components) > 1 && components[1] != "" {
		scopeName, err := decodeLDAPSearchURLComponent(components[1], "scope")
		if err != nil {
			return ldapSearchDirectURL{}, err
		}
		switch strings.ToLower(scopeName) {
		case "base":
			scope = ldap.ScopeBaseObject
		case "one":
			scope = ldap.ScopeSingleLevel
		case "sub":
			scope = ldap.ScopeWholeSubtree
		default:
			return ldapSearchDirectURL{}, fmt.Errorf(
				"invalid LDAP search URL scope %q; RFC 4516 permits base, one, or sub",
				scopeName,
			)
		}
	}

	filter := "(objectClass=*)"
	if len(components) > 2 && components[2] != "" {
		filter, err = decodeLDAPSearchURLComponent(components[2], "filter")
		if err != nil {
			return ldapSearchDirectURL{}, err
		}
		if _, err := ldap.CompileFilter(filter); err != nil {
			return ldapSearchDirectURL{}, fmt.Errorf("invalid LDAP search URL filter: %w", err)
		}
	}

	if len(components) > 3 {
		if components[3] == "" {
			return ldapSearchDirectURL{}, errors.New("LDAP search URL contains an empty extensions component")
		}
		for _, rawExtension := range strings.Split(components[3], ",") {
			extension, err := decodeLDAPSearchURLComponent(rawExtension, "extension")
			if err != nil {
				return ldapSearchDirectURL{}, err
			}
			critical := strings.HasPrefix(extension, "!")
			if critical {
				extension = extension[1:]
			}
			extensionType, _, _ := strings.Cut(extension, "=")
			if !validLDAPKeyString(extensionType) && !validNumericOID(extensionType) {
				return ldapSearchDirectURL{}, fmt.Errorf(
					"invalid LDAP search URL extension type %q",
					extensionType,
				)
			}
			if critical {
				return ldapSearchDirectURL{}, fmt.Errorf(
					"unsupported critical LDAP search URL extension %q",
					extensionType,
				)
			}
		}
	}

	dialURL := *parsed
	dialURL.Path = ""
	dialURL.RawPath = ""
	dialURL.RawQuery = ""
	dialURL.ForceQuery = false
	dialURL.Fragment = ""
	dialURL.RawFragment = ""
	return ldapSearchDirectURL{
		direct:     true,
		dialURI:    dialURL.String(),
		baseDN:     baseDN,
		attributes: attributes,
		scope:      scope,
		filter:     filter,
	}, nil
}

func decodeLDAPSearchURLComponent(raw, name string) (string, error) {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("decode LDAP search URL %s: %w", name, err)
	}
	if !utf8.ValidString(decoded) {
		return "", fmt.Errorf("LDAP search URL %s is not valid UTF-8", name)
	}
	if strings.ContainsAny(decoded, "\x00\r\n") {
		return "", fmt.Errorf("LDAP search URL %s contains a prohibited control character", name)
	}
	return decoded, nil
}

func splitLDAPSearchArguments(arguments []string) (string, []string) {
	if len(arguments) == 0 {
		return "", nil
	}
	if strings.HasPrefix(arguments[0], "(") || strings.Contains(arguments[0], "=") {
		if len(arguments) == 1 {
			return arguments[0], nil
		}
		return arguments[0], arguments[1:]
	}
	return "", arguments
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

type ldapSearchPagingOptions struct {
	size     uint32
	critical bool
	prompt   bool
}

func resolveLDAPSearchExtensions(
	flags *flag.FlagSet,
	pageSize uint64,
	extensions repeatedStringFlag,
) (ldapSearchPagingOptions, []ldap.Control, error) {
	pageExtension := ""
	matchedValuesExtension := ""
	domainScopeExtension := ""
	controlSpecs := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		name := strings.TrimLeft(extension, "!")
		name, _, _ = strings.Cut(name, "=")
		if strings.EqualFold(name, "pr") {
			if pageExtension != "" {
				return ldapSearchPagingOptions{}, nil, errors.New(
					"ldapsearch paging extension was provided more than once",
				)
			}
			pageExtension = extension
			continue
		}
		if strings.EqualFold(name, "mv") {
			if matchedValuesExtension != "" {
				return ldapSearchPagingOptions{}, nil, errors.New(
					"ldapsearch matched-values extension was provided more than once",
				)
			}
			matchedValuesExtension = extension
			continue
		}
		if strings.EqualFold(name, "domainScope") {
			if domainScopeExtension != "" {
				return ldapSearchPagingOptions{}, nil, errors.New(
					"ldapsearch domainScope extension was provided more than once",
				)
			}
			domainScopeExtension = extension
			continue
		}
		controlSpecs = append(controlSpecs, extension)
	}
	if flagWasSet(flags, "page-size") && pageExtension != "" {
		return ldapSearchPagingOptions{}, nil, errors.New("-page-size and -E pr=... are mutually exclusive")
	}
	controls, err := parseLDAPControlSpecs(controlSpecs, ldapControlValueLDIF)
	if err != nil {
		return ldapSearchPagingOptions{}, nil, fmt.Errorf("ldapsearch -E: %w", err)
	}
	if matchedValuesExtension != "" {
		control, controlErr := parseLDAPSearchMatchedValuesExtension(matchedValuesExtension)
		if controlErr != nil {
			clearLDAPControls(controls)
			return ldapSearchPagingOptions{}, nil, controlErr
		}
		for _, existing := range controls {
			if existing.GetControlType() == ldapwire.MatchedValuesControlOID {
				if raw, ok := control.(*ldapRawControl); ok {
					raw.clear()
				}
				clearLDAPControls(controls)
				return ldapSearchPagingOptions{}, nil, fmt.Errorf(
					"LDAP control %s was provided more than once",
					ldapwire.MatchedValuesControlOID,
				)
			}
		}
		controls = append(controls, control)
	}
	if domainScopeExtension != "" {
		control, controlErr := parseLDAPSearchDomainScopeExtension(domainScopeExtension)
		if controlErr != nil {
			clearLDAPControls(controls)
			return ldapSearchPagingOptions{}, nil, controlErr
		}
		for _, existing := range controls {
			if existing.GetControlType() == ldapwire.DomainScopeControlOID {
				clearLDAPControls(controls)
				return ldapSearchPagingOptions{}, nil, fmt.Errorf(
					"LDAP control %s was provided more than once",
					ldapwire.DomainScopeControlOID,
				)
			}
		}
		controls = append(controls, control)
	}
	paging := ldapSearchPagingOptions{}
	if pageExtension != "" {
		paging, err = parseLDAPSearchPagingExtension(pageExtension)
		if err != nil {
			clearLDAPControls(controls)
			return ldapSearchPagingOptions{}, nil, err
		}
	} else if flagWasSet(flags, "page-size") {
		if pageSize == 0 || pageSize > uint64(^uint32(0)) {
			clearLDAPControls(controls)
			return ldapSearchPagingOptions{}, nil, errors.New("-page-size must be between 1 and 4294967295")
		}
		paging.size = uint32(pageSize)
	}
	return paging, controls, nil
}

func parseLDAPSearchDomainScopeExtension(value string) (ldap.Control, error) {
	critical := strings.HasPrefix(value, "!")
	if critical {
		value = value[1:]
	}
	if !strings.EqualFold(value, "domainScope") {
		return nil, fmt.Errorf("invalid domainScope extension %q", value)
	}
	return &ldapRawControl{
		oid:      ldapwire.DomainScopeControlOID,
		critical: critical,
	}, nil
}

func parseLDAPSearchMatchedValuesExtension(value string) (ldap.Control, error) {
	critical := strings.HasPrefix(value, "!")
	value = strings.TrimLeft(value, "!")
	name, parameter, found := strings.Cut(value, "=")
	if !found || !strings.EqualFold(name, "mv") || strings.TrimSpace(parameter) == "" {
		return nil, fmt.Errorf("invalid matched-values extension %q", value)
	}
	items, err := splitLDAPSearchMatchedValuesFilters(parameter)
	if err != nil {
		return nil, err
	}
	sequence := ber.NewSequence("ValuesReturnFilter")
	for _, item := range items {
		packet, err := ldap.CompileFilter(item)
		if err != nil || packet.ClassType != ber.ClassContext || packet.Tag < 3 || packet.Tag > 9 {
			return nil, fmt.Errorf("invalid matched-values simple filter %q", item)
		}
		sequence.AppendChild(packet)
	}
	return &ldapRawControl{
		oid:      ldapwire.MatchedValuesControlOID,
		critical: critical,
		value:    sequence.Bytes(),
		hasValue: true,
	}, nil
}

func splitLDAPSearchMatchedValuesFilters(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "(") {
		value = "(" + value + ")"
	}
	items, err := splitLDAPSearchTopLevelFilters(value)
	if err != nil {
		return nil, fmt.Errorf("invalid matched-values filter %q", value)
	}
	if len(items) == 1 && items[0] == value {
		inner := strings.TrimSpace(value[1 : len(value)-1])
		if strings.HasPrefix(inner, "(") {
			items, err = splitLDAPSearchTopLevelFilters(inner)
			if err != nil {
				return nil, fmt.Errorf("invalid matched-values filter list %q", value)
			}
		}
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("matched-values filter list is empty")
	}
	return items, nil
}

func splitLDAPSearchTopLevelFilters(value string) ([]string, error) {
	var items []string
	for offset := 0; offset < len(value); {
		for offset < len(value) && (value[offset] == ' ' || value[offset] == '\t') {
			offset++
		}
		if offset == len(value) {
			break
		}
		if value[offset] != '(' {
			return nil, errors.New("filter item does not start with '('")
		}
		start := offset
		depth := 0
		escaped := false
		for ; offset < len(value); offset++ {
			switch {
			case escaped:
				escaped = false
			case value[offset] == '\\':
				escaped = true
			case value[offset] == '(':
				depth++
			case value[offset] == ')':
				depth--
				if depth == 0 {
					offset++
					items = append(items, value[start:offset])
					goto next
				}
				if depth < 0 {
					return nil, errors.New("unbalanced filter parentheses")
				}
			}
		}
		return nil, errors.New("unterminated filter item")
	next:
	}
	return items, nil
}

func parseLDAPSearchPagingExtension(value string) (ldapSearchPagingOptions, error) {
	paging := ldapSearchPagingOptions{critical: strings.HasPrefix(value, "!"), prompt: true}
	value = strings.TrimLeft(value, "!")
	name, parameter, found := strings.Cut(value, "=")
	if !found || !strings.EqualFold(name, "pr") {
		return ldapSearchPagingOptions{}, fmt.Errorf(
			"ldapsearch extension %q is not supported; use pr=<size>[/noprompt]",
			value,
		)
	}
	parts := strings.Split(parameter, "/")
	if len(parts) > 2 || parts[0] == "" {
		return ldapSearchPagingOptions{}, fmt.Errorf("invalid paging extension %q", value)
	}
	if len(parts) == 2 {
		switch strings.ToLower(parts[1]) {
		case "noprompt":
			paging.prompt = false
		case "prompt":
		default:
			return ldapSearchPagingOptions{}, fmt.Errorf("invalid paging prompt mode %q", parts[1])
		}
	}
	size, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || size == 0 {
		return ldapSearchPagingOptions{}, fmt.Errorf("invalid paging size %q", parts[0])
	}
	paging.size = uint32(size)
	return paging, nil
}

func validateLDAPSearchBatchPattern(pattern string) (int, error) {
	placeholder := -1
	for index := 0; index < len(pattern); index++ {
		if pattern[index] != '%' {
			continue
		}
		if placeholder >= 0 || index+1 >= len(pattern) || pattern[index+1] != 's' {
			return -1, errors.New("-f filter pattern may contain at most one %s and no other % characters")
		}
		placeholder = index
		index++
	}
	return placeholder, nil
}

func readLDAPSearchBatchFile(path, pattern string, placeholder int) ([]string, error) {
	return readLDAPSearchBatchFileMode(path, pattern, placeholder, true)
}

func readLDAPSearchBatchFileForSearch(
	path, pattern string,
	placeholder int,
) ([]string, error) {
	return readLDAPSearchBatchFileMode(path, pattern, placeholder, false)
}

func readLDAPSearchBatchFileMode(
	path, pattern string,
	placeholder int,
	validateFilters bool,
) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve -f batch file path: %w", err)
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect -f batch file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("-f batch input must be a non-symlink regular file")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("-f batch input must not be writable by group or other users")
	}
	if before.Size() > maxLDAPSearchBatchSize {
		return nil, fmt.Errorf("-f batch input exceeds %d bytes", maxLDAPSearchBatchSize)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, fmt.Errorf("open -f batch file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened -f batch file: %w", err)
	}
	after, err := os.Lstat(absolute)
	if err != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, errors.New("-f batch file changed while it was being opened")
	}
	return readLDAPSearchBatchMode(
		file,
		pattern,
		placeholder,
		"-f batch file",
		validateFilters,
	)
}

func readLDAPSearchBatch(
	reader io.Reader,
	pattern string,
	placeholder int,
	source string,
) ([]string, error) {
	return readLDAPSearchBatchMode(reader, pattern, placeholder, source, true)
}

func readLDAPSearchBatchForSearch(
	reader io.Reader,
	pattern string,
	placeholder int,
	source string,
) ([]string, error) {
	return readLDAPSearchBatchMode(reader, pattern, placeholder, source, false)
}

func readLDAPSearchBatchMode(
	reader io.Reader,
	pattern string,
	placeholder int,
	source string,
	validateFilters bool,
) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxLDAPSearchBatchSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	defer clear(data)
	if len(data) > maxLDAPSearchBatchSize {
		return nil, fmt.Errorf("%s exceeds %d bytes", source, maxLDAPSearchBatchSize)
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 && len(data) > 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLDAPSearchBatchCount {
		return nil, fmt.Errorf("%s exceeds %d queries", source, maxLDAPSearchBatchCount)
	}
	queries := make([]string, 0, len(lines))
	for index, line := range lines {
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > maxLDAPSearchBatchLine {
			return nil, fmt.Errorf("%s line %d exceeds %d bytes", source, index+1, maxLDAPSearchBatchLine)
		}
		if bytes.IndexByte(line, 0) >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			return nil, fmt.Errorf("%s line %d contains a prohibited control character", source, index+1)
		}
		query := pattern
		if placeholder >= 0 {
			var builder strings.Builder
			builder.Grow(len(pattern) - 2 + len(line))
			builder.WriteString(pattern[:placeholder])
			_, _ = builder.Write(line)
			builder.WriteString(pattern[placeholder+2:])
			query = builder.String()
		}
		if len(query) > maxLDAPSearchBatchLine*2 {
			return nil, fmt.Errorf("%s line %d produces an oversized search filter", source, index+1)
		}
		if validateFilters {
			if _, err := ldap.CompileFilter(query); err != nil {
				return nil, fmt.Errorf("%s line %d produces an invalid search filter", source, index+1)
			}
		}
		queries = append(queries, query)
	}
	return queries, nil
}

func runLDAPSearchQuery(
	client *ldapClientOptions,
	connection *ldap.Conn,
	request *ldap.SearchRequest,
	paging ldapSearchPagingOptions,
	promptReader *bufio.Reader,
	stdout, stderr io.Writer,
	output *ldapSearchLDIFOutput,
) error {
	if paging.size == 0 ||
		(!paging.critical && !paging.prompt && !output.sort && output.level >= 2) {
		messageID := output.nextSearchMessageID()
		result, searchErr := client.searchWithReferrals(connection, request, paging.size)
		wireResponses := client.takeSearchResponses()
		var outputErr error
		if result != nil {
			outputErr = output.writeEntriesWithResponses(result.Entries, wireResponses)
		}
		if outputErr == nil {
			outputErr = output.writeResult(result, searchErr, true, messageID, wireResponses)
		}
		return ldapSearchResultError(searchErr, outputErr, stderr, output.level)
	}

	pageSize := paging.size
	var cookie []byte
	defer clear(cookie)
	for {
		messageID := output.nextSearchMessageID()
		pagingControl := newLDAPSearchPagingControl(pageSize, cookie, paging.critical)
		sent := *request
		sent.Controls = append(cloneLDAPControls(request.Controls), pagingControl)
		result, searchErr := client.searchWithReferrals(connection, &sent, 0)
		wireResponses := client.takeSearchResponses()
		clearLDAPControls(sent.Controls)
		var outputErr error
		if result != nil {
			outputErr = output.writeEntriesWithResponses(result.Entries, wireResponses)
		}
		if outputErr != nil {
			return outputErr
		}
		if searchErr != nil {
			if err := output.writeResult(result, searchErr, true, messageID, wireResponses); err != nil {
				return errors.Join(err, searchErr)
			}
			return ldapSearchResultError(searchErr, nil, stderr, output.level)
		}
		if result == nil {
			return errors.New("search completed without a result")
		}
		responseControl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if responseControl == nil {
			if err := output.writeResult(result, nil, true, messageID, wireResponses); err != nil {
				return err
			}
			return nil
		}
		responsePaging, ok := responseControl.(*ldap.ControlPaging)
		if !ok {
			return errors.New("search returned a malformed RFC 2696 paging control")
		}
		clear(cookie)
		cookie = append(cookie[:0], responsePaging.Cookie...)
		if err := output.writeResult(
			result,
			nil,
			len(cookie) == 0,
			messageID,
			wireResponses,
		); err != nil {
			return err
		}
		if len(cookie) == 0 {
			return nil
		}
		if !paging.prompt {
			continue
		}
		if responsePaging.PagingSize > 0 {
			if _, err := fmt.Fprintf(stdout, "Estimate entries: %d\n", responsePaging.PagingSize); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(
			stdout,
			"Press [size] Enter for the next {%d|size} entries.\n",
			pageSize,
		); err != nil {
			return err
		}
		updated, provided, err := readLDAPSearchPagingPrompt(promptReader)
		if err != nil {
			return err
		}
		if provided {
			pageSize = updated
		}
	}
}

func ldapSearchResultError(searchErr, outputErr error, stderr io.Writer, ldifLevel int) error {
	if searchErr == nil {
		return outputErr
	}
	if outputErr != nil {
		return errors.Join(outputErr, searchErr)
	}
	if code, name, ok := ldapReferralClientResult(searchErr); ok {
		_, diagnosticErr := fmt.Fprintf(stderr, "ldap_result: %s (%d)\n", name, code)
		return &ldapClientExitError{
			code:  int(code),
			cause: errors.Join(outputErr, diagnosticErr),
		}
	}
	var ldapError *ldap.Error
	if errors.As(searchErr, &ldapError) {
		code := ldapError.ResultCode
		var diagnosticErr error
		if ldifLevel > 0 {
			_, diagnosticErr = fmt.Fprintf(
				stderr,
				"%s (%d)\n",
				openLDAPResultName(code),
				code,
			)
			if ldapError.MatchedDN != "" {
				_, err := fmt.Fprintf(stderr, "Matched DN: %s\n", ldapError.MatchedDN)
				diagnosticErr = errors.Join(diagnosticErr, err)
			}
			if information := ldapErrorDiagnostic(ldapError); information != "" {
				_, err := fmt.Fprintf(stderr, "Additional information: %s\n", information)
				diagnosticErr = errors.Join(diagnosticErr, err)
			}
			for _, referral := range ldapSearchResultReferrals(searchErr) {
				_, err := fmt.Fprintf(stderr, "Referral: %s\n", referral)
				diagnosticErr = errors.Join(diagnosticErr, err)
			}
		}
		return &ldapClientExitError{code: int(code), cause: diagnosticErr}
	}
	return errors.Join(outputErr, fmt.Errorf("search: %w", searchErr))
}

func ldapSearchFilterCompileError(stderr io.Writer) error {
	_, err := io.WriteString(stderr, "ldap_search_ext: Bad search filter (-7)\n")
	return &ldapClientExitError{code: 249, cause: err}
}

func ldapSearchResultReferrals(err error) []string {
	if referrals := ldapReferralURLs(err); len(referrals) > 0 {
		return referrals
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.Packet == nil ||
		len(ldapError.Packet.Children) < 2 {
		return nil
	}
	operation := ldapError.Packet.Children[1]
	if operation == nil {
		return nil
	}
	var referrals []string
	for _, child := range operation.Children {
		if child == nil || child.ClassType != ber.ClassContext || child.Tag != 3 {
			continue
		}
		for _, value := range child.Children {
			if value == nil {
				continue
			}
			referral, _ := value.Value.(string)
			if referral == "" && value.Data != nil {
				referral = value.Data.String()
			}
			if referral != "" {
				referrals = append(referrals, referral)
			}
		}
	}
	return referrals
}

func ldapSearchCanContinue(err error) bool {
	var exitError *ldapClientExitError
	return errors.As(err, &exitError)
}

func openLDAPResultName(code uint16) string {
	name := strings.ToLower(ldap.LDAPResultCodeMap[code])
	if name == "" {
		return "Unknown error"
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func ldapErrorDiagnostic(ldapError *ldap.Error) string {
	if ldapError == nil || ldapError.Err == nil {
		return ""
	}
	diagnostic := ldapError.Err.Error()
	if diagnostic == "<nil>" {
		return ""
	}
	return diagnostic
}

func newLDAPSearchPagingControl(size uint32, cookie []byte, critical bool) *ldapRawControl {
	sequence := ber.NewSequence("Search Control Value")
	sequence.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(size),
		"Paging Size",
	))
	cookiePacket := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"Cookie",
	)
	cookiePacket.Value = cookie
	_, _ = cookiePacket.Data.Write(cookie)
	sequence.AppendChild(cookiePacket)
	return &ldapRawControl{
		oid:      ldap.ControlTypePaging,
		critical: critical,
		value:    sequence.Bytes(),
		hasValue: true,
	}
}

func readLDAPSearchPagingPrompt(reader *bufio.Reader) (uint32, bool, error) {
	if reader == nil {
		return 0, false, nil
	}
	line := make([]byte, 0, 10)
	defer clear(line)
	for {
		character, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(line) == 0 {
					return 0, false, nil
				}
				break
			}
			return 0, false, fmt.Errorf("read paging prompt: %w", err)
		}
		if character == '\n' {
			break
		}
		if character == '\r' {
			continue
		}
		if len(line) >= maxLDAPSearchPromptLine {
			return 0, false, fmt.Errorf("paging prompt input exceeds %d bytes", maxLDAPSearchPromptLine)
		}
		line = append(line, character)
	}
	if len(line) == 0 {
		return 0, false, nil
	}
	size, err := strconv.ParseUint(string(line), 10, 32)
	if err != nil || size == 0 {
		return 0, false, errors.New("paging prompt input must be a positive 32-bit page size or an empty line")
	}
	return uint32(size), true, nil
}

type ldapSearchLDIFOutput struct {
	writer        io.Writer
	typesOnly     bool
	level         int
	minimal       bool
	started       bool
	valueFiles    *ldapSearchValueFiles
	allValueFiles bool
	sort          bool
	sortAttribute string
	includeUFN    bool
	batch         bool
	responses     int
	entries       int
	references    int
	partials      int
	messageID     int64
}

type ldapSearchOutputMetadata struct {
	baseDN        string
	scope         int
	filterPattern string
	attributes    []string
	batch         bool
}

func (output *ldapSearchLDIFOutput) start(metadata ldapSearchOutputMetadata) error {
	output.batch = metadata.batch
	if err := output.ensureStarted(); err != nil {
		return err
	}
	if output.level >= 2 {
		return nil
	}
	scope := "subtree"
	switch metadata.scope {
	case ldap.ScopeBaseObject:
		scope = "baseObject"
	case ldap.ScopeSingleLevel:
		scope = "oneLevel"
	case ldap.ScopeChildren:
		scope = "children"
	}
	filterLabel := "filter"
	if metadata.batch {
		filterLabel = "filter pattern"
	}
	if _, err := fmt.Fprintf(
		output.writer,
		"#\n# LDAPv3\n# base <%s> with scope %s\n# %s: %s\n# requesting: ",
		metadata.baseDN,
		scope,
		filterLabel,
		metadata.filterPattern,
	); err != nil {
		return err
	}
	if len(metadata.attributes) == 0 {
		if _, err := io.WriteString(output.writer, "ALL"); err != nil {
			return err
		}
	} else {
		for _, attribute := range metadata.attributes {
			if _, err := fmt.Fprintf(output.writer, "%s ", attribute); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(output.writer, "\n#\n\n")
	return err
}

func (output *ldapSearchLDIFOutput) ensureStarted() error {
	if output.started {
		return nil
	}
	if output.minimal {
		output.level = 3
	}
	switch output.level {
	case 0:
		if _, err := io.WriteString(output.writer, "# extended LDIF\n"); err != nil {
			return err
		}
	case 1, 2:
		if err := writeFoldedLDIFLine(output.writer, []byte("version: 1")); err != nil {
			return err
		}
		if _, err := io.WriteString(output.writer, "\n"); err != nil {
			return err
		}
	}
	output.started = true
	return nil
}

func (output *ldapSearchLDIFOutput) startQuery(query string, index int) error {
	output.responses = 0
	output.entries = 0
	output.references = 0
	output.partials = 0
	if output.batch && index > 0 {
		if _, err := io.WriteString(output.writer, "\n"); err != nil {
			return err
		}
	}
	if output.level >= 2 || !output.batch {
		return nil
	}
	_, err := fmt.Fprintf(output.writer, "#\n# filter: %s\n#\n", query)
	return err
}

func (output *ldapSearchLDIFOutput) nextSearchMessageID() int64 {
	if output.messageID == 0 {
		output.messageID = 1
	}
	output.messageID++
	return output.messageID
}

func (output *ldapSearchLDIFOutput) writeResult(
	result *ldap.SearchResult,
	searchErr error,
	final bool,
	messageID int64,
	wireResponses []ldapSearchWireResponse,
) error {
	if result != nil {
		output.responses += len(result.Entries)
		output.entries += len(result.Entries)
		if err := output.writeReferences(result.Referrals); err != nil {
			return err
		}
	}
	if err := output.writeReferenceControls(wireResponses); err != nil {
		return err
	}
	if err := output.writeIntermediateResponses(wireResponses); err != nil {
		return err
	}

	var ldapError *ldap.Error
	hasLDAPResult := searchErr == nil || errors.As(searchErr, &ldapError)
	if hasLDAPResult {
		output.responses++
		if output.level < 2 {
			if _, err := io.WriteString(output.writer, "# search result\n"); err != nil {
				return err
			}
			if output.level == 0 {
				code := uint16(ldap.LDAPResultSuccess)
				if ldapError != nil {
					code = ldapError.ResultCode
				}
				if _, err := fmt.Fprintf(
					output.writer,
					"search: %d\nresult: %d %s\n",
					messageID,
					code,
					openLDAPResultName(code),
				); err != nil {
					return err
				}
				if ldapError != nil {
					if ldapError.MatchedDN != "" {
						if err := writeLDIFAttribute(
							output.writer,
							"matchedDN",
							[]byte(ldapError.MatchedDN),
						); err != nil {
							return err
						}
					}
					if information := ldapErrorDiagnostic(ldapError); information != "" {
						if err := writeLDIFAttribute(
							output.writer,
							"text",
							[]byte(information),
						); err != nil {
							return err
						}
					}
					for _, referral := range ldapSearchResultReferrals(searchErr) {
						if err := writeLDIFAttribute(output.writer, "ref", []byte(referral)); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	controls := ldapSearchDoneControls(wireResponses)
	if len(controls) == 0 && result != nil {
		controls = ldapSearchControlsFromDecoded(result.Controls)
	}
	if err := output.writeResponseControls(controls); err != nil {
		return err
	}
	if !final {
		return nil
	}
	if output.level >= 2 {
		return nil
	}
	if _, err := fmt.Fprintf(output.writer, "\n# numResponses: %d\n", output.responses); err != nil {
		return err
	}
	if output.entries > 0 {
		if _, err := fmt.Fprintf(output.writer, "# numEntries: %d\n", output.entries); err != nil {
			return err
		}
	}
	if output.partials > 0 {
		if _, err := fmt.Fprintf(output.writer, "# numPartial: %d\n", output.partials); err != nil {
			return err
		}
	}
	if output.references > 0 {
		if _, err := fmt.Fprintf(output.writer, "# numReferences: %d\n", output.references); err != nil {
			return err
		}
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeReferences(referrals []string) error {
	for _, referral := range referrals {
		output.responses++
		output.references++
		if output.level >= 2 {
			continue
		}
		if _, err := io.WriteString(output.writer, "# search reference\n"); err != nil {
			return err
		}
		if output.level == 0 {
			if err := writeLDIFAttribute(output.writer, "ref", []byte(referral)); err != nil {
				return err
			}
		} else if err := writeFoldedLDIFLine(
			output.writer,
			[]byte("# ref"+referral),
		); err != nil {
			return err
		}
		if _, err := io.WriteString(output.writer, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeReferenceControls(
	responses []ldapSearchWireResponse,
) error {
	for _, response := range responses {
		if response.tag != ldap.ApplicationSearchResultReference {
			continue
		}
		if err := output.writeResponseControls(response.controls); err != nil {
			return err
		}
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeIntermediateResponses(
	responses []ldapSearchWireResponse,
) error {
	for _, response := range responses {
		if response.tag != ldap.ApplicationIntermediateResponse {
			continue
		}
		output.responses++
		output.partials++
		if response.intermediateOID == ldap.ControlTypeSyncInfo {
			if err := output.writeSyncInfoIntermediate(response); err != nil {
				return err
			}
			if _, err := io.WriteString(output.writer, "\n"); err != nil {
				return err
			}
			continue
		}
		if output.level >= 2 {
			continue
		}
		if _, err := io.WriteString(output.writer, "# extended partial response\n"); err != nil {
			return err
		}
		if output.level == 0 {
			if err := writeLDIFAttribute(
				output.writer,
				"partial",
				[]byte(response.intermediateOID),
			); err != nil {
				return err
			}
			if response.hasIntermediateData {
				if err := writeBase64LDIFAttribute(
					output.writer,
					"data",
					response.intermediateData,
					false,
				); err != nil {
					return err
				}
			}
		} else {
			if err := writeCommentLDIFAttribute(
				output.writer,
				"partial",
				[]byte(response.intermediateOID),
				false,
			); err != nil {
				return err
			}
			if response.hasIntermediateData {
				if err := writeBase64LDIFAttribute(
					output.writer,
					"data",
					response.intermediateData,
					true,
				); err != nil {
					return err
				}
			}
		}
		if err := output.writeResponseControls(response.controls); err != nil {
			return err
		}
		if _, err := io.WriteString(output.writer, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeResponseControls(
	controls []ldapSearchResponseControl,
) error {
	return output.writeOpenLDAPResponseControls(controls)
}

func ldapSearchDoneControls(
	responses []ldapSearchWireResponse,
) []ldapSearchResponseControl {
	for index := len(responses) - 1; index >= 0; index-- {
		if responses[index].tag == ldap.ApplicationSearchResultDone {
			return responses[index].controls
		}
	}
	return nil
}

func ldapSearchControlsFromDecoded(controls []ldap.Control) []ldapSearchResponseControl {
	result := make([]ldapSearchResponseControl, 0, len(controls))
	for _, control := range controls {
		if control == nil || control.GetControlType() == "" {
			continue
		}
		encoded := control.Encode()
		decoded := parseLDAPSearchResponseControl(encoded)
		if decoded.oid == "" {
			decoded.oid = control.GetControlType()
		}
		result = append(result, decoded)
	}
	return result
}

func parseLDAPSearchResponseControl(encoded *ber.Packet) ldapSearchResponseControl {
	if encoded == nil || len(encoded.Children) == 0 {
		return ldapSearchResponseControl{}
	}
	control := ldapSearchResponseControl{oid: ldapBERString(encoded.Children[0])}
	index := 1
	if index < len(encoded.Children) {
		if critical, ok := encoded.Children[index].Value.(bool); ok {
			control.critical = critical
			index++
		}
	}
	if index < len(encoded.Children) {
		control.value = ldapBERBytes(encoded.Children[index])
		control.hasValue = true
	}
	return control
}

func writeCommentLDIFAttribute(
	writer io.Writer,
	name string,
	value []byte,
	binary bool,
) error {
	line := make([]byte, 0, len(name)+5+len(value)*2)
	line = append(line, '#', ' ')
	line = append(line, name...)
	line = append(line, ':')
	if binary {
		line = append(line, ':')
	}
	if len(value) > 0 {
		line = append(line, ' ')
		line = append(line, value...)
	}
	return writeFoldedLDIFLineWithWidth(writer, line, ldapSearchLDIFLineWidth+1)
}

func writeBase64LDIFAttribute(
	writer io.Writer,
	name string,
	value []byte,
	comment bool,
) error {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(value)))
	base64.StdEncoding.Encode(encoded, value)
	if comment {
		return writeCommentLDIFAttribute(writer, name, encoded, true)
	}
	line := make([]byte, 0, len(name)+4+len(encoded))
	line = append(line, name...)
	line = append(line, ':', ':')
	if len(encoded) > 0 {
		line = append(line, ' ')
		line = append(line, encoded...)
	}
	return writeFoldedLDIFLine(writer, line)
}

func (output *ldapSearchLDIFOutput) writeEntries(entries []*ldap.Entry) error {
	return output.writeEntriesWithResponses(entries, nil)
}

func (output *ldapSearchLDIFOutput) writeEntriesWithResponses(
	entries []*ldap.Entry,
	responses []ldapSearchWireResponse,
) error {
	if err := output.ensureStarted(); err != nil {
		return err
	}
	if output.sort {
		var err error
		entries, err = sortLDAPSearchEntries(entries, output.sortAttribute)
		if err != nil {
			return err
		}
	}
	entryControls := make(map[*ldap.Entry][]ldapSearchResponseControl, len(entries))
	entryIndex := 0
	for _, response := range responses {
		if response.tag == ldap.ApplicationSearchResultEntry && entryIndex < len(entries) {
			entryControls[entries[entryIndex]] = response.controls
			entryIndex++
		}
	}
	for _, entry := range entries {
		if entry == nil {
			return errors.New("search returned a nil LDAP entry")
		}
		if output.level < 2 {
			ufn, _, err := ldapSearchUserFriendlyDN(entry.DN)
			if err != nil {
				return fmt.Errorf("format user-friendly DN comment %q: %w", entry.DN, err)
			}
			comment := "#"
			if ufn != "" {
				comment += " " + ufn
			}
			if err := writeFoldedLDIFLine(output.writer, []byte(comment)); err != nil {
				return err
			}
		}
		if err := writeLDIFAttribute(output.writer, "dn", []byte(entry.DN)); err != nil {
			return err
		}
		if controls, ok := entryControls[entry]; ok {
			if err := output.writeResponseControls(controls); err != nil {
				return err
			}
		}
		if output.includeUFN {
			ufn, _, err := ldapSearchUserFriendlyDN(entry.DN)
			if err != nil {
				return fmt.Errorf("format user-friendly DN %q: %w", entry.DN, err)
			}
			if err := writeLDIFAttribute(output.writer, "ufn", []byte(ufn)); err != nil {
				return err
			}
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
			if output.typesOnly {
				if err := writeLDIFAttribute(output.writer, attribute.Name, nil); err != nil {
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
				if output.valueFiles != nil &&
					(output.allValueFiles || ldifValueRequiresBase64(value)) {
					reference, err := output.valueFiles.Write(attribute.Name, value)
					if err != nil {
						return fmt.Errorf("write search value for attribute %s: %w", attribute.Name, err)
					}
					if err := writeLDIFURLAttribute(output.writer, attribute.Name, reference); err != nil {
						return err
					}
					continue
				}
				if err := writeLDIFAttribute(output.writer, attribute.Name, value); err != nil {
					return err
				}
			}
		}
		if _, err := io.WriteString(output.writer, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func sortLDAPSearchEntries(
	entries []*ldap.Entry,
	attribute string,
) ([]*ldap.Entry, error) {
	type sortableEntry struct {
		entry  *ldap.Entry
		values []string
	}
	sorted := make([]sortableEntry, len(entries))
	for index, entry := range entries {
		if entry == nil {
			return nil, errors.New("search returned a nil LDAP entry")
		}
		values := entry.GetEqualFoldAttributeValues(attribute)
		if attribute == "" {
			var err error
			_, values, err = ldapSearchUserFriendlyDN(entry.DN)
			if err != nil {
				return nil, fmt.Errorf("sort DN %q: %w", entry.DN, err)
			}
		}
		sorted[index] = sortableEntry{entry: entry, values: values}
	}
	sort.SliceStable(sorted, func(left, right int) bool {
		return compareLDAPSearchSortValues(
			sorted[left].values,
			sorted[right].values,
		) < 0
	})
	result := make([]*ldap.Entry, len(sorted))
	for index := range sorted {
		result[index] = sorted[index].entry
	}
	return result, nil
}

func compareLDAPSearchSortValues(left, right []string) int {
	switch {
	case len(left) == 0 && len(right) == 0:
		return 0
	case len(left) == 0:
		return -1
	case len(right) == 0:
		return 1
	}
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		comparison := compareLDAPSearchSortString(left[index], right[index])
		if comparison != 0 {
			return comparison
		}
	}
	return len(left) - len(right)
}

func compareLDAPSearchSortString(left, right string) int {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		leftByte := left[index]
		rightByte := right[index]
		if leftByte >= 'A' && leftByte <= 'Z' {
			leftByte += 'a' - 'A'
		}
		if rightByte >= 'A' && rightByte <= 'Z' {
			rightByte += 'a' - 'A'
		}
		if leftByte < rightByte {
			return -1
		}
		if leftByte > rightByte {
			return 1
		}
	}
	return len(left) - len(right)
}

func ldapSearchUserFriendlyDN(rawDN string) (string, []string, error) {
	dn, err := ldap.ParseDN(rawDN)
	if err != nil {
		return "", nil, err
	}
	rawRDNs := splitLDAPSearchDNComponents(rawDN, ",;")
	components := make([]string, len(dn.RDNs))
	binaryRDNs := make([]bool, len(dn.RDNs))
	for rdnIndex, rdn := range dn.RDNs {
		var rawAVAs []string
		if rdnIndex < len(rawRDNs) {
			rawAVAs = splitLDAPSearchDNComponents(rawRDNs[rdnIndex], "+")
		}
		values := make([]string, len(rdn.Attributes))
		for attributeIndex, attribute := range rdn.Attributes {
			if attributeIndex < len(rawAVAs) {
				if rawValue, ok := rawLDAPSearchAVAValue(rawAVAs[attributeIndex]); ok &&
					strings.HasPrefix(rawValue, "#") {
					values[attributeIndex] = "#" + strings.ToUpper(rawValue[1:])
					binaryRDNs[rdnIndex] = true
					continue
				}
			}
			values[attributeIndex] = escapeLDAPSearchUFNValue(attribute.Value)
		}
		components[rdnIndex] = strings.Join(values, " + ")
	}

	domainStart := len(dn.RDNs)
	for index := len(dn.RDNs) - 1; index >= 0; index-- {
		rdn := dn.RDNs[index]
		if len(rdn.Attributes) != 1 || !strings.EqualFold(rdn.Attributes[0].Type, "dc") {
			break
		}
		domainStart = index
	}
	if domainStart == len(dn.RDNs) {
		return strings.Join(components, ", "), components, nil
	}
	domain := make([]string, len(dn.RDNs)-domainStart)
	for index := domainStart; index < len(dn.RDNs); index++ {
		if binaryRDNs[index] ||
			!ldapSearchUFNDomainValueIsPrintable(dn.RDNs[index].Attributes[0].Value) {
			return "", components, nil
		}
		domain[index-domainStart] = dn.RDNs[index].Attributes[0].Value
	}
	ufnComponents := append([]string(nil), components[:domainStart]...)
	ufnComponents = append(ufnComponents, strings.Join(domain, "."))
	return strings.Join(ufnComponents, ", "), components, nil
}

func splitLDAPSearchDNComponents(value, separators string) []string {
	components := make([]string, 0, 4)
	start := 0
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' {
			index++
			continue
		}
		if strings.IndexByte(separators, value[index]) >= 0 {
			components = append(components, value[start:index])
			start = index + 1
		}
	}
	return append(components, value[start:])
}

func rawLDAPSearchAVAValue(ava string) (string, bool) {
	for index := 0; index < len(ava); index++ {
		if ava[index] == '\\' {
			index++
			continue
		}
		if ava[index] == '=' {
			return ava[index+1:], true
		}
	}
	return "", false
}

func escapeLDAPSearchUFNValue(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		hexEscape := character == 0 || character >= 0x80 || character == '=' ||
			strings.ContainsRune("\\,;+\"<>", rune(character)) ||
			(index == 0 && (character == ' ' || character == '#')) ||
			(index == len(value)-1 && character == ' ')
		if !hexEscape {
			escaped.WriteByte(character)
			continue
		}
		escaped.WriteByte('\\')
		escaped.WriteByte(hexadecimal[character>>4])
		escaped.WriteByte(hexadecimal[character&0x0f])
	}
	return escaped.String()
}

func ldapSearchUFNDomainValueIsPrintable(value string) bool {
	if value == "" || value[0] <= ' ' || value[0] >= 0x7f || value[0] == ':' || value[0] == '<' ||
		value[len(value)-1] <= ' ' || value[len(value)-1] >= 0x7f {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < ' ' || value[index] >= 0x7f {
			return false
		}
	}
	return true
}

func writeLDAPSearchLDIF(
	writer io.Writer,
	entries []*ldap.Entry,
	typesOnly,
	minimal bool,
) error {
	return (&ldapSearchLDIFOutput{
		writer:    writer,
		typesOnly: typesOnly,
		level:     2,
		minimal:   minimal,
	}).writeEntries(entries)
}

type ldapSearchValueFiles struct {
	root      *os.Root
	urlPrefix string
}

func openLDAPSearchValueFiles(
	enabled bool,
	directory,
	urlPrefix string,
) (*ldapSearchValueFiles, error) {
	if len(urlPrefix) > 4096 || strings.ContainsAny(urlPrefix, "\x00\r\n") {
		return nil, errors.New("-F URL prefix is too long or contains a prohibited control character")
	}
	if !enabled && directory == "" && urlPrefix == "" {
		return nil, nil
	}
	if directory == "" {
		directory = os.TempDir()
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve temporary value directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	before, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect temporary value directory: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("temporary value path must be a non-symlink directory")
	}
	if runtime.GOOS != "windows" {
		permissions := before.Mode().Perm()
		if permissions&0o300 != 0o300 {
			return nil, errors.New("temporary value directory must be writable and searchable by its owner")
		}
		if permissions&0o022 != 0 && before.Mode()&os.ModeSticky == 0 {
			return nil, errors.New("group- or other-writable temporary value directory must have the sticky bit")
		}
	}
	prefix, err := normalizeLDAPSearchValueURLPrefix(urlPrefix, absolute)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("open temporary value directory: %w", err)
	}
	closeOnError := func(err error) (*ldapSearchValueFiles, error) {
		return nil, errors.Join(err, root.Close())
	}
	opened, err := root.Stat(".")
	if err != nil {
		return closeOnError(fmt.Errorf("inspect opened temporary value directory: %w", err))
	}
	after, err := os.Lstat(absolute)
	if err != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return closeOnError(errors.New("temporary value directory changed while it was being opened"))
	}
	return &ldapSearchValueFiles{root: root, urlPrefix: prefix}, nil
}

func normalizeLDAPSearchValueURLPrefix(prefix, directory string) (string, error) {
	if prefix == "" {
		path := filepath.ToSlash(directory)
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		return (&url.URL{Scheme: "file", Path: path}).String(), nil
	}
	parsed, err := url.Parse(prefix)
	if err != nil {
		return "", fmt.Errorf("parse -F URL prefix: %w", err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "file" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("-F URL prefix must use file://, http://, or https://")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("-F URL prefix must not contain userinfo, a query, a fragment, or opaque data")
	}
	if parsed.Scheme == "file" && parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
		return "", errors.New("-F file URL prefix host must be empty or localhost")
	}
	if (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() == "" {
		return "", errors.New("-F HTTP URL prefix requires a host")
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	return parsed.String(), nil
}

func (files *ldapSearchValueFiles) Close() error {
	if files == nil || files.root == nil {
		return nil
	}
	err := files.root.Close()
	files.root = nil
	return err
}

func (files *ldapSearchValueFiles) Write(attribute string, value []byte) (string, error) {
	if len(value) > maxLDAPSearchValueSize {
		return "", fmt.Errorf("value exceeds %d bytes", maxLDAPSearchValueSize)
	}
	random := make([]byte, 16)
	defer clear(random)
	prefix := ldapSearchTemporaryNamePrefix(attribute)
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := rand.Read(random); err != nil {
			return "", fmt.Errorf("generate temporary value filename: %w", err)
		}
		name := prefix + hex.EncodeToString(random)
		file, err := files.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("create temporary value file: %w", err)
		}
		removeOnError := func(err error) (string, error) {
			return "", errors.Join(err, file.Close(), files.root.Remove(name))
		}
		if err := file.Chmod(0o600); err != nil {
			return removeOnError(fmt.Errorf("secure temporary value file: %w", err))
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() ||
			(runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
			return removeOnError(errors.New("temporary value output is not a secure regular file"))
		}
		written, err := file.Write(value)
		if err != nil {
			return removeOnError(fmt.Errorf("write temporary value file: %w", err))
		}
		if written != len(value) {
			return removeOnError(io.ErrShortWrite)
		}
		if err := file.Close(); err != nil {
			_ = files.root.Remove(name)
			return "", fmt.Errorf("close temporary value file: %w", err)
		}
		return files.urlPrefix + url.PathEscape(name), nil
	}
	return "", errors.New("could not allocate a unique temporary value file")
}

func ldapSearchTemporaryNamePrefix(attribute string) string {
	var builder strings.Builder
	builder.WriteString("ldapsearch-")
	for index := 0; index < len(attribute) && builder.Len() < 59; index++ {
		character := attribute[index]
		if isASCIIAlpha(character) || character >= '0' && character <= '9' || character == '-' {
			builder.WriteByte(character)
		} else {
			builder.WriteByte('-')
		}
	}
	builder.WriteByte('-')
	return builder.String()
}

func writeLDIFURLAttribute(writer io.Writer, name, reference string) error {
	if reference == "" || strings.ContainsAny(reference, "\x00\r\n") {
		return errors.New("temporary value file produced an invalid URL")
	}
	line := make([]byte, 0, len(name)+3+len(reference))
	line = append(line, name...)
	line = append(line, ':', '<', ' ')
	line = append(line, reference...)
	return writeFoldedLDIFLine(writer, line)
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
	return writeFoldedLDIFLineWithWidth(writer, line, ldapSearchLDIFLineWidth)
}

func writeFoldedLDIFLineWithWidth(writer io.Writer, line []byte, lineWidth int) error {
	first := true
	for len(line) > 0 {
		width := lineWidth
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
