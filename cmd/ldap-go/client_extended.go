package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	ldapCancelOID             = "1.3.6.1.1.8"
	ldapDynamicRefreshOID     = "1.3.6.1.4.1.1466.101.119.1"
	ldapManageDsaITOID        = "2.16.840.1.113730.3.4.2"
	ldapPasswordModifyOID     = "1.3.6.1.4.1.4203.1.11.1"
	ldapWhoAmIOID             = "1.3.6.1.4.1.4203.1.11.3"
	maxLDAPExtendedValueSize  = 8 << 20
	defaultLDAPRefreshSeconds = 3600
)

type ldapClientExitError struct {
	code  int
	cause error
}

func (exitError *ldapClientExitError) Error() string {
	if exitError.cause != nil {
		return exitError.cause.Error()
	}
	return fmt.Sprintf("LDAP client exit status %d", exitError.code)
}

func (exitError *ldapClientExitError) Unwrap() error {
	return exitError.cause
}

func ldapClientExitStatus(err error) (int, error, bool) {
	var exitError *ldapClientExitError
	if !errors.As(err, &exitError) {
		return 0, nil, false
	}
	return exitError.code, exitError.cause, true
}

func runLDAPCompare(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldapcompare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	client.unsupportedFlags = withoutLDAPClientUnsupportedFlag(client.unsupportedFlags, "M")
	flags.Lookup("M").Usage = "enable ManageDsaIT control"
	defer client.clear()

	quiet := flags.Bool("z", false, "suppress TRUE or FALSE output")
	flags.String("E", "", "unsupported: compare extensions and controls")
	criticalManageDsaIT := flags.Bool("MM", false, "critical ManageDsaIT control")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	if err := rejectUnsupportedFlags("ldapcompare", flags, []unsupportedFlag{
		{name: "E", reason: "compare extensions and controls are not implemented"},
	}); err != nil {
		return err
	}
	manageDsaIT, err := ldapBooleanFlagValue(flags, "M")
	if err != nil {
		return err
	}
	if flagWasSet(flags, "M") && !manageDsaIT {
		return errors.New("-M=false is not supported")
	}
	if flagWasSet(flags, "MM") && !*criticalManageDsaIT {
		return errors.New("-MM=false is not supported")
	}
	if manageDsaIT && *criticalManageDsaIT {
		return errors.New("-M and -MM cannot be combined")
	}
	if flagWasSet(flags, "z") && !*quiet {
		return errors.New("-z=false is not supported")
	}
	if flags.NArg() != 2 {
		return errors.New("ldapcompare requires DN and attr:value or attr::base64")
	}

	dn := flags.Arg(0)
	if _, err := ldap.ParseDN(dn); err != nil {
		return fmt.Errorf("parse compare DN: %w", err)
	}
	attribute, value, err := parseLDAPCompareAssertion(flags.Arg(1))
	if err != nil {
		return err
	}
	defer clear(value)
	controls := client.generalControls
	if manageDsaIT || *criticalManageDsaIT {
		manageControl := &ldapRawControl{
			oid:      ldapManageDsaITOID,
			critical: *criticalManageDsaIT,
		}
		controls, err = mergeLDAPControls(client.generalControls, []ldap.Control{manageControl})
		if err != nil {
			return fmt.Errorf("ldapcompare controls: %w", err)
		}
	}
	if client.dryRun {
		return nil
	}

	var matched bool
	if len(controls) == 0 {
		connection, connectErr := client.connectAndBind(flags, stdin, stderr)
		if connectErr != nil {
			return connectErr
		}
		defer connection.Close()
		matched, err = client.compareWithReferrals(
			connection,
			dn,
			attribute,
			string(value),
		)
	} else {
		connection, connectErr := connectLDAPCompareRaw(
			&client,
			flags,
			stdin,
			stderr,
		)
		if connectErr != nil {
			return connectErr
		}
		defer connection.Close()
		matched, err = client.compareRawWithReferrals(
			connection,
			dn,
			attribute,
			value,
			controls,
		)
	}
	if err != nil {
		cause := fmt.Errorf("compare DN %q attribute %q: %w", dn, attribute, err)
		var ldapError *ldap.Error
		if errors.As(err, &ldapError) && ldapCompareExitCode(ldapError.ResultCode) {
			if *quiet {
				cause = nil
			}
			return &ldapClientExitError{code: int(ldapError.ResultCode), cause: cause}
		}
		return cause
	}
	if !*quiet {
		result := "FALSE"
		if matched {
			result = "TRUE"
		}
		if _, err := fmt.Fprintln(stdout, result); err != nil {
			return err
		}
	}
	if !matched {
		return &ldapClientExitError{code: ldap.LDAPResultCompareFalse}
	}
	return &ldapClientExitError{code: ldap.LDAPResultCompareTrue}
}

func withoutLDAPClientUnsupportedFlag(
	unsupported []unsupportedFlag,
	name string,
) []unsupportedFlag {
	filtered := unsupported[:0]
	for _, option := range unsupported {
		if option.name != name {
			filtered = append(filtered, option)
		}
	}
	return filtered
}

func ldapBooleanFlagValue(flags *flag.FlagSet, name string) (bool, error) {
	option := flags.Lookup(name)
	if option == nil {
		return false, fmt.Errorf("LDAP client option -%s is not registered", name)
	}
	getter, ok := option.Value.(flag.Getter)
	if !ok {
		return false, fmt.Errorf("LDAP client option -%s is not boolean", name)
	}
	value, ok := getter.Get().(bool)
	if !ok {
		return false, fmt.Errorf("LDAP client option -%s is not boolean", name)
	}
	return value, nil
}

func ldapCompareExitCode(code uint16) bool {
	return (code > 0 && code <= ldap.LDAPResultOther) ||
		(code >= ldap.LDAPResultCanceled && code <= ldap.LDAPResultAuthorizationDenied)
}

func parseLDAPCompareAssertion(assertion string) (string, []byte, error) {
	separator := strings.IndexByte(assertion, ':')
	if separator <= 0 {
		return "", nil, errors.New("compare assertion must be attr:value or attr::base64")
	}
	attribute := assertion[:separator]
	if !validLDIFAttributeDescription(attribute) {
		return "", nil, fmt.Errorf("invalid compare attribute description %q", attribute)
	}
	value := assertion[separator+1:]
	if !strings.HasPrefix(value, ":") {
		if len(value) > maxLDAPExtendedValueSize {
			return "", nil, fmt.Errorf("compare value exceeds %d bytes", maxLDAPExtendedValueSize)
		}
		return attribute, []byte(value), nil
	}

	decoded, err := decodeLDAPCLIBase64(value[1:], "compare value")
	if err != nil {
		return "", nil, err
	}
	return attribute, decoded, nil
}

type ldapRawCompareConnection struct {
	net.Conn
	nextMessageID int64
}

func connectLDAPCompareRaw(
	client *ldapClientOptions,
	flags *flag.FlagSet,
	stdin io.Reader,
	stderr io.Writer,
) (*ldapRawCompareConnection, error) {
	parsedURI, dialURI, tlsConfig, err := client.connectionConfiguration(flags)
	if err != nil {
		return nil, err
	}
	password, hasPassword, err := client.loadPassword(flags, stdin, stderr)
	if err != nil {
		return nil, err
	}
	defer clear(password)

	dial := func(useTLS bool) (net.Conn, error) {
		return dialLDAPRawConnection(parsedURI, tlsConfig, client.timeout, useTLS)
	}
	connection, err := dial(parsedURI.Scheme == "ldaps")
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", dialURI, err)
	}
	closeOnError := func(err error) (*ldapRawCompareConnection, error) {
		_ = connection.Close()
		return nil, err
	}

	messageID := int64(1)
	if client.tryStartTLS || client.requireStartTLS {
		upgraded, startTLSErr := ldapClientSASLStartTLS(
			connection,
			tlsConfig,
			client.timeout,
			messageID,
		)
		messageID++
		if startTLSErr != nil {
			if client.requireStartTLS {
				return closeOnError(fmt.Errorf("StartTLS with %s: %w", dialURI, startTLSErr))
			}
			_ = connection.Close()
			if _, writeErr := fmt.Fprintf(
				stderr,
				"warning: StartTLS with %s failed; continuing over cleartext LDAP: %v\n",
				dialURI,
				startTLSErr,
			); writeErr != nil {
				return nil, writeErr
			}
			connection, err = dial(false)
			if err != nil {
				return nil, fmt.Errorf(
					"reconnect to %s after StartTLS failure: %w",
					dialURI,
					err,
				)
			}
			messageID = 1
		} else {
			connection = upgraded
		}
	}

	if err := connection.SetDeadline(time.Now().Add(client.timeout)); err != nil {
		return closeOnError(fmt.Errorf("set LDAP bind deadline: %w", err))
	}
	if client.simple {
		bindDN := ""
		var bindPassword []byte
		if hasPassword {
			bindDN = client.bindDN
			bindPassword = password
		}
		if err := ldapRawSimpleBind(connection, &messageID, bindDN, bindPassword); err != nil {
			if hasPassword {
				return closeOnError(fmt.Errorf("bind as %s: %w", client.bindDN, err))
			}
			return closeOnError(fmt.Errorf("anonymous bind: %w", err))
		}
	} else {
		if !hasPassword && client.saslMechanism != "EXTERNAL" {
			return closeOnError(fmt.Errorf(
				"SASL %s password was not loaded",
				client.saslMechanism,
			))
		}
		if err := client.bindSASL(
			connection,
			parsedURI.Hostname(),
			password,
			&messageID,
		); err != nil {
			return closeOnError(err)
		}
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return closeOnError(fmt.Errorf("clear LDAP bind deadline: %w", err))
	}
	return &ldapRawCompareConnection{
		Conn:          connection,
		nextMessageID: messageID,
	}, nil
}

func dialLDAPRawConnection(
	parsedURI *url.URL,
	tlsConfig *tls.Config,
	timeout time.Duration,
	useTLS bool,
) (net.Conn, error) {
	address := parsedURI.Host
	if parsedURI.Port() == "" {
		port := "389"
		if parsedURI.Scheme == "ldaps" {
			port = "636"
		}
		address = net.JoinHostPort(parsedURI.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: timeout}
	if useTLS {
		return tls.DialWithDialer(dialer, "tcp", address, tlsConfig.Clone())
	}
	return dialer.Dial("tcp", address)
}

func ldapRawSimpleBind(
	connection net.Conn,
	messageID *int64,
	dn string,
	password []byte,
) error {
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: *messageID,
		Request: ldapwire.BindRequest{
			Version: 3,
			Name:    dn,
			Authentication: ldapwire.Authentication{
				Simple: password,
			},
		},
	})
	if err != nil {
		return err
	}
	defer clear(request)
	if err := ldapwire.Write(connection, request); err != nil {
		return err
	}
	result, err := readLDAPClientSASLResult(
		connection,
		*messageID,
		ldap.ApplicationBindResponse,
	)
	*messageID++
	if err != nil {
		return err
	}
	return ldapRawResultError(result)
}

func (client *ldapClientOptions) compareRawWithReferrals(
	connection *ldapRawCompareConnection,
	dn, attribute string,
	value []byte,
	controls []ldap.Control,
) (bool, error) {
	seen := map[string]struct{}{
		client.referralKey(client.uri, "compare", dn): {},
	}
	return client.compareRawWithReferralsAt(
		connection,
		dn,
		attribute,
		value,
		controls,
		0,
		seen,
	)
}

func (client *ldapClientOptions) compareRawWithReferralsAt(
	connection *ldapRawCompareConnection,
	dn, attribute string,
	value []byte,
	controls []ldap.Control,
	depth int,
	seen map[string]struct{},
) (bool, error) {
	matched, err := ldapRawCompare(
		connection,
		client.timeout,
		dn,
		attribute,
		value,
		controls,
	)
	if !client.chaseReferrals {
		return matched, err
	}
	referrals := ldapReferralURLs(err)
	if len(referrals) == 0 {
		return matched, err
	}
	if depth >= client.referralHopLimit {
		return false, ldap.NewError(
			ldap.LDAPResultReferralLimitExceeded,
			fmt.Errorf("referral hop limit %d exceeded", client.referralHopLimit),
		)
	}
	var lastErr error
	for _, raw := range referrals {
		target, parseErr := parseLDAPReferralTarget(raw)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		followedDN := dn
		if target.hasDN {
			followedDN = target.dn
		}
		key := client.referralKey(target.endpoint, "compare", followedDN)
		if _, duplicate := seen[key]; duplicate {
			lastErr = ldap.NewError(
				ldap.LDAPResultClientLoop,
				fmt.Errorf("LDAP referral loop at %s", target.raw),
			)
			continue
		}
		referralConnection, connectErr := client.connectLDAPRawReferral(target)
		if connectErr != nil {
			lastErr = connectErr
			continue
		}
		branchSeen := cloneLDAPReferralSet(seen)
		branchSeen[key] = struct{}{}
		matched, compareErr := client.compareRawWithReferralsAt(
			referralConnection,
			followedDN,
			attribute,
			value,
			controls,
			depth+1,
			branchSeen,
		)
		_ = referralConnection.Close()
		return matched, compareErr
	}
	if lastErr == nil {
		lastErr = err
	}
	return false, fmt.Errorf("chase LDAP referral: %w", lastErr)
}

func (client *ldapClientOptions) connectLDAPRawReferral(
	target ldapReferralTarget,
) (*ldapRawCompareConnection, error) {
	parsed, err := url.Parse(target.endpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := client.clientTLSConfig(parsed.Hostname())
	if err != nil {
		return nil, err
	}
	dial := func(useTLS bool) (net.Conn, error) {
		return dialLDAPRawConnection(parsed, tlsConfig, client.timeout, useTLS)
	}
	connection, err := dial(parsed.Scheme == "ldaps")
	if err != nil {
		return nil, fmt.Errorf("connect to referral %s: %w", target.endpoint, err)
	}
	closeOnError := func(err error) (*ldapRawCompareConnection, error) {
		_ = connection.Close()
		return nil, err
	}
	messageID := int64(1)
	if target.startTLS {
		upgraded, startTLSErr := ldapClientSASLStartTLS(
			connection,
			tlsConfig,
			client.timeout,
			messageID,
		)
		messageID++
		if startTLSErr != nil {
			if target.startTLSRequired {
				return closeOnError(fmt.Errorf(
					"StartTLS with referral %s: %w",
					target.endpoint,
					startTLSErr,
				))
			}
			_ = connection.Close()
			connection, err = dial(false)
			if err != nil {
				return nil, fmt.Errorf(
					"reconnect to referral %s after StartTLS failure: %w",
					target.endpoint,
					err,
				)
			}
			messageID = 1
		} else {
			connection = upgraded
		}
	}
	if err := connection.SetDeadline(time.Now().Add(client.timeout)); err != nil {
		return closeOnError(fmt.Errorf("set referral bind deadline: %w", err))
	}
	if err := ldapRawSimpleBind(connection, &messageID, "", nil); err != nil {
		return closeOnError(fmt.Errorf(
			"anonymous bind to referral %s: %w",
			target.endpoint,
			err,
		))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return closeOnError(fmt.Errorf("clear referral bind deadline: %w", err))
	}
	return &ldapRawCompareConnection{
		Conn:          connection,
		nextMessageID: messageID,
	}, nil
}

func ldapRawCompare(
	connection *ldapRawCompareConnection,
	timeout time.Duration,
	dn, attribute string,
	value []byte,
	controls []ldap.Control,
) (bool, error) {
	wireControls := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		raw, ok := control.(*ldapRawControl)
		if !ok {
			return false, fmt.Errorf(
				"ldapcompare cannot encode control %s of type %T",
				control.GetControlType(),
				control,
			)
		}
		wireControls = append(wireControls, ldapwire.Control{
			OID:      raw.oid,
			Critical: raw.critical,
			Value:    raw.value,
			HasValue: raw.hasValue,
		})
	}
	messageID := connection.nextMessageID
	connection.nextMessageID++
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.CompareRequest{
			DN:        dn,
			Attribute: attribute,
			Assertion: value,
		},
		Controls: wireControls,
	})
	if err != nil {
		return false, err
	}
	defer clear(request)
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}
	defer connection.SetDeadline(time.Time{})
	if err := ldapwire.Write(connection, request); err != nil {
		return false, err
	}
	result, err := readLDAPClientSASLResult(
		connection,
		messageID,
		ldap.ApplicationCompareResponse,
	)
	if err != nil {
		return false, err
	}
	switch result.code {
	case ldap.LDAPResultCompareTrue:
		return true, nil
	case ldap.LDAPResultCompareFalse:
		return false, nil
	default:
		return false, ldapRawResultError(result)
	}
}

func ldapRawResultError(result ldapClientSASLResult) error {
	if result.code == ldap.LDAPResultSuccess {
		return nil
	}
	message := ldap.LDAPResultCodeMap[result.code]
	if result.packet != nil && len(result.packet.Children) > 1 {
		operation := result.packet.Children[1]
		if operation != nil && len(operation.Children) > 2 {
			if diagnostic, ok := ldapClientPacketBytes(operation.Children[2]); ok && len(diagnostic) > 0 {
				message = string(diagnostic)
			}
		}
	}
	if message == "" {
		message = "LDAP operation failed"
	}
	return &ldap.Error{
		ResultCode: result.code,
		MatchedDN:  result.matchedDN,
		Err:        errors.New(message),
		Packet:     result.packet,
	}
}

func runLDAPPasswd(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldappasswd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()
	var passwordOptions ldapPasswordCLIOptions
	passwordOptions.register(flags)
	defer passwordOptions.clear()

	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("ldappasswd accepts at most one user identity")
	}
	if err := passwordOptions.validate(flags); err != nil {
		return err
	}
	userIdentity := ""
	if flags.NArg() == 1 {
		userIdentity = flags.Arg(0)
		if userIdentity == "" || strings.ContainsAny(userIdentity, "\x00\r\n") {
			return errors.New("user identity must be non-empty and contain no NUL or line breaks")
		}
	}
	if client.dryRun {
		return passwordOptions.validateDryRun(flags, stderr)
	}
	return passwordOptions.execute(
		&client,
		flags,
		stdin,
		stdout,
		stderr,
		userIdentity,
	)
}

type ldapPasswordCLIOptions struct {
	bindEarly bool
	oldDirect secretFlagValue
	oldPrompt bool
	oldFile   string
	newDirect secretFlagValue
	newPrompt bool
	newFile   string
}

func (options *ldapPasswordCLIOptions) register(flags *flag.FlagSet) {
	flags.BoolVar(&options.bindEarly, "E", false, "bind before reading operation passwords")
	flags.Var(
		&options.oldDirect,
		"a",
		"old password (insecure: visible in process arguments; prefer -A or -t)",
	)
	flags.BoolVar(&options.oldPrompt, "A", false, "prompt twice for the old password")
	flags.StringVar(&options.oldFile, "t", "", "read the old password from a file")
	flags.Var(
		&options.newDirect,
		"s",
		"new password (insecure: visible in process arguments; prefer -S or -T)",
	)
	flags.BoolVar(&options.newPrompt, "S", false, "prompt twice for the new password")
	flags.StringVar(&options.newFile, "T", "", "read the new password from a file")
}

func (options *ldapPasswordCLIOptions) clear() {
	options.oldDirect.clear()
	options.newDirect.clear()
}

func (options *ldapPasswordCLIOptions) validate(flags *flag.FlagSet) error {
	if flagWasSet(flags, "E") && !options.bindEarly {
		return errors.New("-E=false is not supported")
	}
	if err := validateLDAPPasswordSources(
		flags,
		&options.oldDirect,
		"a", "A", "t",
		options.oldPrompt,
		options.oldFile,
		"old password",
	); err != nil {
		return err
	}
	return validateLDAPPasswordSources(
		flags,
		&options.newDirect,
		"s", "S", "T",
		options.newPrompt,
		options.newFile,
		"new password",
	)
}

func (options *ldapPasswordCLIOptions) validateDryRun(
	flags *flag.FlagSet,
	stderr io.Writer,
) error {
	return validateLDAPPasswordDryRunSources(
		flags,
		stderr,
		&options.oldDirect,
		options.oldFile,
		"a", "t",
		&options.newDirect,
		options.newFile,
		"s", "T",
	)
}

func (options *ldapPasswordCLIOptions) wasSet(flags *flag.FlagSet) bool {
	for _, name := range []string{"E", "a", "A", "t", "s", "S", "T"} {
		if flagWasSet(flags, name) {
			return true
		}
	}
	return false
}

func (options *ldapPasswordCLIOptions) execute(
	client *ldapClientOptions,
	flags *flag.FlagSet,
	stdin io.Reader,
	stdout, stderr io.Writer,
	userIdentity string,
) error {

	var connection *ldap.Conn
	var oldPassword, newPassword []byte
	var hasOldPassword, hasNewPassword bool
	var err error
	connect := func() error {
		connection, err = client.connectAndBind(flags, stdin, stderr)
		return err
	}
	loadPasswords := func() error {
		oldPassword, hasOldPassword, err = loadLDAPOperationPassword(
			flags,
			stdin,
			stderr,
			&options.oldDirect,
			"a", "A", "t",
			options.oldFile,
			"Old password: ",
			"Re-enter old password: ",
		)
		if err != nil {
			return err
		}
		newPassword, hasNewPassword, err = loadLDAPOperationPassword(
			flags,
			stdin,
			stderr,
			&options.newDirect,
			"s", "S", "T",
			options.newFile,
			"New password: ",
			"Re-enter new password: ",
		)
		return err
	}
	if options.bindEarly {
		err = connect()
		if err == nil {
			err = loadPasswords()
		}
	} else {
		err = loadPasswords()
		if err == nil {
			err = connect()
		}
	}
	defer clear(oldPassword)
	defer clear(newPassword)
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return err
	}

	generatedPassword, hasGeneratedPassword, err := ldapPasswordModify(
		client,
		connection,
		client.generalControls,
		userIdentity,
		oldPassword,
		hasOldPassword,
		newPassword,
		hasNewPassword,
	)
	if err != nil {
		return fmt.Errorf("password modify: %w", err)
	}
	defer clear(generatedPassword)
	if hasNewPassword {
		return nil
	}
	if !hasGeneratedPassword || len(generatedPassword) == 0 {
		return errors.New("password modify succeeded but the server returned no generated password")
	}
	if len(generatedPassword) > maxPasswordInputSize {
		return fmt.Errorf("generated password exceeds %d bytes", maxPasswordInputSize)
	}
	return writeLDAPGeneratedPassword(stdout, generatedPassword)
}

func writeLDAPGeneratedPassword(writer io.Writer, password []byte) error {
	return writeLDIFAttribute(writer, "New password", password)
}

func ldapPasswordModify(
	client *ldapClientOptions,
	connection *ldap.Conn,
	controls []ldap.Control,
	userIdentity string,
	oldPassword []byte,
	hasOldPassword bool,
	newPassword []byte,
	hasNewPassword bool,
) ([]byte, bool, error) {
	requestValue, err := newLDAPPasswordModifyRequestValue(
		userIdentity,
		oldPassword,
		hasOldPassword,
		newPassword,
		hasNewPassword,
	)
	if err != nil {
		return nil, false, err
	}
	defer clearBERPacket(requestValue)

	request := ldap.NewExtendedRequest(ldapPasswordModifyOID, requestValue)
	request.Controls = controls
	defer func() { request.Value = nil }()
	response, err := client.extendedWithReferrals(connection, request)
	if err != nil {
		return nil, false, err
	}
	if response == nil {
		return nil, false, errors.New("server returned a nil password modify response")
	}
	if response.Name != "" && response.Name != ldapPasswordModifyOID {
		return nil, false, fmt.Errorf(
			"server returned password modify response OID %q",
			response.Name,
		)
	}
	defer clearBERPacket(response.Value)
	return decodeLDAPPasswordModifyResponse(response)
}

func newLDAPPasswordModifyRequestValue(
	userIdentity string,
	oldPassword []byte,
	hasOldPassword bool,
	newPassword []byte,
	hasNewPassword bool,
) (*ber.Packet, error) {
	if userIdentity == "" && !hasOldPassword && !hasNewPassword {
		return nil, nil
	}

	type field struct {
		tag   byte
		value []byte
	}
	fields := make([]field, 0, 3)
	var identity []byte
	if userIdentity != "" {
		identity = []byte(userIdentity)
		defer clear(identity)
		fields = append(fields, field{tag: 0, value: identity})
	}
	if hasOldPassword {
		fields = append(fields, field{tag: 1, value: oldPassword})
	}
	if hasNewPassword {
		fields = append(fields, field{tag: 2, value: newPassword})
	}

	contentLength := 0
	for _, field := range fields {
		fieldLength := 1 + ldapBERLengthSize(len(field.value)) + len(field.value)
		if fieldLength > maxLDAPExtendedValueSize-contentLength {
			return nil, fmt.Errorf(
				"password modify request value exceeds %d bytes",
				maxLDAPExtendedValueSize,
			)
		}
		contentLength += fieldLength
	}
	encodedLength := 1 + ldapBERLengthSize(contentLength) + contentLength
	if encodedLength > maxLDAPExtendedValueSize {
		return nil, fmt.Errorf(
			"password modify request value exceeds %d bytes",
			maxLDAPExtendedValueSize,
		)
	}

	packet := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		ber.Tag(1),
		nil,
		"Extended Request Value: Password Modify Request",
	)
	_ = packet.Data.WriteByte(0x30)
	appendLDAPBERLength(packet.Data, contentLength)
	for _, field := range fields {
		_ = packet.Data.WriteByte(0x80 | field.tag)
		appendLDAPBERLength(packet.Data, len(field.value))
		_, _ = packet.Data.Write(field.value)
	}
	return packet, nil
}

func ldapBERLengthSize(length int) int {
	if length < 128 {
		return 1
	}
	size := 1
	for value := length; value > 0; value >>= 8 {
		size++
	}
	return size
}

func appendLDAPBERLength(buffer *bytes.Buffer, length int) {
	if length < 128 {
		_ = buffer.WriteByte(byte(length))
		return
	}
	var encoded [8]byte
	position := len(encoded)
	for value := length; value > 0; value >>= 8 {
		position--
		encoded[position] = byte(value)
	}
	_ = buffer.WriteByte(0x80 | byte(len(encoded)-position))
	_, _ = buffer.Write(encoded[position:])
}

func decodeLDAPPasswordModifyResponse(
	response *ldap.ExtendedResponse,
) ([]byte, bool, error) {
	if response.Value == nil {
		return nil, false, nil
	}
	value, err := ldapExtendedResponseBytes(response)
	if err != nil {
		return nil, false, err
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return nil, false, fmt.Errorf("decode password modify response value: %w", err)
	}
	defer clearBERPacket(packet)
	if reader.Len() != 0 {
		return nil, false, errors.New("password modify response value contains trailing BER data")
	}
	if packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypeConstructed ||
		packet.Tag != ber.TagSequence ||
		len(packet.Children) != 1 {
		return nil, false, errors.New("password modify response value must contain one generated password")
	}
	generated := packet.Children[0]
	if generated.ClassType != ber.ClassContext ||
		generated.TagType != ber.TypePrimitive ||
		generated.Tag != ber.TagEOC ||
		generated.Data == nil {
		return nil, false, errors.New("password modify response contains an invalid generated password")
	}
	if generated.Data.Len() > maxPasswordInputSize {
		return nil, false, fmt.Errorf(
			"generated password exceeds %d bytes",
			maxPasswordInputSize,
		)
	}
	return bytes.Clone(generated.Data.Bytes()), true, nil
}

func validateLDAPPasswordSources(
	flags *flag.FlagSet,
	direct *secretFlagValue,
	directName, promptName, fileName string,
	prompt bool,
	file string,
	description string,
) error {
	if direct.count > 1 {
		return fmt.Errorf("%s was provided more than once", description)
	}
	if direct.count == 1 && len(direct.value) == 0 {
		return fmt.Errorf("%s must not be empty", description)
	}
	if flagWasSet(flags, promptName) && !prompt {
		return fmt.Errorf("-%s=false is not supported", promptName)
	}
	sources := 0
	for _, name := range []string{directName, promptName, fileName} {
		if flagWasSet(flags, name) {
			sources++
		}
	}
	if sources > 1 {
		return fmt.Errorf("-%s, -%s, and -%s %s sources are mutually exclusive",
			directName, promptName, fileName, description)
	}
	if flagWasSet(flags, fileName) && file == "" {
		return fmt.Errorf("-%s requires a non-empty password file path", fileName)
	}
	return nil
}

func validateLDAPPasswordDryRunSources(
	flags *flag.FlagSet,
	stderr io.Writer,
	oldDirect *secretFlagValue,
	oldFile, oldDirectName, oldFileName string,
	newDirect *secretFlagValue,
	newFile, newDirectName, newFileName string,
) error {
	for _, source := range []struct {
		direct     *secretFlagValue
		file       string
		directName string
		fileName   string
		label      string
	}{
		{oldDirect, oldFile, oldDirectName, oldFileName, "old password"},
		{newDirect, newFile, newDirectName, newFileName, "new password"},
	} {
		if flagWasSet(flags, source.directName) && len(source.direct.value) == 0 {
			return fmt.Errorf("%s must not be empty", source.label)
		}
		if flagWasSet(flags, source.fileName) {
			password, err := readLDAPPasswordFile(source.file, stderr)
			if err != nil {
				return fmt.Errorf("read %s: %w", source.label, err)
			}
			if len(password) == 0 {
				clear(password)
				return fmt.Errorf("%s must not be empty", source.label)
			}
			clear(password)
		}
	}
	return nil
}

func loadLDAPOperationPassword(
	flags *flag.FlagSet,
	stdin io.Reader,
	stderr io.Writer,
	direct *secretFlagValue,
	directName, promptName, fileName, file string,
	prompt, confirmationPrompt string,
) ([]byte, bool, error) {
	var password []byte
	var err error
	switch {
	case flagWasSet(flags, directName):
		password = direct.take()
	case flagWasSet(flags, promptName):
		password, err = readConfirmedLDAPPassword(
			stdin,
			stderr,
			prompt,
			confirmationPrompt,
		)
	case flagWasSet(flags, fileName):
		password, err = readLDAPPasswordFile(file, stderr)
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(password) == 0 {
		clear(password)
		return nil, false, errors.New("password must not be empty")
	}
	return password, true, nil
}

func readConfirmedLDAPPassword(
	reader io.Reader,
	stderr io.Writer,
	prompt, confirmationPrompt string,
) ([]byte, error) {
	if _, err := io.WriteString(stderr, prompt); err != nil {
		return nil, err
	}
	password, err := readLDAPPromptPassword(reader, stderr)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(stderr, confirmationPrompt); err != nil {
		clear(password)
		return nil, err
	}
	confirmation, err := readLDAPPromptPassword(reader, stderr)
	if err != nil {
		clear(password)
		return nil, err
	}
	defer clear(confirmation)
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		clear(password)
		return nil, errors.New("passwords do not match")
	}
	return password, nil
}

type ldapExopKind uint8

const (
	ldapExopWhoAmI ldapExopKind = iota + 1
	ldapExopCancel
	ldapExopRefresh
	ldapExopPasswd
	ldapExopGeneric
)

type ldapExopInvocation struct {
	kind       ldapExopKind
	oid        string
	value      []byte
	hasValue   bool
	cancelID   int64
	refreshDN  string
	refreshTTL int64
	passwdUser string
}

func (invocation *ldapExopInvocation) clear() {
	clear(invocation.value)
	invocation.value = nil
}

func runLDAPExop(
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	flags := flag.NewFlagSet("ldapexop", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var client ldapClientOptions
	client.register(flags)
	defer client.clear()
	var passwordOptions ldapPasswordCLIOptions
	passwordOptions.register(flags)
	defer passwordOptions.clear()
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := client.validateWrite(flags); err != nil {
		return err
	}
	invocation, err := parseLDAPExopInvocation(flags.Args())
	if err != nil {
		return err
	}
	defer invocation.clear()
	if invocation.kind == ldapExopPasswd {
		if err := passwordOptions.validate(flags); err != nil {
			return err
		}
	} else if passwordOptions.wasSet(flags) {
		return errors.New("ldapexop password options require the passwd operation")
	}
	if client.dryRun {
		if invocation.kind == ldapExopPasswd {
			return passwordOptions.validateDryRun(flags, stderr)
		}
		return nil
	}
	if invocation.kind == ldapExopPasswd {
		return passwordOptions.execute(
			&client,
			flags,
			stdin,
			stdout,
			stderr,
			invocation.passwdUser,
		)
	}

	connection, err := client.connectAndBind(flags, stdin, stderr)
	if err != nil {
		return err
	}
	defer connection.Close()
	switch invocation.kind {
	case ldapExopWhoAmI:
		authzID, err := ldapWhoAmIRequest(&client, connection, client.generalControls)
		if err != nil {
			return fmt.Errorf("Who Am I extended operation: %w", err)
		}
		defer clear(authzID)
		if len(authzID) == 0 {
			_, err = io.WriteString(stdout, "anonymous\n")
			return err
		}
		if ldifValueRequiresBase64(authzID) {
			return writeLDIFAttribute(stdout, "authzID", authzID)
		}
		return writePasswordOutput(stdout, authzID, false)

	case ldapExopCancel:
		value := ldapwire.EncodeCancelRequestValue(invocation.cancelID)
		defer clear(value)
		request := ldap.NewExtendedRequest(
			ldapCancelOID,
			newLDAPExtendedRequestValue(value),
		)
		request.Controls = client.generalControls
		defer func() { request.Value = nil }()
		if _, err := client.extendedWithReferrals(connection, request); err != nil {
			return fmt.Errorf("cancel operation %d: %w", invocation.cancelID, err)
		}
		return nil

	case ldapExopRefresh:
		value := ldapwire.EncodeDynamicRefreshRequestValue(
			invocation.refreshDN,
			invocation.refreshTTL,
		)
		defer clear(value)
		request := ldap.NewExtendedRequest(
			ldapDynamicRefreshOID,
			newLDAPExtendedRequestValue(value),
		)
		request.Controls = client.generalControls
		defer func() { request.Value = nil }()
		response, err := client.extendedWithReferrals(connection, request)
		if err != nil {
			return fmt.Errorf("refresh %q: %w", invocation.refreshDN, err)
		}
		responseValue, err := ldapExtendedResponseBytes(response)
		if err != nil {
			return fmt.Errorf("refresh response: %w", err)
		}
		responseTTL, err := ldapwire.DecodeDynamicRefreshResponseValue(responseValue)
		if err != nil {
			return fmt.Errorf("decode refresh response: %w", err)
		}
		_, err = fmt.Fprintf(stdout, "newttl=%d\n", responseTTL)
		return err

	case ldapExopPasswd:
		return errors.New("password modify execution was not initialized")

	case ldapExopGeneric:
		var value *ber.Packet
		if invocation.hasValue {
			value = newLDAPExtendedRequestValue(invocation.value)
		}
		request := ldap.NewExtendedRequest(invocation.oid, value)
		request.Controls = client.generalControls
		defer func() { request.Value = nil }()
		response, err := client.extendedWithReferrals(connection, request)
		if err != nil {
			return fmt.Errorf("extended operation %s: %w", invocation.oid, err)
		}
		return writeLDAPExtendedResponse(stdout, response)

	default:
		return errors.New("unknown LDAP extended operation")
	}
}

func parseLDAPExopInvocation(args []string) (*ldapExopInvocation, error) {
	if len(args) == 0 {
		return nil, errors.New("ldapexop requires whoami, cancel, refresh, passwd, or OID[:value]")
	}
	switch strings.ToLower(args[0]) {
	case "whoami":
		if len(args) != 1 {
			return nil, errors.New("ldapexop whoami takes no arguments")
		}
		return &ldapExopInvocation{kind: ldapExopWhoAmI}, nil

	case "cancel":
		if len(args) != 2 {
			return nil, errors.New("ldapexop cancel requires one positive message ID")
		}
		messageID, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil || messageID <= 0 {
			return nil, fmt.Errorf("invalid cancel message ID %q", args[1])
		}
		return &ldapExopInvocation{kind: ldapExopCancel, cancelID: messageID}, nil

	case "refresh":
		if len(args) < 2 || len(args) > 3 {
			return nil, errors.New("ldapexop refresh requires DN and optional positive TTL")
		}
		if _, err := ldap.ParseDN(args[1]); err != nil {
			return nil, fmt.Errorf("parse refresh DN: %w", err)
		}
		ttl := int64(defaultLDAPRefreshSeconds)
		if len(args) == 3 {
			var err error
			ttl, err = strconv.ParseInt(args[2], 10, 32)
			if err != nil || ttl <= 0 {
				return nil, fmt.Errorf("invalid refresh TTL %q", args[2])
			}
		}
		return &ldapExopInvocation{
			kind:       ldapExopRefresh,
			refreshDN:  args[1],
			refreshTTL: ttl,
		}, nil

	case "passwd":
		if len(args) > 2 {
			return nil, errors.New("ldapexop passwd accepts at most one user identity")
		}
		userIdentity := ""
		if len(args) == 2 {
			userIdentity = args[1]
			if userIdentity == "" || strings.ContainsAny(userIdentity, "\x00\r\n") {
				return nil, errors.New(
					"user identity must be non-empty and contain no NUL or line breaks",
				)
			}
		}
		return &ldapExopInvocation{
			kind:       ldapExopPasswd,
			passwdUser: userIdentity,
		}, nil
	}

	if len(args) != 1 {
		return nil, errors.New("a generic ldapexop accepts exactly one OID[:value] argument")
	}
	oid, value, hasValue, err := parseLDAPGenericExop(args[0])
	if err != nil {
		return nil, err
	}
	return &ldapExopInvocation{
		kind:     ldapExopGeneric,
		oid:      oid,
		value:    value,
		hasValue: hasValue,
	}, nil
}

func parseLDAPGenericExop(argument string) (string, []byte, bool, error) {
	separator := strings.IndexByte(argument, ':')
	oid := strings.TrimSpace(argument)
	if separator >= 0 {
		oid = strings.TrimSpace(argument[:separator])
	}
	if !validLDAPOperationOID(oid) {
		return "", nil, false, fmt.Errorf("invalid LDAP extended operation OID %q", oid)
	}
	if separator < 0 {
		return oid, nil, false, nil
	}
	value := argument[separator+1:]
	if strings.HasPrefix(value, "<") {
		location := strings.TrimLeft(value[1:], " \t\r\n\v\f")
		if location == "" {
			return "", nil, false, errors.New("extended operation value is missing a URL")
		}
		loaded, err := readLDAPExopURL(location)
		if err != nil {
			return "", nil, false, err
		}
		return oid, loaded, true, nil
	}
	if strings.HasPrefix(value, ":") {
		value = strings.TrimLeft(value[1:], " \t\r\n\v\f")
		if value == "" {
			return "", nil, false, errors.New("extended operation value is missing base64 data")
		}
		decoded, err := decodeLDAPCLIBase64(value, "extended operation value")
		if err != nil {
			return "", nil, false, err
		}
		return oid, decoded, true, nil
	}
	value = strings.TrimLeft(value, " ")
	if len(value) > maxLDAPExtendedValueSize {
		return "", nil, false, fmt.Errorf(
			"extended operation value exceeds %d bytes",
			maxLDAPExtendedValueSize,
		)
	}
	return oid, []byte(value), true, nil
}

func readLDAPExopURL(location string) ([]byte, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse extended operation value URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "file") {
		return nil, fmt.Errorf(
			"extended operation value URL scheme %q is not supported; use file:",
			parsed.Scheme,
		)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("extended operation file URL must not contain userinfo, query, or fragment")
	}

	path := parsed.Path
	if parsed.Opaque != "" {
		path = parsed.Opaque
	}
	if parsed.Host != "" {
		if runtime.GOOS != "windows" || len(parsed.Host) != 2 || parsed.Host[1] != ':' {
			return nil, errors.New("extended operation file URL must not contain a host")
		}
		path = parsed.Host + parsed.Path
	}
	if runtime.GOOS == "windows" {
		path = strings.TrimPrefix(path, "/")
	}
	path = filepath.FromSlash(path)
	if path == "" {
		return nil, errors.New("extended operation file URL has an empty path")
	}
	return readLimitedClientFile(
		path,
		maxLDAPExtendedValueSize,
		"extended operation value file",
	)
}

func validLDAPOperationOID(oid string) bool {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func decodeLDAPCLIBase64(value, description string) ([]byte, error) {
	if strings.ContainsAny(value, " \t\r\n") {
		return nil, fmt.Errorf("%s contains whitespace in base64 data", description)
	}
	if len(value) > base64.StdEncoding.EncodedLen(maxLDAPExtendedValueSize) {
		return nil, fmt.Errorf("%s exceeds %d decoded bytes", description, maxLDAPExtendedValueSize)
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	length, err := base64.StdEncoding.Strict().Decode(decoded, []byte(value))
	if err != nil {
		clear(decoded)
		return nil, fmt.Errorf("decode %s as base64: %w", description, err)
	}
	decoded = decoded[:length]
	if len(decoded) > maxLDAPExtendedValueSize {
		clear(decoded)
		return nil, fmt.Errorf("%s exceeds %d decoded bytes", description, maxLDAPExtendedValueSize)
	}
	return decoded, nil
}

func newLDAPExtendedRequestValue(value []byte) *ber.Packet {
	packet := ber.Encode(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		nil,
		"Extended Request Value",
	)
	_, _ = packet.Data.Write(value)
	return packet
}

func ldapWhoAmIRequest(
	client *ldapClientOptions,
	connection *ldap.Conn,
	controls []ldap.Control,
) ([]byte, error) {
	request := ldap.NewExtendedRequest(ldapWhoAmIOID, nil)
	request.Controls = controls
	response, err := client.extendedWithReferrals(connection, request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("server returned a nil Who Am I response")
	}
	if response.Name != "" && response.Name != ldapWhoAmIOID {
		return nil, fmt.Errorf("server returned Who Am I response OID %q", response.Name)
	}
	defer clearBERPacket(response.Value)
	value, err := ldapExtendedResponseBytes(response)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(value), nil
}

func clearBERPacket(packet *ber.Packet) {
	if packet == nil {
		return
	}
	for _, child := range packet.Children {
		clearBERPacket(child)
	}
	clear(packet.ByteValue)
	packet.ByteValue = nil
	if packet.Data != nil {
		clear(packet.Data.Bytes())
		packet.Data.Reset()
	}
	packet.Value = nil
}

func ldapExtendedResponseBytes(response *ldap.ExtendedResponse) ([]byte, error) {
	if response == nil || response.Value == nil || response.Value.Data == nil {
		return nil, errors.New("server omitted the extended response value")
	}
	if response.Value.ClassType != ber.ClassContext ||
		response.Value.TagType != ber.TypePrimitive ||
		response.Value.Tag != ber.TagEmbeddedPDV {
		return nil, errors.New("server returned an invalid extended response value")
	}
	value := response.Value.Data.Bytes()
	if len(value) > maxLDAPExtendedValueSize {
		return nil, fmt.Errorf("extended response value exceeds %d bytes", maxLDAPExtendedValueSize)
	}
	return value, nil
}

func writeLDAPExtendedResponse(writer io.Writer, response *ldap.ExtendedResponse) error {
	if response == nil {
		return errors.New("server returned a nil extended response")
	}
	if response.Name != "" && !validLDAPOperationOID(response.Name) {
		return fmt.Errorf("server returned invalid extended response OID %q", response.Name)
	}
	var value []byte
	if response.Value != nil {
		var err error
		value, err = ldapExtendedResponseBytes(response)
		if err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, "# extended operation response\n"); err != nil {
		return err
	}
	if response.Name != "" {
		if err := writeLDIFAttribute(writer, "oid", []byte(response.Name)); err != nil {
			return err
		}
	}
	if response.Value != nil {
		if len(value) == 0 {
			return writeLDIFAttribute(writer, "data", nil)
		}
		if err := writeLDIFBase64Attribute(writer, "data", value); err != nil {
			return err
		}
	}
	return nil
}

func writeLDIFBase64Attribute(writer io.Writer, name string, value []byte) error {
	line := make([]byte, len(name)+3+base64.StdEncoding.EncodedLen(len(value)))
	defer clear(line)
	position := copy(line, name)
	position += copy(line[position:], ":: ")
	base64.StdEncoding.Encode(line[position:], value)
	return writeFoldedLDIFLine(writer, line)
}
