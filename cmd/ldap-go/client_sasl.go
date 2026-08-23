package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // DIGEST-MD5 is required for OpenLDAP CLI interoperability.
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
	"github.com/xdg-go/stringprep"
)

const (
	ldapClientSASLMaxChallengeSize = 64 << 10
	ldapClientCRAMMaxChallengeSize = 1024
	ldapClientSCRAMMinIterations   = 4096
	ldapClientSCRAMMaxIterations   = 10_000_000
	ldapClientSCRAMMaxSaltSize     = 1024
)

type ldapClientSASLResult struct {
	code                 uint16
	matchedDN            string
	serverCredentials    []byte
	hasServerCredentials bool
	packet               *ber.Packet
}

func (result ldapClientSASLResult) err() error {
	if result.code == ldap.LDAPResultSuccess {
		return nil
	}
	message := ldap.LDAPResultCodeMap[result.code]
	if message == "" {
		message = "LDAP SASL bind failed"
	}
	return &ldap.Error{
		ResultCode: result.code,
		MatchedDN:  result.matchedDN,
		Err:        errors.New(message),
		Packet:     result.packet,
	}
}

func (options *ldapClientOptions) validateSASL(
	flags *flag.FlagSet,
	passwordSources int,
) error {
	if !flagWasSet(flags, "Y") || strings.TrimSpace(options.saslMechanism) == "" {
		return errors.New("SASL authentication requires -Y with an explicit mechanism")
	}
	options.saslMechanism = strings.ToUpper(strings.TrimSpace(options.saslMechanism))
	for name, value := range map[string]string{
		"-U": options.saslAuthentication,
		"-X": options.saslAuthorization,
		"-R": options.saslRealm,
	} {
		if strings.IndexByte(value, 0) >= 0 || !utf8.ValidString(value) {
			return fmt.Errorf("%s must be valid UTF-8 without NUL", name)
		}
	}

	switch options.saslMechanism {
	case "PLAIN":
		if options.saslAuthentication == "" {
			return errors.New("SASL PLAIN requires a non-empty -U authentication identity")
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources == 0 {
			return errors.New("SASL PLAIN requires one of -w, -W, or -y")
		}
	case "DIGEST-MD5":
		if options.saslAuthentication == "" {
			return errors.New("SASL DIGEST-MD5 requires a non-empty -U authentication identity")
		}
		if flagWasSet(flags, "R") && options.saslRealm == "" {
			return errors.New("-R requires a non-empty SASL realm")
		}
		if passwordSources == 0 {
			return errors.New("SASL DIGEST-MD5 requires one of -w, -W, or -y")
		}
	case "CRAM-MD5":
		if options.saslAuthentication == "" {
			return errors.New("SASL CRAM-MD5 requires a non-empty -U authentication identity")
		}
		if strings.ContainsAny(options.saslAuthentication, " \t\r\n") {
			return errors.New("SASL CRAM-MD5 -U authentication identity must not contain whitespace")
		}
		if flagWasSet(flags, "X") {
			return errors.New("SASL CRAM-MD5 does not support -X authorization identities")
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources == 0 {
			return errors.New("SASL CRAM-MD5 requires one of -w, -W, or -y")
		}
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512":
		if options.saslAuthentication == "" {
			return fmt.Errorf(
				"SASL %s requires a non-empty -U authentication identity",
				options.saslMechanism,
			)
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources == 0 {
			return fmt.Errorf(
				"SASL %s requires one of -w, -W, or -y",
				options.saslMechanism,
			)
		}
	case "EXTERNAL":
		if flagWasSet(flags, "U") {
			return errors.New("SASL EXTERNAL obtains its authentication identity from TLS; do not use -U")
		}
		if flagWasSet(flags, "R") {
			return errors.New("-R is only supported with SASL DIGEST-MD5")
		}
		if passwordSources != 0 {
			return errors.New("SASL EXTERNAL does not use -w, -W, or -y")
		}
		if options.tlsCertificateFile == "" || options.tlsPrivateKeyFile == "" {
			return errors.New("SASL EXTERNAL requires -tls-cert and -tls-key")
		}
	default:
		if strings.HasPrefix(options.saslMechanism, "SCRAM-") &&
			strings.HasSuffix(options.saslMechanism, "-PLUS") {
			return errors.New("SCRAM-PLUS mechanisms are not supported by the auth-only client")
		}
		return fmt.Errorf(
			"unsupported SASL mechanism %q; supported mechanisms are PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-SHA-1, SCRAM-SHA-256, SCRAM-SHA-512, and EXTERNAL",
			options.saslMechanism,
		)
	}
	if flagWasSet(flags, "X") && options.saslAuthorization == "" {
		return errors.New("-X requires a non-empty SASL authorization identity")
	}
	return nil
}

func (options *ldapClientOptions) connectAndBindSASL(
	parsedURI *url.URL,
	dialURI string,
	tlsConfig *tls.Config,
	password []byte,
	hasPassword bool,
	stderr io.Writer,
) (*ldap.Conn, error) {
	address := parsedURI.Host
	if parsedURI.Port() == "" {
		port := "389"
		if parsedURI.Scheme == "ldaps" {
			port = "636"
		}
		address = net.JoinHostPort(parsedURI.Hostname(), port)
	}
	dial := func(useTLS bool) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: options.timeout}
		if useTLS {
			connection, err := tls.DialWithDialer(
				dialer,
				"tcp",
				address,
				tlsConfig.Clone(),
			)
			if err != nil {
				return nil, err
			}
			return connection, nil
		}
		return dialer.Dial("tcp", address)
	}

	connection, err := dial(parsedURI.Scheme == "ldaps")
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", dialURI, err)
	}
	closeOnError := func(err error) (*ldap.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	secure := parsedURI.Scheme == "ldaps"
	messageID := int64(1)
	if options.tryStartTLS || options.requireStartTLS {
		upgraded, startTLSErr := ldapClientSASLStartTLS(
			connection,
			tlsConfig,
			options.timeout,
			messageID,
		)
		messageID++
		if startTLSErr != nil {
			if options.requireStartTLS {
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
			secure = true
		}
	}

	if !hasPassword && options.saslMechanism != "EXTERNAL" {
		return closeOnError(fmt.Errorf("SASL %s password was not loaded", options.saslMechanism))
	}
	if err := connection.SetDeadline(time.Now().Add(options.timeout)); err != nil {
		return closeOnError(fmt.Errorf("set SASL bind deadline: %w", err))
	}
	if err := options.bindSASL(
		connection,
		parsedURI.Hostname(),
		password,
		&messageID,
	); err != nil {
		return closeOnError(err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return closeOnError(fmt.Errorf("clear SASL bind deadline: %w", err))
	}

	client := ldap.NewConn(connection, secure)
	client.SetTimeout(options.timeout)
	client.Start()
	return client, nil
}

func ldapClientSASLStartTLS(
	connection net.Conn,
	config *tls.Config,
	timeout time.Duration,
	messageID int64,
) (net.Conn, error) {
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name: ldapStartTLSOID,
		},
	})
	if err != nil {
		return nil, err
	}
	if err := ldapwire.Write(connection, request); err != nil {
		return nil, err
	}
	result, err := readLDAPClientSASLResult(
		connection,
		messageID,
		ldap.ApplicationExtendedResponse,
	)
	if err != nil {
		return nil, err
	}
	if err := result.err(); err != nil {
		return nil, err
	}
	upgraded := tls.Client(connection, config.Clone())
	if err := upgraded.Handshake(); err != nil {
		return nil, err
	}
	return upgraded, nil
}

func (options *ldapClientOptions) bindSASL(
	connection net.Conn,
	host string,
	password []byte,
	messageID *int64,
) error {
	switch options.saslMechanism {
	case "PLAIN":
		return options.bindSASLPlain(connection, password, messageID)
	case "DIGEST-MD5":
		return options.bindSASLDigestMD5(connection, host, password, messageID)
	case "CRAM-MD5":
		return options.bindSASLCRAMMD5(connection, password, messageID)
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512":
		return options.bindSASLSCRAM(connection, password, messageID)
	case "EXTERNAL":
		return options.bindSASLExternal(connection, messageID)
	default:
		return fmt.Errorf("unsupported SASL mechanism %q", options.saslMechanism)
	}
}

func (options *ldapClientOptions) bindSASLPlain(
	connection net.Conn,
	password []byte,
	messageID *int64,
) error {
	credentials := make([]byte, 0, len(options.saslAuthorization)+
		len(options.saslAuthentication)+len(password)+2)
	credentials = append(credentials, options.saslAuthorization...)
	credentials = append(credentials, 0)
	credentials = append(credentials, options.saslAuthentication...)
	credentials = append(credentials, 0)
	credentials = append(credentials, password...)
	defer clear(credentials)

	for round := 0; round < 2; round++ {
		result, err := exchangeLDAPClientSASLBind(
			connection,
			takeLDAPClientMessageID(messageID),
			"PLAIN",
			credentials,
			true,
		)
		if err != nil {
			return fmt.Errorf("SASL PLAIN bind: %w", err)
		}
		switch result.code {
		case ldap.LDAPResultSuccess:
			if result.hasServerCredentials {
				return errors.New("SASL PLAIN server returned unexpected credentials")
			}
			return nil
		case ldap.LDAPResultSaslBindInProgress:
			if round != 0 || len(result.serverCredentials) != 0 {
				return errors.New("SASL PLAIN server returned an unexpected challenge")
			}
		default:
			return fmt.Errorf("SASL PLAIN bind: %w", result.err())
		}
	}
	return errors.New("SASL PLAIN bind exceeded the challenge limit")
}

func (options *ldapClientOptions) bindSASLExternal(
	connection net.Conn,
	messageID *int64,
) error {
	hasCredentials := options.saslAuthorization != ""
	result, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"EXTERNAL",
		[]byte(options.saslAuthorization),
		hasCredentials,
	)
	if err != nil {
		return fmt.Errorf("SASL EXTERNAL bind: %w", err)
	}
	if result.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("SASL EXTERNAL bind: %w", result.err())
	}
	if result.hasServerCredentials {
		return errors.New("SASL EXTERNAL server returned unexpected credentials")
	}
	return nil
}

func (options *ldapClientOptions) bindSASLCRAMMD5(
	connection net.Conn,
	password []byte,
	messageID *int64,
) error {
	first, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"CRAM-MD5",
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("SASL CRAM-MD5 bind: %w", err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		if resultErr := first.err(); resultErr != nil {
			return fmt.Errorf("SASL CRAM-MD5 bind: %w", resultErr)
		}
		return errors.New("SASL CRAM-MD5 server completed without a challenge")
	}
	if err := validateLDAPClientCRAMMD5Challenge(
		first.serverCredentials,
		first.hasServerCredentials,
	); err != nil {
		return err
	}
	authenticationID, err := stringprep.SASLprep.Prepare(
		options.saslAuthentication,
	)
	if err != nil || authenticationID == "" ||
		strings.ContainsAny(authenticationID, " \t\r\n") {
		return errors.New("SASL CRAM-MD5 authentication identity is not a valid SASLprep value")
	}
	mac := hmac.New(md5.New, password) //nolint:gosec // CRAM-MD5 requires HMAC-MD5.
	_, _ = mac.Write(first.serverCredentials)
	macSum := mac.Sum(nil)
	digest := make([]byte, hex.EncodedLen(md5.Size))
	hex.Encode(digest, macSum)
	clear(macSum)
	response := make([]byte, 0, len(authenticationID)+1+len(digest))
	response = append(response, authenticationID...)
	response = append(response, ' ')
	response = append(response, digest...)
	clear(digest)
	defer clear(response)

	final, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"CRAM-MD5",
		response,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL CRAM-MD5 bind: %w", err)
	}
	if final.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("SASL CRAM-MD5 bind: %w", final.err())
	}
	if final.hasServerCredentials {
		return errors.New("SASL CRAM-MD5 server returned unexpected final credentials")
	}
	return nil
}

func validateLDAPClientCRAMMD5Challenge(challenge []byte, present bool) error {
	if !present || len(challenge) < 5 || len(challenge) > ldapClientCRAMMaxChallengeSize ||
		challenge[0] != '<' || challenge[len(challenge)-1] != '>' {
		return errors.New("SASL CRAM-MD5 server returned a malformed challenge")
	}
	at := bytes.LastIndexByte(challenge, '@')
	if at <= 1 || at >= len(challenge)-2 || bytes.IndexByte(challenge[1:at], '@') >= 0 {
		return errors.New("SASL CRAM-MD5 challenge is not a valid message ID")
	}
	for _, value := range challenge[1 : len(challenge)-1] {
		if value <= 0x20 || value >= 0x7f || value == '<' || value == '>' {
			return errors.New("SASL CRAM-MD5 challenge contains invalid bytes")
		}
	}
	return nil
}

func (options *ldapClientOptions) bindSASLSCRAM(
	connection net.Conn,
	password []byte,
	messageID *int64,
) error {
	generator, ok := ldapClientSCRAMGenerator(options.saslMechanism)
	if !ok {
		return fmt.Errorf("unsupported SCRAM mechanism %q", options.saslMechanism)
	}
	client, err := generator.NewClient(
		options.saslAuthentication,
		string(password),
		options.saslAuthorization,
	)
	if err != nil {
		return fmt.Errorf("SASL %s credentials are not valid SASLprep values", options.saslMechanism)
	}
	client.WithMinIterations(ldapClientSCRAMMinIterations)
	conversation := client.NewConversation()
	clientFirst, err := conversation.Step("")
	if err != nil {
		return fmt.Errorf("initialize SASL %s conversation", options.saslMechanism)
	}
	clientNonce, err := ldapClientSCRAMClientNonce(clientFirst)
	if err != nil {
		return fmt.Errorf("initialize SASL %s nonce: %w", options.saslMechanism, err)
	}

	first, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		options.saslMechanism,
		[]byte(clientFirst),
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		if resultErr := first.err(); resultErr != nil {
			return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, resultErr)
		}
		return fmt.Errorf("SASL %s server completed before sending server-first", options.saslMechanism)
	}
	serverFirst := first.serverCredentials
	if !first.hasServerCredentials {
		return fmt.Errorf("SASL %s server omitted server-first", options.saslMechanism)
	}
	if err := validateLDAPClientSCRAMServerFirst(serverFirst, clientNonce); err != nil {
		return fmt.Errorf("SASL %s server-first: %w", options.saslMechanism, err)
	}
	clientFinal, err := conversation.Step(string(serverFirst))
	if err != nil {
		return fmt.Errorf("SASL %s server-first was rejected", options.saslMechanism)
	}

	clientFinalBytes := []byte(clientFinal)
	defer clear(clientFinalBytes)
	final, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		options.saslMechanism,
		clientFinalBytes,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, err)
	}
	if final.code != ldap.LDAPResultSuccess &&
		final.code != ldap.LDAPResultSaslBindInProgress {
		return fmt.Errorf("SASL %s bind: %w", options.saslMechanism, final.err())
	}
	if !final.hasServerCredentials {
		return fmt.Errorf("SASL %s server omitted server-final proof", options.saslMechanism)
	}
	if err := validateLDAPClientSCRAMServerFinal(
		final.serverCredentials,
		generator().Size(),
	); err != nil {
		return fmt.Errorf("SASL %s server-final: %w", options.saslMechanism, err)
	}
	if response, err := conversation.Step(string(final.serverCredentials)); err != nil || response != "" || !conversation.Done() || !conversation.Valid() {
		return fmt.Errorf("SASL %s server signature is invalid", options.saslMechanism)
	}
	if final.code == ldap.LDAPResultSuccess {
		return nil
	}

	completed, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		options.saslMechanism,
		[]byte{},
		true,
	)
	if err != nil {
		return fmt.Errorf("complete SASL %s bind: %w", options.saslMechanism, err)
	}
	if completed.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("complete SASL %s bind: %w", options.saslMechanism, completed.err())
	}
	if completed.hasServerCredentials {
		return fmt.Errorf("SASL %s server returned unexpected completion data", options.saslMechanism)
	}
	return nil
}

func ldapClientSCRAMGenerator(mechanism string) (scram.HashGeneratorFcn, bool) {
	switch mechanism {
	case "SCRAM-SHA-1":
		return scram.SHA1, true
	case "SCRAM-SHA-256":
		return scram.SHA256, true
	case "SCRAM-SHA-512":
		return scram.SHA512, true
	default:
		return nil, false
	}
}

func ldapClientSCRAMClientNonce(clientFirst string) (string, error) {
	fields := strings.Split(clientFirst, ",")
	if len(fields) != 4 || fields[0] != "n" ||
		(fields[1] != "" && !strings.HasPrefix(fields[1], "a=")) ||
		!strings.HasPrefix(fields[2], "n=") || !strings.HasPrefix(fields[3], "r=") {
		return "", errors.New("SCRAM client-first message is malformed")
	}
	nonce := strings.TrimPrefix(fields[3], "r=")
	if !ldapClientSCRAMNonceValid(nonce) {
		return "", errors.New("SCRAM client nonce is malformed")
	}
	return nonce, nil
}

func validateLDAPClientSCRAMServerFirst(serverFirst []byte, clientNonce string) error {
	if len(serverFirst) == 0 || len(serverFirst) > ldapClientSASLMaxChallengeSize ||
		!utf8.Valid(serverFirst) || bytes.IndexByte(serverFirst, 0) >= 0 {
		return errors.New("server-first has invalid encoding or size")
	}
	fields := strings.Split(string(serverFirst), ",")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "r=") ||
		!strings.HasPrefix(fields[1], "s=") || !strings.HasPrefix(fields[2], "i=") {
		return errors.New("server-first must contain only canonical r, s, and i fields")
	}
	nonce := strings.TrimPrefix(fields[0], "r=")
	if len(nonce) <= len(clientNonce) || !strings.HasPrefix(nonce, clientNonce) ||
		!ldapClientSCRAMNonceValid(nonce) {
		return errors.New("server nonce did not strictly extend the client nonce")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(fields[1], "s="))
	if err != nil || len(salt) == 0 || len(salt) > ldapClientSCRAMMaxSaltSize {
		clear(salt)
		return errors.New("server salt is malformed")
	}
	clear(salt)
	rawIterations := strings.TrimPrefix(fields[2], "i=")
	if rawIterations == "" || (len(rawIterations) > 1 && rawIterations[0] == '0') {
		return errors.New("server iteration count is not canonical")
	}
	for _, value := range rawIterations {
		if value < '0' || value > '9' {
			return errors.New("server iteration count is malformed")
		}
	}
	iterations, err := strconv.ParseUint(rawIterations, 10, 32)
	if err != nil || iterations < ldapClientSCRAMMinIterations ||
		iterations > ldapClientSCRAMMaxIterations {
		return fmt.Errorf(
			"server iteration count must be between %d and %d",
			ldapClientSCRAMMinIterations,
			ldapClientSCRAMMaxIterations,
		)
	}
	return nil
}

func validateLDAPClientSCRAMServerFinal(serverFinal []byte, hashSize int) error {
	if len(serverFinal) == 0 || len(serverFinal) > ldapClientSASLMaxChallengeSize ||
		!utf8.Valid(serverFinal) || bytes.IndexByte(serverFinal, 0) >= 0 {
		return errors.New("server-final has invalid encoding or size")
	}
	text := string(serverFinal)
	if strings.Contains(text, ",") || !strings.HasPrefix(text, "v=") {
		return errors.New("server-final must contain only a verifier")
	}
	verifier, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(text, "v="))
	if err != nil || len(verifier) != hashSize {
		clear(verifier)
		return errors.New("server-final verifier is malformed")
	}
	clear(verifier)
	return nil
}

func ldapClientSCRAMNonceValid(nonce string) bool {
	if nonce == "" {
		return false
	}
	for _, value := range []byte(nonce) {
		if value < 0x21 || value > 0x7e || value == ',' {
			return false
		}
	}
	return true
}

func (options *ldapClientOptions) bindSASLDigestMD5(
	connection net.Conn,
	host string,
	password []byte,
	messageID *int64,
) error {
	first, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"DIGEST-MD5",
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("SASL DIGEST-MD5 bind: %w", err)
	}
	if first.code != ldap.LDAPResultSaslBindInProgress {
		if resultErr := first.err(); resultErr != nil {
			return fmt.Errorf("SASL DIGEST-MD5 bind: %w", resultErr)
		}
		return errors.New("SASL DIGEST-MD5 server completed without a challenge")
	}
	if !first.hasServerCredentials {
		return errors.New("SASL DIGEST-MD5 server omitted its challenge")
	}
	response, expectedRspauth, err := options.digestMD5Response(
		first.serverCredentials,
		host,
		password,
	)
	if err != nil {
		return fmt.Errorf("process SASL DIGEST-MD5 challenge: %w", err)
	}
	defer clear(response)
	defer clear(expectedRspauth)

	second, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"DIGEST-MD5",
		response,
		true,
	)
	if err != nil {
		return fmt.Errorf("SASL DIGEST-MD5 bind: %w", err)
	}
	if second.code != ldap.LDAPResultSuccess &&
		second.code != ldap.LDAPResultSaslBindInProgress {
		return fmt.Errorf("SASL DIGEST-MD5 bind: %w", second.err())
	}
	if err := verifyLDAPClientDigestMD5Rspauth(
		second.serverCredentials,
		second.hasServerCredentials,
		expectedRspauth,
	); err != nil {
		return err
	}
	if second.code == ldap.LDAPResultSuccess {
		return nil
	}

	final, err := exchangeLDAPClientSASLBind(
		connection,
		takeLDAPClientMessageID(messageID),
		"DIGEST-MD5",
		[]byte{},
		true,
	)
	if err != nil {
		return fmt.Errorf("complete SASL DIGEST-MD5 bind: %w", err)
	}
	if final.code != ldap.LDAPResultSuccess {
		return fmt.Errorf("complete SASL DIGEST-MD5 bind: %w", final.err())
	}
	if final.hasServerCredentials {
		return errors.New("SASL DIGEST-MD5 server returned unexpected final credentials")
	}
	return nil
}

func takeLDAPClientMessageID(next *int64) int64 {
	messageID := *next
	*next = messageID + 1
	return messageID
}

func exchangeLDAPClientSASLBind(
	connection net.Conn,
	messageID int64,
	mechanism string,
	credentials []byte,
	hasCredentials bool,
) (ldapClientSASLResult, error) {
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.BindRequest{
			Version: 3,
			Authentication: ldapwire.Authentication{
				IsSASL:             true,
				SASLMechanism:      mechanism,
				SASLCredentials:    credentials,
				HasSASLCredentials: hasCredentials,
			},
		},
	})
	if err != nil {
		return ldapClientSASLResult{}, err
	}
	defer clear(request)
	if err := ldapwire.Write(connection, request); err != nil {
		return ldapClientSASLResult{}, err
	}
	return readLDAPClientSASLResult(
		connection,
		messageID,
		ldap.ApplicationBindResponse,
	)
}

func readLDAPClientSASLResult(
	reader io.Reader,
	messageID int64,
	responseTag uint64,
) (ldapClientSASLResult, error) {
	packet, err := ber.ReadPacket(io.LimitReader(reader, ldapClientSASLMaxChallengeSize))
	if err != nil {
		return ldapClientSASLResult{}, fmt.Errorf("read LDAP response: %w", err)
	}
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypeConstructed, uint64(ber.TagSequence)) ||
		len(packet.Children) < 2 || len(packet.Children) > 3 {
		return ldapClientSASLResult{}, errors.New("malformed LDAP response envelope")
	}
	if len(packet.Children) == 3 &&
		!ldapClientPacketIs(packet.Children[2], ber.ClassContext, ber.TypeConstructed, 0) {
		return ldapClientSASLResult{}, errors.New("malformed LDAP response controls")
	}
	id, ok := ldapClientPacketInteger(packet.Children[0])
	if !ok || id != messageID {
		return ldapClientSASLResult{}, errors.New("LDAP response has an unexpected message ID")
	}
	operation := packet.Children[1]
	if !ldapClientPacketIs(operation, ber.ClassApplication, ber.TypeConstructed, responseTag) ||
		len(operation.Children) < 3 {
		return ldapClientSASLResult{}, errors.New("malformed LDAP result response")
	}
	code, ok := ldapClientPacketInteger(operation.Children[0])
	if !ok || code < 0 || code > 65535 {
		return ldapClientSASLResult{}, errors.New("malformed LDAP result code")
	}
	matchedDN, ok := ldapClientPacketBytes(operation.Children[1])
	if !ok {
		return ldapClientSASLResult{}, errors.New("malformed LDAP matched DN")
	}
	_, ok = ldapClientPacketBytes(operation.Children[2])
	if !ok {
		return ldapClientSASLResult{}, errors.New("malformed LDAP diagnostic message")
	}
	result := ldapClientSASLResult{
		code:      uint16(code),
		matchedDN: string(matchedDN),
		packet:    packet,
	}
	for _, child := range operation.Children[3:] {
		if responseTag == ldap.ApplicationBindResponse &&
			ldapClientPacketIs(child, ber.ClassContext, ber.TypePrimitive, 7) {
			if result.hasServerCredentials {
				return ldapClientSASLResult{}, errors.New("duplicate server SASL credentials")
			}
			result.serverCredentials = bytes.Clone(child.Data.Bytes())
			result.hasServerCredentials = true
			continue
		}
		if ldapClientPacketIs(child, ber.ClassContext, ber.TypeConstructed, 3) {
			for _, referral := range child.Children {
				if _, ok := ldapClientPacketBytes(referral); !ok {
					return ldapClientSASLResult{}, errors.New("malformed LDAP referral")
				}
			}
			continue
		}
		if responseTag == ldap.ApplicationExtendedResponse &&
			child.ClassType == ber.ClassContext && child.TagType == ber.TypePrimitive &&
			(child.Tag == 10 || child.Tag == 11) {
			continue
		}
		return ldapClientSASLResult{}, errors.New("LDAP response contains an unexpected element")
	}
	return result, nil
}

func ldapClientPacketIs(packet *ber.Packet, class ber.Class, kind ber.Type, tag uint64) bool {
	return packet != nil && packet.ClassType == class && packet.TagType == kind &&
		uint64(packet.Tag) == tag
}

func ldapClientPacketInteger(packet *ber.Packet) (int64, bool) {
	if packet == nil || packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypePrimitive ||
		(packet.Tag != ber.TagInteger && packet.Tag != ber.TagEnumerated) {
		return 0, false
	}
	value, ok := packet.Value.(int64)
	return value, ok
}

func ldapClientPacketBytes(packet *ber.Packet) ([]byte, bool) {
	if !ldapClientPacketIs(packet, ber.ClassUniversal, ber.TypePrimitive, uint64(ber.TagOctetString)) ||
		packet.Data == nil {
		return nil, false
	}
	return bytes.Clone(packet.Data.Bytes()), true
}

func bytesContainNUL(value []byte) bool {
	return bytes.IndexByte(value, 0) >= 0
}

type ldapClientDigestMD5Values struct {
	username      string
	realm         string
	nonce         string
	cnonce        string
	digestURI     string
	authorization string
}

func (options *ldapClientOptions) digestMD5Response(
	challenge []byte,
	host string,
	password []byte,
) ([]byte, []byte, error) {
	directives, realms, err := parseLDAPClientDigestMD5Directives(challenge, true)
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(directives["algorithm"], "md5-sess") {
		return nil, nil, errors.New("DIGEST-MD5 challenge does not use md5-sess")
	}
	if charset, present := directives["charset"]; present &&
		!strings.EqualFold(charset, "utf-8") {
		return nil, nil, errors.New("DIGEST-MD5 challenge uses an unsupported charset")
	}
	if _, utf8Offered := directives["charset"]; utf8Offered && !utf8.Valid(password) {
		return nil, nil, errors.New("DIGEST-MD5 password is not valid UTF-8")
	}
	if stale, present := directives["stale"]; present && strings.EqualFold(stale, "true") {
		return nil, nil, errors.New("DIGEST-MD5 server marked its nonce stale")
	}
	nonce := directives["nonce"]
	if nonce == "" {
		return nil, nil, errors.New("DIGEST-MD5 challenge has no nonce")
	}
	qop := directives["qop"]
	if qop == "" {
		qop = "auth"
	}
	if !ldapClientDigestMD5ListContains(qop, "auth") {
		return nil, nil, errors.New("DIGEST-MD5 challenge does not offer auth qop")
	}
	if rawMaximum, present := directives["maxbuf"]; present {
		maximum, parseErr := strconv.ParseUint(rawMaximum, 10, 24)
		if parseErr != nil || maximum <= 16 {
			return nil, nil, errors.New("DIGEST-MD5 challenge has invalid maxbuf")
		}
	}
	realm := options.saslRealm
	if realm == "" && len(realms) > 0 {
		realm = realms[0]
	}
	if options.saslRealm != "" && len(realms) > 0 &&
		!ldapClientStringSliceContains(realms, options.saslRealm) {
		return nil, nil, errors.New("requested DIGEST-MD5 realm was not offered by the server")
	}
	entropy := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, nil, fmt.Errorf("generate DIGEST-MD5 cnonce: %w", err)
	}
	cnonce := base64.RawStdEncoding.EncodeToString(entropy)
	clear(entropy)
	values := ldapClientDigestMD5Values{
		username:      options.saslAuthentication,
		realm:         realm,
		nonce:         nonce,
		cnonce:        cnonce,
		digestURI:     "ldap/" + strings.ToLower(host),
		authorization: options.saslAuthorization,
	}
	responseDigest, rspauth := ldapClientDigestMD5Exchange(values, password)
	response := fmt.Sprintf(
		`username="%s",realm="%s",nonce="%s",cnonce="%s",nc=00000001,`+
			`qop=auth,digest-uri="%s",response=%s`,
		ldapClientDigestMD5Quote(values.username),
		ldapClientDigestMD5Quote(values.realm),
		ldapClientDigestMD5Quote(values.nonce),
		ldapClientDigestMD5Quote(values.cnonce),
		ldapClientDigestMD5Quote(values.digestURI),
		responseDigest,
	)
	if values.authorization != "" {
		response += `,authzid="` + ldapClientDigestMD5Quote(values.authorization) + `"`
	}
	if _, present := directives["charset"]; present {
		response += ",charset=utf-8"
	}
	return []byte(response), []byte(rspauth), nil
}

func ldapClientDigestMD5Exchange(
	values ldapClientDigestMD5Values,
	password []byte,
) (string, string) {
	secretHash := md5.New() //nolint:gosec // Required by DIGEST-MD5.
	_, _ = secretHash.Write([]byte(values.username + ":" + values.realm + ":"))
	_, _ = secretHash.Write(password)
	secret := secretHash.Sum(nil)
	a1 := md5.New() //nolint:gosec // Required by DIGEST-MD5.
	_, _ = a1.Write(secret)
	clear(secret)
	_, _ = a1.Write([]byte(":" + values.nonce + ":" + values.cnonce))
	if values.authorization != "" {
		_, _ = a1.Write([]byte(":" + values.authorization))
	}
	sessionKey := hex.EncodeToString(a1.Sum(nil))
	calculate := func(method string) string {
		a2 := md5.Sum([]byte(method + ":" + values.digestURI)) //nolint:gosec
		material := strings.Join([]string{
			sessionKey,
			values.nonce,
			"00000001",
			values.cnonce,
			"auth",
			hex.EncodeToString(a2[:]),
		}, ":")
		digest := md5.Sum([]byte(material)) //nolint:gosec
		return hex.EncodeToString(digest[:])
	}
	return calculate("AUTHENTICATE"), calculate("")
}

func verifyLDAPClientDigestMD5Rspauth(
	credentials []byte,
	hasCredentials bool,
	expected []byte,
) error {
	if !hasCredentials {
		return errors.New("SASL DIGEST-MD5 server omitted rspauth")
	}
	directives, _, err := parseLDAPClientDigestMD5Directives(credentials, false)
	if err != nil || len(directives) != 1 {
		return errors.New("SASL DIGEST-MD5 server returned malformed rspauth")
	}
	rspauth, present := directives["rspauth"]
	if !present || len(rspauth) != len(expected) ||
		subtle.ConstantTimeCompare([]byte(rspauth), expected) != 1 {
		return errors.New("SASL DIGEST-MD5 server proof is invalid")
	}
	return nil
}

func parseLDAPClientDigestMD5Directives(
	input []byte,
	allowRepeatedRealm bool,
) (map[string]string, []string, error) {
	if len(input) == 0 || len(input) > ldapClientSASLMaxChallengeSize {
		return nil, nil, errors.New("DIGEST-MD5 directive list has invalid size")
	}
	directives := make(map[string]string)
	var realms []string
	for offset := 0; offset < len(input); {
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		start := offset
		for offset < len(input) && ldapClientDigestMD5TokenByte(input[offset]) {
			offset++
		}
		if start == offset {
			return nil, nil, errors.New("DIGEST-MD5 directive name is invalid")
		}
		name := strings.ToLower(string(input[start:offset]))
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		if offset >= len(input) || input[offset] != '=' {
			return nil, nil, errors.New("DIGEST-MD5 directive has no value")
		}
		offset++
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		var value strings.Builder
		if offset < len(input) && input[offset] == '"' {
			offset++
			closed := false
			for offset < len(input) {
				character := input[offset]
				offset++
				if character == '\\' {
					if offset >= len(input) {
						return nil, nil, errors.New("DIGEST-MD5 quoted pair is incomplete")
					}
					value.WriteByte(input[offset])
					offset++
					continue
				}
				if character == '"' {
					closed = true
					break
				}
				if character < 0x20 || character == 0x7f {
					return nil, nil, errors.New("DIGEST-MD5 quoted value is invalid")
				}
				value.WriteByte(character)
			}
			if !closed {
				return nil, nil, errors.New("DIGEST-MD5 quoted value is incomplete")
			}
		} else {
			start = offset
			for offset < len(input) && input[offset] != ',' &&
				input[offset] != ' ' && input[offset] != '\t' {
				if !ldapClientDigestMD5TokenByte(input[offset]) {
					return nil, nil, errors.New("DIGEST-MD5 token value is invalid")
				}
				offset++
			}
			if start == offset {
				return nil, nil, errors.New("DIGEST-MD5 directive value is empty")
			}
			value.Write(input[start:offset])
		}
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		if name == "realm" && allowRepeatedRealm {
			realms = append(realms, value.String())
		} else {
			if _, duplicate := directives[name]; duplicate {
				return nil, nil, errors.New("DIGEST-MD5 directive is duplicated")
			}
			directives[name] = value.String()
		}
		if offset == len(input) {
			break
		}
		if input[offset] != ',' {
			return nil, nil, errors.New("DIGEST-MD5 directives are not comma separated")
		}
		offset++
		if offset == len(input) {
			return nil, nil, errors.New("DIGEST-MD5 directive list has a trailing comma")
		}
	}
	return directives, realms, nil
}

func ldapClientDigestMD5TokenByte(value byte) bool {
	if value <= 0x20 || value >= 0x7f {
		return false
	}
	switch value {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=':
		return false
	default:
		return true
	}
}

func ldapClientDigestMD5Quote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func ldapClientDigestMD5ListContains(values, wanted string) bool {
	for _, value := range strings.Split(values, ",") {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func ldapClientStringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
