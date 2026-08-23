package server

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	saslDigestMD5NonceSize          = 32
	maxSASLDigestMD5ChallengeSize   = 2048
	maxSASLDigestMD5ResponseSize    = 4096
	maxSASLDigestMD5BufferSize      = 0xFFFFFF
	saslDigestMD5SecretAttribute    = "cmusaslsecretDIGEST-MD5"
	saslDigestMD5AuthenticationQOP  = "auth"
	saslDigestMD5IntegrityQOP       = "auth-int"
	saslDigestMD5ConfidentialityQOP = "auth-conf"
	saslDigestMD5AuthenticationVerb = "AUTHENTICATE"
)

var errSASLDigestMD5CredentialsUnavailable = errors.New(
	"DIGEST-MD5 credentials are unavailable",
)

type serverSASLDigestMD5Session struct {
	nonce          string
	realm          string
	challenge      []byte
	allowAuth      bool
	allowIntegrity bool
	ciphers        map[string]saslDigestMD5Cipher
	maxBufferSize  uint32
	expectedHosts  map[string]struct{}
}

type saslDigestMD5Response struct {
	username         string
	realm            string
	nonce            string
	cnonce           string
	nonceCount       uint32
	qop              string
	digestURI        string
	response         string
	authorization    string
	hasAuthorization bool
	maxBufferSize    uint32
	cipher           string
}

type saslDigestMD5Directive struct {
	name  string
	value string
}

type saslDigestMD5Credentials struct {
	authenticationDN directory.DN
	password         []byte
	secret           []byte
}

func (credentials *saslDigestMD5Credentials) clear() {
	clear(credentials.password)
	clear(credentials.secret)
}

func startSASLDigestMD5Session(
	runtime *runtimeState,
	externalSSF uint32,
	expectedHosts ...string,
) (*serverSASLSession, error) {
	conversation, err := newSASLDigestMD5SessionWithSSF(
		runtime,
		externalSSF,
		rand.Reader,
		expectedHosts...,
	)
	if err != nil {
		return nil, err
	}
	return &serverSASLSession{
		mechanism:        "DIGEST-MD5",
		runtime:          runtime,
		digestMD5Session: conversation,
	}, nil
}

func newSASLDigestMD5Session(
	runtime *runtimeState,
	random io.Reader,
) (*serverSASLDigestMD5Session, error) {
	return newSASLDigestMD5SessionWithSSF(runtime, 0, random)
}

func newSASLDigestMD5SessionWithSSF(
	runtime *runtimeState,
	externalSSF uint32,
	random io.Reader,
	additionalHosts ...string,
) (*serverSASLDigestMD5Session, error) {
	entropy := make([]byte, saslDigestMD5NonceSize)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return nil, err
	}
	nonce := base64.StdEncoding.EncodeToString(entropy)
	realm := runtime.sasl.realm
	if realm == "" {
		realm = runtime.sasl.host
	}
	if realm == "" ||
		!utf8.ValidString(realm) ||
		strings.IndexByte(realm, 0) >= 0 {
		return nil, errors.New("DIGEST-MD5 realm is invalid")
	}
	if runtime.sasl.securityProperties.maxBufferSize >
		maxSASLDigestMD5BufferSize {
		return nil, errors.New("DIGEST-MD5 maxbuf exceeds RFC limit")
	}

	properties := runtime.sasl.securityProperties
	requiredSSF := uint32(0)
	if properties.minSSF > externalSSF {
		requiredSSF = properties.minSSF - externalSSF
	}
	maximumSSF := uint32(0)
	if properties.maxSSF > externalSSF {
		maximumSSF = properties.maxSSF - externalSSF
	}
	allowAuth := requiredSSF == 0
	allowIntegrity := properties.maxBufferSize != 0 &&
		requiredSSF <= 1 && maximumSSF >= 1
	ciphers := availableSASLDigestMD5Ciphers(requiredSSF, maximumSSF)
	if properties.maxBufferSize == 0 {
		ciphers = nil
	}
	if !allowAuth && !allowIntegrity && len(ciphers) == 0 {
		return nil, errors.New(
			"DIGEST-MD5 cannot satisfy the configured SASL SSF",
		)
	}

	qops := make([]string, 0, 3)
	if allowAuth {
		qops = append(qops, saslDigestMD5AuthenticationQOP)
	}
	if allowIntegrity {
		qops = append(qops, saslDigestMD5IntegrityQOP)
	}
	if len(ciphers) != 0 {
		qops = append(qops, saslDigestMD5ConfidentialityQOP)
	}

	var challenge strings.Builder
	challenge.WriteString(`nonce="`)
	challenge.WriteString(quoteSASLDigestMD5Value(nonce))
	challenge.WriteString(`",realm="`)
	challenge.WriteString(quoteSASLDigestMD5Value(realm))
	challenge.WriteString(`",qop="`)
	challenge.WriteString(strings.Join(qops, ","))
	challenge.WriteByte('"')
	if len(ciphers) != 0 {
		challenge.WriteString(`,cipher="`)
		wroteCipher := false
		for _, cipher := range orderedSASLDigestMD5Ciphers() {
			if _, ok := ciphers[cipher.name]; !ok {
				continue
			}
			if wroteCipher {
				challenge.WriteByte(',')
			}
			challenge.WriteString(cipher.name)
			wroteCipher = true
		}
		challenge.WriteByte('"')
	}
	if runtime.sasl.securityProperties.maxBufferSize != 0 {
		challenge.WriteString(",maxbuf=")
		challenge.WriteString(strconv.FormatUint(
			uint64(runtime.sasl.securityProperties.maxBufferSize),
			10,
		))
	}
	challenge.WriteString(",charset=utf-8,algorithm=md5-sess")
	if challenge.Len() >= maxSASLDigestMD5ChallengeSize {
		return nil, errors.New("DIGEST-MD5 challenge exceeds 2047 bytes")
	}
	encoded := []byte(challenge.String())
	expectedHosts := make(map[string]struct{}, len(additionalHosts)+1)
	for _, host := range append([]string{runtime.sasl.host}, additionalHosts...) {
		if normalized, ok := normalizeSASLDigestMD5Host(host); ok {
			expectedHosts[normalized] = struct{}{}
		}
	}
	return &serverSASLDigestMD5Session{
		nonce:          nonce,
		realm:          realm,
		challenge:      encoded,
		allowAuth:      allowAuth,
		allowIntegrity: allowIntegrity,
		ciphers:        ciphers,
		maxBufferSize:  properties.maxBufferSize,
		expectedHosts:  expectedHosts,
	}, nil
}

func quoteSASLDigestMD5Value(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func (server *Server) handleSASLDigestMD5Step(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	session *serverSASLSession,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	response, err := parseSASLDigestMD5Response(
		request.Authentication.SASLCredentials,
		session.digestMD5Session,
	)
	if err != nil {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}

	authenticationID := response.username
	if response.realm != session.digestMD5Session.realm &&
		response.realm != "" {
		authenticationID += "@" + response.realm
	}
	credentials, err := server.lookupSASLDigestMD5Credentials(
		ctx,
		session.runtime,
		authenticationID,
	)
	if err != nil {
		if !errors.Is(err, errSASLDigestMD5CredentialsUnavailable) {
			return server.writeSASLAuxiliaryLookupFailure(
				connection,
				state,
				message.ID,
				session.mechanism,
				err,
			)
		}
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	defer credentials.clear()

	rspauth, sessionKey, valid := verifySASLDigestMD5Response(
		response,
		credentials,
	)
	if !valid {
		clearSASLSession(state)
		return writeSASLInvalidCredentials(connection, message.ID)
	}
	defer clear(sessionKey)

	authorizationDN, err := server.resolveSASLAuthorizationDN(
		ctx,
		session.runtime,
		session.mechanism,
		authenticationID,
		credentials.authenticationDN,
		response.authorization,
	)
	if err != nil {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultInappropriateAuthentication,
				"",
			),
			nil,
		))
	}

	state.boundDN = authorizationDN.String()
	state.authMechanism = session.mechanism
	clearSASLSession(state)
	if err := ldapwire.Write(connection, ldapwire.EncodeSASLBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		[]byte("rspauth="+rspauth),
		true,
		nil,
	)); err != nil {
		return err
	}
	if response.qop == saslDigestMD5IntegrityQOP {
		securityLayer, err := newSASLDigestMD5ServerIntegrityConnection(
			state.connection,
			sessionKey,
			response.maxBufferSize,
			session.digestMD5Session.maxBufferSize,
		)
		if err != nil {
			return err
		}
		state.connection = securityLayer
		state.saslSSF = 1
	} else if response.qop == saslDigestMD5ConfidentialityQOP {
		cipher := session.digestMD5Session.ciphers[response.cipher]
		securityLayer, err := newSASLDigestMD5ServerPrivacyConnection(
			state.connection,
			sessionKey,
			cipher,
			response.maxBufferSize,
			session.digestMD5Session.maxBufferSize,
		)
		if err != nil {
			return err
		}
		state.connection = securityLayer
		state.saslSSF = cipher.ssf
	}
	return nil
}

func (server *Server) lookupSASLDigestMD5Credentials(
	ctx context.Context,
	runtime *runtimeState,
	authenticationID string,
) (saslDigestMD5Credentials, error) {
	authenticationDN, err := server.saslAuthenticationDN(
		ctx,
		runtime,
		"DIGEST-MD5",
		authenticationID,
	)
	if err != nil {
		return saslDigestMD5Credentials{},
			errSASLDigestMD5CredentialsUnavailable
	}
	database := databaseForDN(runtime, authenticationDN)
	if database == nil {
		return saslDigestMD5Credentials{},
			errSASLDigestMD5CredentialsUnavailable
	}
	if rootPassword, ok := databaseAuthenticationRoot(
		runtime,
		*database,
		authenticationDN,
	); ok {
		password, ok := auth.ExtractCleartextPassword(
			rootPassword,
		)
		if !ok {
			return saslDigestMD5Credentials{},
				errSASLDigestMD5CredentialsUnavailable
		}
		return saslDigestMD5Credentials{
			authenticationDN: authenticationDN,
			password:         password,
		}, nil
	}

	credentials := saslDigestMD5Credentials{
		authenticationDN: authenticationDN,
	}
	entry, err := server.lookupSASLCredentialEntry(
		ctx,
		runtime,
		authenticationDN,
		[]string{"userPassword", saslDigestMD5SecretAttribute},
	)
	if err != nil {
		if errors.Is(err, errSASLCredentialEntryUnavailable) {
			err = errSASLDigestMD5CredentialsUnavailable
		}
		return saslDigestMD5Credentials{}, err
	}
	defer clearSASLCredentialEntry(&entry)

	for _, stored := range entry.Values("userPassword") {
		password, ok := auth.ExtractCleartextPassword(stored)
		if !ok {
			continue
		}
		credentials.password = password
		return credentials, nil
	}
	for _, stored := range entry.Values(saslDigestMD5SecretAttribute) {
		if len(stored) != md5.Size {
			continue
		}
		credentials.secret = bytes.Clone(stored)
		return credentials, nil
	}
	return saslDigestMD5Credentials{},
		errSASLDigestMD5CredentialsUnavailable
}

func parseSASLDigestMD5Response(
	input []byte,
	session *serverSASLDigestMD5Session,
) (saslDigestMD5Response, error) {
	if session == nil ||
		len(input) == 0 ||
		len(input) > maxSASLDigestMD5ResponseSize {
		return saslDigestMD5Response{}, errors.New(
			"invalid DIGEST-MD5 response size",
		)
	}
	directives, err := parseSASLDigestMD5Directives(input)
	if err != nil {
		return saslDigestMD5Response{}, err
	}
	required := []string{
		"username",
		"nonce",
		"cnonce",
		"nc",
		"digest-uri",
		"response",
	}
	for _, name := range required {
		if _, ok := directives[name]; !ok {
			return saslDigestMD5Response{}, fmt.Errorf(
				"DIGEST-MD5 response is missing %s",
				name,
			)
		}
	}

	qop, hasQOP := directives["qop"]
	if !hasQOP {
		qop = saslDigestMD5AuthenticationQOP
	}
	response := saslDigestMD5Response{
		username:  directives["username"],
		realm:     directives["realm"],
		nonce:     directives["nonce"],
		cnonce:    directives["cnonce"],
		qop:       qop,
		digestURI: directives["digest-uri"],
		response:  directives["response"],
	}
	response.authorization, response.hasAuthorization =
		directives["authzid"]
	if response.username == "" ||
		!utf8.ValidString(response.username) ||
		!utf8.ValidString(response.realm) ||
		!utf8.ValidString(response.authorization) {
		return saslDigestMD5Response{}, errors.New(
			"DIGEST-MD5 identities are not valid UTF-8",
		)
	}
	if response.nonce != session.nonce {
		return saslDigestMD5Response{}, errors.New(
			"DIGEST-MD5 nonce does not match",
		)
	}
	switch {
	case strings.EqualFold(response.qop, saslDigestMD5AuthenticationQOP):
		response.qop = saslDigestMD5AuthenticationQOP
		if !session.allowAuth {
			return saslDigestMD5Response{}, errors.New(
				"DIGEST-MD5 auth qop was not offered",
			)
		}
	case strings.EqualFold(response.qop, saslDigestMD5IntegrityQOP):
		response.qop = saslDigestMD5IntegrityQOP
		if !session.allowIntegrity {
			return saslDigestMD5Response{}, errors.New(
				"DIGEST-MD5 auth-int qop was not offered",
			)
		}
	case strings.EqualFold(response.qop, saslDigestMD5ConfidentialityQOP):
		response.qop = saslDigestMD5ConfidentialityQOP
		cipherName, present := directives["cipher"]
		if !present || cipherName == "" {
			return saslDigestMD5Response{}, errors.New(
				"DIGEST-MD5 auth-conf response has no cipher",
			)
		}
		response.cipher = strings.ToLower(cipherName)
		if _, ok := session.ciphers[response.cipher]; !ok {
			return saslDigestMD5Response{}, errors.New(
				"DIGEST-MD5 auth-conf cipher was not offered",
			)
		}
	default:
		return saslDigestMD5Response{}, errors.New(
			"DIGEST-MD5 qop is not supported",
		)
	}
	if response.qop != saslDigestMD5ConfidentialityQOP {
		if _, present := directives["cipher"]; present {
			return saslDigestMD5Response{}, errors.New(
				"DIGEST-MD5 cipher is only valid with auth-conf",
			)
		}
	}
	if err := validateSASLDigestMD5URI(response.digestURI, session.expectedHosts); err != nil {
		return saslDigestMD5Response{}, err
	}
	if len(response.response) != hex.EncodedLen(md5.Size) ||
		!isLowerHex(response.response) {
		return saslDigestMD5Response{}, errors.New(
			"DIGEST-MD5 response digest is malformed",
		)
	}

	nonceCount, err := strconv.ParseUint(directives["nc"], 16, 32)
	if err != nil || nonceCount != 1 {
		return saslDigestMD5Response{}, errors.New(
			"DIGEST-MD5 nonce count is invalid",
		)
	}
	response.nonceCount = uint32(nonceCount)
	if charset, ok := directives["charset"]; ok &&
		!strings.EqualFold(charset, "utf-8") {
		return saslDigestMD5Response{}, errors.New(
			"DIGEST-MD5 charset is not UTF-8",
		)
	}
	response.maxBufferSize = saslDigestMD5DefaultMaxBuffer
	if maxBuffer, ok := directives["maxbuf"]; ok {
		size, err := strconv.ParseUint(maxBuffer, 10, 32)
		if err != nil ||
			size <= 16 ||
			size > maxSASLDigestMD5BufferSize {
			return saslDigestMD5Response{}, errors.New(
				"DIGEST-MD5 maxbuf is invalid",
			)
		}
		response.maxBufferSize = uint32(size)
	}
	return response, nil
}

func validateSASLDigestMD5URI(
	digestURI string,
	expectedHosts map[string]struct{},
) error {
	parts := strings.Split(digestURI, "/")
	if len(parts) < 2 || len(parts) > 3 ||
		!strings.EqualFold(parts[0], "ldap") {
		return errors.New("DIGEST-MD5 digest-uri is not an LDAP service")
	}
	if len(parts) == 3 && parts[2] != "" && !strings.EqualFold(parts[2], "ldap") {
		return errors.New("DIGEST-MD5 digest-uri service name is not accepted")
	}
	host, ok := normalizeSASLDigestMD5Host(parts[1])
	if !ok {
		return errors.New("DIGEST-MD5 digest-uri host is invalid")
	}
	if _, ok := expectedHosts[host]; !ok {
		return fmt.Errorf("DIGEST-MD5 digest-uri host %q does not match this LDAP service", parts[1])
	}
	return nil
}

func normalizeSASLDigestMD5Host(host string) (string, bool) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, "/\x00\r\n\t ") {
		return "", false
	}
	return strings.ToLower(host), true
}

func saslDigestMD5ConnectionHosts(
	connection net.Conn,
	listenerURLs []string,
) []string {
	hosts := make([]string, 0, len(listenerURLs)+1)
	if connection != nil && connection.LocalAddr() != nil {
		if host, _, err := net.SplitHostPort(connection.LocalAddr().String()); err == nil {
			hosts = append(hosts, host)
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				hosts = append(hosts, "localhost")
			}
		}
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		hosts = append(hosts, hostname)
	}
	for _, raw := range listenerURLs {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Hostname() != "" {
			hosts = append(hosts, parsed.Hostname())
		}
	}
	return hosts
}

func parseSASLDigestMD5Directives(
	input []byte,
) (map[string]string, error) {
	parsed, err := parseSASLDigestMD5DirectiveList(input)
	if err != nil {
		return nil, err
	}
	directives := make(map[string]string, len(parsed))
	for _, directive := range parsed {
		if _, exists := directives[directive.name]; exists {
			return nil, fmt.Errorf(
				"DIGEST-MD5 directive %q is duplicated",
				directive.name,
			)
		}
		directives[directive.name] = directive.value
	}
	return directives, nil
}

func parseSASLDigestMD5DirectiveList(
	input []byte,
) ([]saslDigestMD5Directive, error) {
	if bytes.IndexByte(input, 0) >= 0 {
		return nil, errors.New("DIGEST-MD5 response contains NUL")
	}
	text := string(input)
	var directives []saslDigestMD5Directive
	index := 0
	skipLWS := func() {
		for index < len(text) && isSASLDigestMD5LWS(text[index]) {
			index++
		}
	}
	skipLWS()
	for index < len(text) {
		nameStart := index
		for index < len(text) &&
			isSASLDigestMD5TokenByte(text[index]) {
			index++
		}
		if nameStart == index {
			return nil, errors.New("DIGEST-MD5 directive name is invalid")
		}
		name := strings.ToLower(text[nameStart:index])
		skipLWS()
		if index >= len(text) || text[index] != '=' {
			return nil, errors.New("DIGEST-MD5 directive has no value")
		}
		index++
		skipLWS()

		var value string
		if index < len(text) && text[index] == '"' {
			index++
			var builder strings.Builder
			closed := false
			for index < len(text) {
				switch text[index] {
				case '\\':
					index++
					if index >= len(text) {
						return nil, errors.New(
							"DIGEST-MD5 quoted-pair is incomplete",
						)
					}
					builder.WriteByte(text[index])
					index++
				case '"':
					index++
					closed = true
				default:
					builder.WriteByte(text[index])
					index++
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, errors.New(
					"DIGEST-MD5 quoted value is incomplete",
				)
			}
			value = builder.String()
		} else {
			valueStart := index
			for index < len(text) &&
				isSASLDigestMD5TokenByte(text[index]) {
				index++
			}
			if valueStart == index {
				return nil, errors.New(
					"DIGEST-MD5 token value is invalid",
				)
			}
			value = text[valueStart:index]
		}
		skipLWS()
		directives = append(directives, saslDigestMD5Directive{
			name:  name,
			value: value,
		})
		if index == len(text) {
			break
		}
		if text[index] != ',' {
			return nil, errors.New(
				"DIGEST-MD5 directives are not comma separated",
			)
		}
		index++
		skipLWS()
		if index == len(text) {
			return nil, errors.New(
				"DIGEST-MD5 response has a trailing comma",
			)
		}
	}
	if len(directives) == 0 {
		return nil, errors.New("DIGEST-MD5 response is empty")
	}
	return directives, nil
}

func isSASLDigestMD5LWS(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func isSASLDigestMD5TokenByte(value byte) bool {
	if value < 0x21 || value > 0x7e {
		return false
	}
	switch value {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/',
		'[', ']', '?', '=', '{', '}':
		return false
	default:
		return true
	}
}

func isLowerHex(value string) bool {
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func verifySASLDigestMD5Response(
	response saslDigestMD5Response,
	credentials saslDigestMD5Credentials,
) (string, []byte, bool) {
	var secrets [][]byte
	if credentials.secret != nil {
		secrets = append(secrets, credentials.secret)
	} else {
		converted := calculateSASLDigestMD5Secret(
			response.username,
			response.realm,
			credentials.password,
			true,
		)
		raw := calculateSASLDigestMD5Secret(
			response.username,
			response.realm,
			credentials.password,
			false,
		)
		secrets = append(secrets, converted)
		if !bytes.Equal(converted, raw) {
			secrets = append(secrets, raw)
		} else {
			clear(raw)
		}
		defer func() {
			for _, secret := range secrets {
				clear(secret)
			}
		}()
	}

	for _, secret := range secrets {
		expected, rspauth := calculateSASLDigestMD5Exchange(
			secret,
			response,
		)
		if subtle.ConstantTimeCompare(
			[]byte(expected),
			[]byte(response.response),
		) == 1 {
			return rspauth, calculateSASLDigestMD5SessionKey(
				secret,
				response,
			), true
		}
	}
	return "", nil, false
}

func calculateSASLDigestMD5Secret(
	username string,
	realm string,
	password []byte,
	convertLatin1 bool,
) []byte {
	digest := md5.New()
	writeSASLDigestMD5SecretValue(
		digest,
		[]byte(username),
		convertLatin1,
	)
	_, _ = digest.Write([]byte{':'})
	writeSASLDigestMD5SecretValue(
		digest,
		[]byte(realm),
		convertLatin1,
	)
	_, _ = digest.Write([]byte{':'})
	writeSASLDigestMD5SecretValue(digest, password, convertLatin1)
	return digest.Sum(nil)
}

func writeSASLDigestMD5SecretValue(
	digest hash.Hash,
	value []byte,
	convertLatin1 bool,
) {
	if convertLatin1 {
		if converted, ok := saslDigestMD5Latin1(value); ok {
			_, _ = digest.Write(converted)
			clear(converted)
			return
		}
	}
	_, _ = digest.Write(value)
}

func saslDigestMD5Latin1(value []byte) ([]byte, bool) {
	if !utf8.Valid(value) {
		return nil, false
	}
	converted := make([]byte, 0, len(value))
	for _, character := range string(value) {
		if character > 0xff {
			clear(converted)
			return nil, false
		}
		converted = append(converted, byte(character))
	}
	return converted, true
}

func calculateSASLDigestMD5Exchange(
	secret []byte,
	response saslDigestMD5Response,
) (string, string) {
	binarySessionKey := calculateSASLDigestMD5SessionKey(secret, response)
	defer clear(binarySessionKey)
	sessionKey := hex.EncodeToString(binarySessionKey)
	client := calculateSASLDigestMD5Digest(
		sessionKey,
		response,
		saslDigestMD5AuthenticationVerb,
	)
	server := calculateSASLDigestMD5Digest(
		sessionKey,
		response,
		"",
	)
	return client, server
}

func calculateSASLDigestMD5SessionKey(
	secret []byte,
	response saslDigestMD5Response,
) []byte {
	a1 := md5.New()
	_, _ = a1.Write(secret)
	_, _ = a1.Write([]byte(":" + response.nonce + ":" + response.cnonce))
	if response.hasAuthorization {
		_, _ = a1.Write([]byte(":" + response.authorization))
	}
	return a1.Sum(nil)
}

func calculateSASLDigestMD5Digest(
	sessionKey string,
	response saslDigestMD5Response,
	method string,
) string {
	a2Value := method + ":" + response.digestURI
	if response.qop == saslDigestMD5IntegrityQOP ||
		response.qop == saslDigestMD5ConfidentialityQOP {
		a2Value += ":00000000000000000000000000000000"
	}
	a2 := md5.Sum([]byte(a2Value))
	a2Hex := hex.EncodeToString(a2[:])
	nonceCount := fmt.Sprintf("%08x", response.nonceCount)
	value := strings.Join([]string{
		sessionKey,
		response.nonce,
		nonceCount,
		response.cnonce,
		response.qop,
		a2Hex,
	}, ":")
	digest := md5.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}
