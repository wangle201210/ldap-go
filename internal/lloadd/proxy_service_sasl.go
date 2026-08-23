package lloadd

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // CRAM-MD5 and DIGEST-MD5 require MD5.
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/xdg-go/scram"
	"github.com/xdg-go/stringprep"
)

const (
	serviceSASLMaxChallengeSize = 64 << 10
	serviceCRAMMaxChallengeSize = 1024
	serviceSCRAMMinIterations   = 4096
	serviceSCRAMMaxIterations   = 10_000_000
	serviceSCRAMMaxSaltSize     = 1024
	serviceDigestMaxBufferSize  = 0xFFFFFF
	serviceGSSAPIDefaultBuffer  = 64 << 10
)

func normalizeRuntimeServiceBind(config RuntimeBindConfig) (RuntimeBindConfig, error) {
	config.Method = strings.ToLower(strings.TrimSpace(config.Method))
	if config.Method == "none" {
		config.Method = ""
	}
	switch config.Method {
	case "":
		if config.DN != "" || len(config.Credentials) != 0 ||
			config.SASLMechanism != "" || config.AuthenticationID != "" ||
			config.AuthorizationID != "" || config.Realm != "" ||
			config.SecurityProperties != "" {
			return RuntimeBindConfig{}, errors.New("upstream bind options require a bind method")
		}
		return config, nil
	case "simple":
		if config.DN == "" || len(config.Credentials) == 0 {
			return RuntimeBindConfig{}, errors.New("upstream simple bind DN and credentials are required")
		}
		if config.SASLMechanism != "" || config.AuthenticationID != "" ||
			config.AuthorizationID != "" || config.Realm != "" ||
			config.SecurityProperties != "" {
			return RuntimeBindConfig{}, errors.New("upstream simple bind cannot use SASL options")
		}
		return config, nil
	case "sasl":
		if config.DN != "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL bind cannot use a bind DN")
		}
	default:
		return RuntimeBindConfig{}, fmt.Errorf("unsupported upstream bind method %q", config.Method)
	}

	config.SASLMechanism = strings.ToUpper(strings.TrimSpace(config.SASLMechanism))
	if config.SASLMechanism == "" {
		return RuntimeBindConfig{}, errors.New("upstream SASL mechanism is required")
	}
	for name, value := range map[string]string{
		"authentication ID": config.AuthenticationID,
		"authorization ID":  config.AuthorizationID,
		"realm":             config.Realm,
	} {
		if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return RuntimeBindConfig{}, fmt.Errorf("upstream SASL %s must be valid UTF-8 without NUL", name)
		}
	}
	securityProperties := strings.ToLower(strings.TrimSpace(config.SecurityProperties))
	config.SecurityProperties = securityProperties

	switch config.SASLMechanism {
	case "PLAIN":
		if len(config.Credentials) == 0 {
			return RuntimeBindConfig{}, errors.New("upstream SASL credentials are required")
		}
		if securityProperties != "" && securityProperties != "none" {
			return RuntimeBindConfig{}, errors.New("upstream SASL auth-only mode supports only empty secprops or secprops=none")
		}
		if config.AuthenticationID == "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL PLAIN requires authcid")
		}
		if config.Realm != "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL PLAIN does not support realm")
		}
		if bytes.IndexByte(config.Credentials, 0) >= 0 {
			return RuntimeBindConfig{}, errors.New("upstream SASL PLAIN credentials contain NUL")
		}
	case "CRAM-MD5":
		if len(config.Credentials) == 0 {
			return RuntimeBindConfig{}, errors.New("upstream SASL credentials are required")
		}
		if securityProperties != "" && securityProperties != "none" {
			return RuntimeBindConfig{}, errors.New("upstream SASL auth-only mode supports only empty secprops or secprops=none")
		}
		if config.AuthenticationID == "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL CRAM-MD5 requires authcid")
		}
		if strings.ContainsAny(config.AuthenticationID, " \t\r\n") {
			return RuntimeBindConfig{}, errors.New("upstream SASL CRAM-MD5 authcid contains whitespace")
		}
		if config.AuthorizationID != "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL CRAM-MD5 does not support authzid")
		}
		if config.Realm != "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL CRAM-MD5 does not support realm")
		}
	case "DIGEST-MD5":
		if len(config.Credentials) == 0 {
			return RuntimeBindConfig{}, errors.New("upstream SASL credentials are required")
		}
		if securityProperties != "" && securityProperties != "none" {
			return RuntimeBindConfig{}, errors.New("upstream SASL auth-only mode supports only empty secprops or secprops=none")
		}
		if config.AuthenticationID == "" {
			return RuntimeBindConfig{}, errors.New("upstream SASL DIGEST-MD5 requires authcid")
		}
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512":
		if len(config.Credentials) == 0 {
			return RuntimeBindConfig{}, errors.New("upstream SASL credentials are required")
		}
		if securityProperties != "" && securityProperties != "none" {
			return RuntimeBindConfig{}, errors.New("upstream SASL auth-only mode supports only empty secprops or secprops=none")
		}
		if config.AuthenticationID == "" {
			return RuntimeBindConfig{}, fmt.Errorf("upstream SASL %s requires authcid", config.SASLMechanism)
		}
		if config.Realm != "" {
			return RuntimeBindConfig{}, fmt.Errorf("upstream SASL %s does not support realm", config.SASLMechanism)
		}
	case "GSSAPI":
		if err := validateServiceGSSAPIStaticConfig(
			config.AuthenticationID,
			config.Realm,
			config.SecurityProperties,
			config.Credentials,
		); err != nil {
			return RuntimeBindConfig{}, err
		}
		settings, err := resolveServiceGSSAPISettings(config, os.LookupEnv)
		if err != nil {
			return RuntimeBindConfig{}, err
		}
		settings.clear()
	default:
		if strings.HasPrefix(config.SASLMechanism, "SCRAM-") &&
			strings.HasSuffix(config.SASLMechanism, "-PLUS") {
			return RuntimeBindConfig{}, errors.New("upstream SASL SCRAM-PLUS is not supported by the auth-only proxy")
		}
		return RuntimeBindConfig{}, fmt.Errorf("unsupported upstream SASL mechanism %q", config.SASLMechanism)
	}
	return config, nil
}

func (backend *runtimeBackend) bindServiceSASL(
	ctx context.Context,
	connection net.Conn,
	nextMessageID *int64,
) (net.Conn, error) {
	config := backend.proxy.config.Bind
	switch config.SASLMechanism {
	case "PLAIN":
		return connection, backend.bindServiceSASLPlain(connection, nextMessageID)
	case "CRAM-MD5":
		return connection, backend.bindServiceSASLCRAMMD5(connection, nextMessageID)
	case "DIGEST-MD5":
		return connection, backend.bindServiceSASLDigestMD5(connection, nextMessageID)
	case "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512":
		return connection, backend.bindServiceSASLSCRAM(connection, nextMessageID)
	case "GSSAPI":
		return backend.bindServiceSASLGSSAPI(ctx, connection, nextMessageID)
	default:
		return nil, fmt.Errorf("unsupported upstream SASL mechanism %q", config.SASLMechanism)
	}
}

type serviceGSSAPICredentialSource uint8

const (
	serviceGSSAPIPassword serviceGSSAPICredentialSource = iota
	serviceGSSAPIKeytab
	serviceGSSAPICCache
)

type serviceGSSAPISettings struct {
	source         serviceGSSAPICredentialSource
	username       string
	realm          string
	password       []byte
	credentialPath string
	configuration  string
	target         string
	authorization  string
}

func (settings *serviceGSSAPISettings) clear() {
	if settings == nil {
		return
	}
	clear(settings.password)
	settings.password = nil
	settings.username = ""
	settings.realm = ""
	settings.credentialPath = ""
	settings.configuration = ""
	settings.target = ""
	settings.authorization = ""
}

type serviceGSSAPISecurityProperties struct {
	minimumSSF    uint32
	maximumSSF    uint32
	maxBufferSize uint32
}

func validateServiceGSSAPIStaticConfig(
	authenticationID string,
	realm string,
	securityProperties string,
	password []byte,
) error {
	if _, err := parseServiceGSSAPISecurityProperties(securityProperties); err != nil {
		return fmt.Errorf("invalid upstream SASL GSSAPI secprops: %w", err)
	}
	username, normalizedRealm, err := normalizeServiceGSSAPIPrincipal(
		authenticationID,
		realm,
	)
	if err != nil {
		return err
	}
	if len(password) == 0 {
		return nil
	}
	if username == "" || normalizedRealm == "" {
		return errors.New("upstream SASL GSSAPI password credentials require authcid and realm")
	}
	if !utf8.Valid(password) || bytes.IndexByte(password, 0) >= 0 {
		return errors.New("upstream SASL GSSAPI password must be valid UTF-8 without NUL")
	}
	return nil
}

func parseServiceGSSAPISecurityProperties(
	value string,
) (serviceGSSAPISecurityProperties, error) {
	properties := serviceGSSAPISecurityProperties{
		maximumSSF:    math.MaxInt32,
		maxBufferSize: serviceGSSAPIDefaultBuffer,
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return properties, nil
	}
	parts := strings.Split(value, ",")
	for _, raw := range parts {
		part := strings.ToLower(strings.TrimSpace(raw))
		if part == "" {
			return serviceGSSAPISecurityProperties{}, errors.New("empty property")
		}
		switch part {
		case "none":
			if len(parts) != 1 {
				return serviceGSSAPISecurityProperties{}, errors.New("none cannot be combined with other properties")
			}
			continue
		case "noplain", "noactive", "nodict", "noanonymous":
			continue
		case "forwardsec", "passcred":
			return serviceGSSAPISecurityProperties{}, fmt.Errorf(
				"%s is not supported by the GSSAPI provider",
				part,
			)
		}
		name, encoded, ok := strings.Cut(part, "=")
		if !ok || encoded == "" {
			return serviceGSSAPISecurityProperties{}, fmt.Errorf("unsupported property %q", raw)
		}
		parsed, err := strconv.ParseUint(encoded, 10, 31)
		if err != nil {
			return serviceGSSAPISecurityProperties{}, fmt.Errorf("invalid %s value", name)
		}
		switch name {
		case "minssf":
			properties.minimumSSF = uint32(parsed)
		case "maxssf":
			properties.maximumSSF = uint32(parsed)
		case "maxbufsize":
			if parsed > saslkrb5.MaxBufferSize {
				return serviceGSSAPISecurityProperties{}, errors.New("maxbufsize exceeds the RFC 4752 limit")
			}
			properties.maxBufferSize = uint32(parsed)
		default:
			return serviceGSSAPISecurityProperties{}, fmt.Errorf("unsupported property %q", name)
		}
	}
	if properties.minimumSSF > properties.maximumSSF {
		return serviceGSSAPISecurityProperties{}, errors.New("minssf exceeds maxssf")
	}
	return properties, nil
}

func resolveServiceGSSAPISettings(
	config RuntimeBindConfig,
	lookupEnv func(string) (string, bool),
) (serviceGSSAPISettings, error) {
	username, realm, err := normalizeServiceGSSAPIPrincipal(
		config.AuthenticationID,
		config.Realm,
	)
	if err != nil {
		return serviceGSSAPISettings{}, err
	}
	settings := serviceGSSAPISettings{
		username:      username,
		realm:         realm,
		configuration: serviceGSSAPIConfigurationPath(lookupEnv),
		authorization: config.AuthorizationID,
	}
	if len(config.Credentials) != 0 {
		if username == "" || realm == "" {
			return serviceGSSAPISettings{}, errors.New(
				"upstream SASL GSSAPI password credentials require authcid and realm",
			)
		}
		settings.source = serviceGSSAPIPassword
		settings.password = bytes.Clone(config.Credentials)
		return settings, nil
	}

	keytab, variable := serviceGSSAPIFirstEnvironment(
		lookupEnv,
		"KRB5_CLIENT_KTNAME",
		"KRB5_KTNAME",
	)
	if keytab != "" {
		path, parseErr := parseServiceGSSAPIFileProvider(keytab, variable)
		if parseErr != nil {
			return serviceGSSAPISettings{}, parseErr
		}
		if username == "" || realm == "" {
			return serviceGSSAPISettings{}, errors.New(
				"upstream SASL GSSAPI keytab credentials require authcid and realm",
			)
		}
		settings.source = serviceGSSAPIKeytab
		settings.credentialPath = path
		return settings, nil
	}

	cache, configured := lookupEnv("KRB5CCNAME")
	if configured && strings.TrimSpace(cache) != "" {
		path, parseErr := parseServiceGSSAPIFileProvider(cache, "KRB5CCNAME")
		if parseErr != nil {
			return serviceGSSAPISettings{}, parseErr
		}
		settings.credentialPath = path
	} else {
		path, pathErr := defaultServiceGSSAPICCache()
		if pathErr != nil {
			return serviceGSSAPISettings{}, pathErr
		}
		settings.credentialPath = path
	}
	settings.source = serviceGSSAPICCache
	return settings, nil
}

func normalizeServiceGSSAPIPrincipal(
	authenticationID string,
	configuredRealm string,
) (string, string, error) {
	authenticationID = strings.TrimSpace(authenticationID)
	configuredRealm = strings.TrimSpace(configuredRealm)
	if strings.ContainsAny(authenticationID, "\x00\r\n") ||
		strings.ContainsAny(configuredRealm, "\x00\r\n") {
		return "", "", errors.New("upstream SASL GSSAPI principal contains an invalid character")
	}
	at := strings.LastIndexByte(authenticationID, '@')
	if at < 0 {
		return authenticationID, configuredRealm, nil
	}
	if at == 0 || at == len(authenticationID)-1 {
		return "", "", errors.New("upstream SASL GSSAPI authcid is not a valid Kerberos principal")
	}
	principalRealm := authenticationID[at+1:]
	if configuredRealm != "" && !strings.EqualFold(configuredRealm, principalRealm) {
		return "", "", fmt.Errorf(
			"upstream SASL GSSAPI authcid realm %q conflicts with realm %q",
			principalRealm,
			configuredRealm,
		)
	}
	return authenticationID[:at], principalRealm, nil
}

func serviceGSSAPIConfigurationPath(lookupEnv func(string) (string, bool)) string {
	if configured, ok := lookupEnv("KRB5_CONFIG"); ok {
		for _, candidate := range filepath.SplitList(configured) {
			if candidate = strings.TrimSpace(candidate); candidate != "" {
				return candidate
			}
		}
	}
	if runtime.GOOS == "windows" {
		if root, ok := lookupEnv("SystemRoot"); ok && strings.TrimSpace(root) != "" {
			return filepath.Join(root, "krb5.ini")
		}
		return `C:\Windows\krb5.ini`
	}
	if runtime.GOOS == "darwin" {
		const path = "/Library/Preferences/edu.mit.Kerberos"
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "/etc/krb5.conf"
}

func serviceGSSAPIFirstEnvironment(
	lookupEnv func(string) (string, bool),
	names ...string,
) (string, string) {
	for _, name := range names {
		if value, ok := lookupEnv(name); ok && strings.TrimSpace(value) != "" {
			return value, name
		}
	}
	return "", ""
}

func parseServiceGSSAPIFileProvider(value, variable string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is empty", variable)
	}
	if serviceGSSAPIWindowsDrivePath(value) {
		return value, nil
	}
	provider, path, hasProvider := strings.Cut(value, ":")
	if !hasProvider {
		return value, nil
	}
	if !strings.EqualFold(provider, "FILE") {
		return "", fmt.Errorf(
			"%s credential provider %q is unsupported; use FILE",
			variable,
			provider,
		)
	}
	if path == "" {
		return "", fmt.Errorf("%s FILE credential path is empty", variable)
	}
	return path, nil
}

func serviceGSSAPIWindowsDrivePath(value string) bool {
	if len(value) < 3 || value[1] != ':' {
		return false
	}
	drive := value[0]
	return ((drive >= 'a' && drive <= 'z') ||
		(drive >= 'A' && drive <= 'Z')) &&
		(value[2] == '\\' || value[2] == '/')
}

func defaultServiceGSSAPICCache() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve default Kerberos credential cache: %w", err)
	}
	uid := strings.TrimSpace(current.Uid)
	if _, err := strconv.ParseUint(uid, 10, 64); err != nil {
		return "", errors.New(
			"KRB5CCNAME is required when the operating system has no numeric UID",
		)
	}
	return filepath.Join(os.TempDir(), "krb5cc_"+uid), nil
}

type serviceGSSAPIInitiator interface {
	InitialToken(string, []byte) ([]byte, error)
	AcceptAPRep([]byte) error
	ContextKey() (types.EncryptionKey, error)
	SecurityState() (saslkrb5.SecurityState, error)
	Close() error
}

type serviceGSSAPIInitiatorFactory func(
	serviceGSSAPISettings,
) (serviceGSSAPIInitiator, error)

func newServiceGSSAPIInitiator(
	settings serviceGSSAPISettings,
) (serviceGSSAPIInitiator, error) {
	switch settings.source {
	case serviceGSSAPIPassword:
		return saslkrb5.NewInitiatorWithPassword(
			settings.username,
			settings.realm,
			string(settings.password),
			settings.configuration,
		)
	case serviceGSSAPIKeytab:
		return saslkrb5.NewInitiatorWithKeytab(
			settings.username,
			settings.realm,
			settings.credentialPath,
			settings.configuration,
		)
	case serviceGSSAPICCache:
		cache, err := credentials.LoadCCache(settings.credentialPath)
		if err != nil {
			return nil, fmt.Errorf("load FILE credential cache: %w", err)
		}
		cacheUsername := cache.GetClientPrincipalName().PrincipalNameString()
		cacheRealm := cache.GetClientRealm()
		if settings.username != "" && settings.username != cacheUsername {
			return nil, fmt.Errorf(
				"upstream SASL GSSAPI authcid %q does not match FILE credential cache principal %q",
				settings.username,
				cacheUsername,
			)
		}
		if settings.realm != "" && !strings.EqualFold(settings.realm, cacheRealm) {
			return nil, fmt.Errorf(
				"upstream SASL GSSAPI realm %q does not match FILE credential cache realm %q",
				settings.realm,
				cacheRealm,
			)
		}
		return saslkrb5.NewInitiatorFromCCache(
			settings.credentialPath,
			settings.configuration,
		)
	default:
		return nil, errors.New("unknown upstream GSSAPI credential source")
	}
}

type serviceGSSAPIBindResult struct {
	connection net.Conn
	err        error
}

const serviceGSSAPIMaxConcurrentInitializations = 16

var serviceGSSAPIInitializationSlots = make(
	chan struct{},
	serviceGSSAPIMaxConcurrentInitializations,
)

func (backend *runtimeBackend) bindServiceSASLGSSAPI(
	ctx context.Context,
	connection net.Conn,
	nextMessageID *int64,
) (net.Conn, error) {
	return backend.bindServiceSASLGSSAPIWithFactory(
		ctx,
		connection,
		nextMessageID,
		newServiceGSSAPIInitiator,
	)
}

func (backend *runtimeBackend) bindServiceSASLGSSAPIWithFactory(
	ctx context.Context,
	connection net.Conn,
	nextMessageID *int64,
	factory serviceGSSAPIInitiatorFactory,
) (net.Conn, error) {
	if factory == nil {
		return connection, errors.New("upstream SASL GSSAPI credential factory is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout := backend.proxy.config.Bind.Timeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return connection, fmt.Errorf("upstream SASL GSSAPI bind: %w", err)
	}
	select {
	case serviceGSSAPIInitializationSlots <- struct{}{}:
	case <-ctx.Done():
		_ = connection.Close()
		return connection, fmt.Errorf("upstream SASL GSSAPI bind: %w", ctx.Err())
	}
	settings, err := resolveServiceGSSAPISettings(
		backend.proxy.config.Bind,
		os.LookupEnv,
	)
	if err != nil {
		<-serviceGSSAPIInitializationSlots
		return connection, err
	}
	target, err := backend.serviceGSSAPITarget()
	if err != nil {
		settings.clear()
		<-serviceGSSAPIInitializationSlots
		return connection, err
	}
	settings.target = target

	// gokrb5's service-ticket API has no context-aware variant. Cancellation can
	// close LDAP I/O immediately, but this single worker can only exit after an
	// in-flight Kerberos call returns. The cancellation handoff avoids adding a
	// second goroutine that waits indefinitely just to reap the worker.
	done := make(chan serviceGSSAPIBindResult)
	abandoned := make(chan struct{})
	workerMessageID := *nextMessageID
	go func() {
		defer func() { <-serviceGSSAPIInitializationSlots }()
		secured, bindErr := backend.bindServiceSASLGSSAPIBlocking(
			connection,
			&workerMessageID,
			settings,
			factory,
		)
		result := serviceGSSAPIBindResult{connection: secured, err: bindErr}
		select {
		case done <- result:
		case <-abandoned:
			if result.connection != nil {
				_ = result.connection.Close()
			}
		}
	}()
	select {
	case result := <-done:
		if result.connection == nil {
			result.connection = connection
		}
		if err := ctx.Err(); err != nil {
			_ = result.connection.Close()
			return connection, fmt.Errorf("upstream SASL GSSAPI bind: %w", err)
		}
		*nextMessageID = workerMessageID
		return result.connection, result.err
	case <-ctx.Done():
		close(abandoned)
		_ = connection.Close()
		return connection, fmt.Errorf("upstream SASL GSSAPI bind: %w", ctx.Err())
	}
}

func (backend *runtimeBackend) serviceGSSAPITarget() (string, error) {
	if runtimeLDAPURLScheme(backend.config.URI) == "ldapi" {
		return "", errors.New("upstream SASL GSSAPI requires a hostname and is not supported for ldapi")
	}
	parsed, err := url.Parse(backend.config.URI)
	if err != nil {
		return "", fmt.Errorf("parse upstream GSSAPI provider URI: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" || strings.IndexByte(host, 0) >= 0 {
		return "", errors.New("upstream SASL GSSAPI provider has no valid hostname")
	}
	return "ldap/" + host, nil
}

func (backend *runtimeBackend) bindServiceSASLGSSAPIBlocking(
	connection net.Conn,
	nextMessageID *int64,
	settings serviceGSSAPISettings,
	factory serviceGSSAPIInitiatorFactory,
) (net.Conn, error) {
	defer settings.clear()
	initiator, err := factory(settings)
	if err != nil {
		return connection, fmt.Errorf("initialize upstream SASL GSSAPI credentials: %w", err)
	}
	return backend.bindServiceSASLGSSAPIWithInitiator(
		connection,
		nextMessageID,
		settings.target,
		settings.authorization,
		initiator,
	)
}

func (backend *runtimeBackend) bindServiceSASLGSSAPIWithInitiator(
	connection net.Conn,
	nextMessageID *int64,
	target string,
	authorizationID string,
	initiator serviceGSSAPIInitiator,
) (net.Conn, error) {
	if initiator == nil {
		return connection, errors.New("upstream SASL GSSAPI initiator is nil")
	}
	defer initiator.Close()
	initial, err := initiator.InitialToken(target, nil)
	if err != nil {
		return connection, fmt.Errorf("create upstream SASL GSSAPI AP-REQ: %w", err)
	}
	first, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"GSSAPI",
		initial,
		true,
	)
	clear(initial)
	if err != nil {
		return connection, err
	}
	if first.code != ldapwire.ResultSASLBindInProgress {
		first.clear()
		return connection, serviceSASLResultError("GSSAPI AP-REQ", first.code)
	}
	if !first.hasServerCredentials || len(first.serverCredentials) == 0 {
		first.clear()
		return connection, errors.New("service SASL GSSAPI acceptor omitted AP-REP")
	}
	err = initiator.AcceptAPRep(first.serverCredentials)
	first.clear()
	if err != nil {
		return connection, fmt.Errorf("verify service SASL GSSAPI AP-REP: %w", err)
	}

	second, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"GSSAPI",
		nil,
		false,
	)
	if err != nil {
		return connection, err
	}
	if second.code != ldapwire.ResultSASLBindInProgress {
		second.clear()
		return connection, serviceSASLResultError("GSSAPI security negotiation", second.code)
	}
	if !second.hasServerCredentials || len(second.serverCredentials) == 0 {
		second.clear()
		return connection, errors.New("service SASL GSSAPI acceptor omitted its security-layer offer")
	}

	key, err := initiator.ContextKey()
	if err != nil {
		second.clear()
		return connection, err
	}
	defer clear(key.KeyValue)
	securityState, err := initiator.SecurityState()
	if err != nil {
		second.clear()
		return connection, err
	}
	offer, err := saslkrb5.Unwrap(
		second.serverCredentials,
		key,
		true,
		securityState.AcceptorSubkey,
		securityState.ReceiveSequence,
	)
	second.clear()
	if err != nil {
		return connection, fmt.Errorf("verify service SASL GSSAPI security-layer offer: %w", err)
	}
	securityState.ReceiveSequence++
	layers, peerMaximum, err := saslkrb5.DecodeOffer(offer)
	clear(offer)
	if err != nil {
		return connection, err
	}
	properties, err := parseServiceGSSAPISecurityProperties(
		backend.proxy.config.Bind.SecurityProperties,
	)
	if err != nil {
		return connection, err
	}
	selection, localMaximum, err := selectServiceGSSAPISecurityLayer(
		layers,
		key,
		properties,
	)
	if err != nil {
		return connection, err
	}
	payload, err := saslkrb5.EncodeNegotiation(
		selection,
		localMaximum,
		authorizationID,
	)
	if err != nil {
		return connection, err
	}
	wrapped, err := saslkrb5.Wrap(
		payload,
		key,
		false,
		securityState.AcceptorSubkey,
		securityState.SendSequence,
	)
	clear(payload)
	if err != nil {
		return connection, fmt.Errorf("encode service SASL GSSAPI security-layer selection: %w", err)
	}
	securityState.SendSequence++
	final, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"GSSAPI",
		wrapped,
		true,
	)
	clear(wrapped)
	if err != nil {
		return connection, err
	}
	defer final.clear()
	if final.code != ldapwire.ResultSuccess {
		return connection, serviceSASLResultError("GSSAPI completion", final.code)
	}
	if final.hasServerCredentials {
		return connection, errors.New("service SASL GSSAPI acceptor returned unexpected completion data")
	}
	if selection == saslkrb5.SecurityNone {
		return connection, nil
	}
	if selection == saslkrb5.SecurityConfidentiality {
		secured, layerErr := saslkrb5.NewConfidentialityConnection(
			connection,
			key,
			false,
			securityState,
			peerMaximum,
			localMaximum,
		)
		if layerErr != nil {
			return connection, fmt.Errorf("install service SASL GSSAPI confidentiality layer: %w", layerErr)
		}
		return secured, nil
	}
	secured, err := saslkrb5.NewIntegrityConnection(
		connection,
		key,
		false,
		securityState,
		peerMaximum,
		localMaximum,
	)
	if err != nil {
		return connection, fmt.Errorf("install service SASL GSSAPI integrity layer: %w", err)
	}
	return secured, nil
}

func selectServiceGSSAPISecurityLayer(
	layers byte,
	key types.EncryptionKey,
	properties serviceGSSAPISecurityProperties,
) (byte, uint32, error) {
	keySSF, err := saslkrb5.SecurityStrength(key)
	if err != nil {
		return 0, 0, fmt.Errorf("determine service SASL GSSAPI context strength: %w", err)
	}
	if layers&saslkrb5.SecurityConfidentiality != 0 &&
		properties.maxBufferSize != 0 &&
		properties.minimumSSF <= keySSF && properties.maximumSSF >= keySSF {
		return saslkrb5.SecurityConfidentiality, properties.maxBufferSize, nil
	}
	if layers&saslkrb5.SecurityIntegrity != 0 &&
		properties.maxBufferSize != 0 &&
		properties.minimumSSF <= 1 && properties.maximumSSF >= 1 {
		return saslkrb5.SecurityIntegrity, properties.maxBufferSize, nil
	}
	if layers&saslkrb5.SecurityNone != 0 && properties.minimumSSF == 0 {
		return saslkrb5.SecurityNone, 0, nil
	}
	return 0, 0, errors.New(
		"service SASL GSSAPI acceptor offers no security layer allowed by secprops",
	)
}

type serviceSASLResult struct {
	code                 ldapwire.ResultCode
	serverCredentials    []byte
	hasServerCredentials bool
}

func (result *serviceSASLResult) clear() {
	clear(result.serverCredentials)
	result.serverCredentials = nil
	result.hasServerCredentials = false
}

func (backend *runtimeBackend) exchangeServiceSASLBind(
	connection net.Conn,
	nextMessageID *int64,
	mechanism string,
	credentials []byte,
	hasCredentials bool,
) (serviceSASLResult, error) {
	messageID := *nextMessageID
	*nextMessageID = messageID + 1
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
		return serviceSASLResult{}, fmt.Errorf("encode service SASL %s Bind: %w", mechanism, err)
	}
	defer clear(request)
	if err := writeConnection(connection, request, backend.proxy.config.IOTimeout); err != nil {
		return serviceSASLResult{}, fmt.Errorf("write service SASL %s Bind: %w", mechanism, err)
	}
	response, err := backend.proxy.codec.Read(
		connection,
		backend.proxy.config.UpstreamMaxMessageSize,
	)
	if err != nil {
		return serviceSASLResult{}, fmt.Errorf("read service SASL %s Bind: %w", mechanism, err)
	}
	if response.MessageID != messageID {
		return serviceSASLResult{}, fmt.Errorf(
			"service SASL %s Bind response message ID %d does not match request %d",
			mechanism,
			response.MessageID,
			messageID,
		)
	}
	if response.ProtocolTag != ldapwire.ApplicationBindResponse || !response.HasResultCode {
		return serviceSASLResult{}, fmt.Errorf("service SASL %s response is not a BindResponse", mechanism)
	}
	serverCredentials, present, err := serviceSASLServerCredentials(response)
	if err != nil {
		return serviceSASLResult{}, fmt.Errorf("service SASL %s response: %w", mechanism, err)
	}
	return serviceSASLResult{
		code:                 response.ResultCode,
		serverCredentials:    serverCredentials,
		hasServerCredentials: present,
	}, nil
}

func serviceSASLServerCredentials(frame proxyFrame) ([]byte, bool, error) {
	parsed, err := parseProxyFrame(frame)
	if err != nil {
		return nil, false, err
	}
	operation, next, err := parseElement(parsed.ProtocolOp, 0)
	if err != nil || next != len(parsed.ProtocolOp) ||
		!elementIs(operation, berClassApplication, true, TagBindResponse) {
		return nil, false, errors.New("malformed BindResponse")
	}
	cursor := operation.contentStart
	for index, tag := range []uint64{berTagEnumerated, berTagOctetString, berTagOctetString} {
		field, fieldEnd, fieldErr := parseElement(parsed.ProtocolOp, cursor)
		if fieldErr != nil || !elementIs(field, berClassUniversal, false, tag) {
			return nil, false, fmt.Errorf("malformed LDAPResult field %d", index)
		}
		cursor = fieldEnd
	}
	seenReferral := false
	seenCredentials := false
	var credentials []byte
	for cursor < operation.end {
		field, fieldEnd, fieldErr := parseElement(parsed.ProtocolOp, cursor)
		if fieldErr != nil {
			return nil, false, errors.New("malformed BindResponse optional field")
		}
		switch {
		case elementIs(field, berClassContext, true, 3):
			if seenReferral || seenCredentials {
				return nil, false, errors.New("duplicate or out-of-order BindResponse referral")
			}
			seenReferral = true
			referralCursor := field.contentStart
			for referralCursor < field.end {
				referral, referralEnd, referralErr := parseElement(parsed.ProtocolOp, referralCursor)
				if referralErr != nil ||
					!elementIs(referral, berClassUniversal, false, berTagOctetString) {
					return nil, false, errors.New("malformed BindResponse referral")
				}
				referralCursor = referralEnd
			}
		case elementIs(field, berClassContext, false, 7):
			if seenCredentials {
				return nil, false, errors.New("duplicate server SASL credentials")
			}
			seenCredentials = true
			credentials = bytes.Clone(parsed.ProtocolOp[field.contentStart:field.end])
		default:
			return nil, false, errors.New("unexpected BindResponse optional field")
		}
		cursor = fieldEnd
	}
	return credentials, seenCredentials, nil
}

func serviceSASLResultError(mechanism string, code ldapwire.ResultCode) error {
	return fmt.Errorf("service SASL %s Bind failed with LDAP result %d", mechanism, code)
}

func (backend *runtimeBackend) bindServiceSASLPlain(
	connection net.Conn,
	nextMessageID *int64,
) error {
	config := backend.proxy.config.Bind
	authenticationID, authErr := stringprep.SASLprep.Prepare(config.AuthenticationID)
	authorizationID, authzErr := stringprep.SASLprep.Prepare(config.AuthorizationID)
	password, passwordErr := stringprep.SASLprep.Prepare(string(config.Credentials))
	if authErr != nil || authzErr != nil || passwordErr != nil || authenticationID == "" {
		return errors.New("service SASL PLAIN credentials are not valid SASLprep values")
	}
	credentials := make([]byte, 0, len(authorizationID)+len(authenticationID)+len(password)+2)
	credentials = append(credentials, authorizationID...)
	credentials = append(credentials, 0)
	credentials = append(credentials, authenticationID...)
	credentials = append(credentials, 0)
	credentials = append(credentials, password...)
	defer clear(credentials)

	for round := 0; round < 2; round++ {
		result, err := backend.exchangeServiceSASLBind(
			connection,
			nextMessageID,
			"PLAIN",
			credentials,
			true,
		)
		defer result.clear()
		if err != nil {
			return err
		}
		switch result.code {
		case ldapwire.ResultSuccess:
			if result.hasServerCredentials {
				return errors.New("service SASL PLAIN server returned unexpected credentials")
			}
			return nil
		case ldapwire.ResultSASLBindInProgress:
			if round != 0 || len(result.serverCredentials) != 0 {
				return errors.New("service SASL PLAIN server returned an unexpected challenge")
			}
		default:
			return serviceSASLResultError("PLAIN", result.code)
		}
	}
	return errors.New("service SASL PLAIN Bind exceeded the challenge limit")
}

func (backend *runtimeBackend) bindServiceSASLCRAMMD5(
	connection net.Conn,
	nextMessageID *int64,
) error {
	result, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"CRAM-MD5",
		nil,
		false,
	)
	defer result.clear()
	if err != nil {
		return err
	}
	if result.code != ldapwire.ResultSASLBindInProgress {
		return serviceSASLResultError("CRAM-MD5", result.code)
	}
	if err := validateServiceCRAMMD5Challenge(
		result.serverCredentials,
		result.hasServerCredentials,
	); err != nil {
		return err
	}
	authenticationID, err := stringprep.SASLprep.Prepare(
		backend.proxy.config.Bind.AuthenticationID,
	)
	if err != nil || authenticationID == "" || strings.ContainsAny(authenticationID, " \t\r\n") {
		return errors.New("service SASL CRAM-MD5 authcid is not a valid SASLprep value")
	}
	mac := hmac.New(md5.New, backend.proxy.config.Bind.Credentials) //nolint:gosec
	_, _ = mac.Write(result.serverCredentials)
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

	final, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"CRAM-MD5",
		response,
		true,
	)
	defer final.clear()
	if err != nil {
		return err
	}
	if final.code != ldapwire.ResultSuccess {
		return serviceSASLResultError("CRAM-MD5", final.code)
	}
	if final.hasServerCredentials {
		return errors.New("service SASL CRAM-MD5 server returned unexpected final credentials")
	}
	return nil
}

func validateServiceCRAMMD5Challenge(challenge []byte, present bool) error {
	if !present || len(challenge) < 5 || len(challenge) > serviceCRAMMaxChallengeSize ||
		challenge[0] != '<' || challenge[len(challenge)-1] != '>' {
		return errors.New("service SASL CRAM-MD5 server returned a malformed challenge")
	}
	at := bytes.LastIndexByte(challenge, '@')
	if at <= 1 || at >= len(challenge)-2 || bytes.IndexByte(challenge[1:at], '@') >= 0 {
		return errors.New("service SASL CRAM-MD5 challenge is not a valid message ID")
	}
	for _, value := range challenge[1 : len(challenge)-1] {
		if value <= 0x20 || value >= 0x7f || value == '<' || value == '>' {
			return errors.New("service SASL CRAM-MD5 challenge contains invalid bytes")
		}
	}
	return nil
}

func (backend *runtimeBackend) bindServiceSASLSCRAM(
	connection net.Conn,
	nextMessageID *int64,
) error {
	config := backend.proxy.config.Bind
	generator, ok := serviceSCRAMGenerator(config.SASLMechanism)
	if !ok {
		return fmt.Errorf("unsupported service SCRAM mechanism %q", config.SASLMechanism)
	}
	client, err := generator.NewClient(
		config.AuthenticationID,
		string(config.Credentials),
		config.AuthorizationID,
	)
	if err != nil {
		return fmt.Errorf("service SASL %s credentials are not valid SASLprep values", config.SASLMechanism)
	}
	client.WithMinIterations(serviceSCRAMMinIterations)
	conversation := client.NewConversation()
	clientFirst, err := conversation.Step("")
	if err != nil {
		return fmt.Errorf("initialize service SASL %s conversation", config.SASLMechanism)
	}
	clientNonce, err := serviceSCRAMClientNonce(clientFirst)
	if err != nil {
		return fmt.Errorf("initialize service SASL %s nonce: %w", config.SASLMechanism, err)
	}
	first, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		config.SASLMechanism,
		[]byte(clientFirst),
		true,
	)
	defer first.clear()
	if err != nil {
		return err
	}
	if first.code != ldapwire.ResultSASLBindInProgress {
		return serviceSASLResultError(config.SASLMechanism, first.code)
	}
	if !first.hasServerCredentials {
		return fmt.Errorf("service SASL %s server omitted server-first", config.SASLMechanism)
	}
	if err := validateServiceSCRAMServerFirst(first.serverCredentials, clientNonce); err != nil {
		return fmt.Errorf("service SASL %s server-first: %w", config.SASLMechanism, err)
	}
	clientFinal, err := conversation.Step(string(first.serverCredentials))
	if err != nil {
		return fmt.Errorf("service SASL %s server-first was rejected", config.SASLMechanism)
	}
	clientFinalBytes := []byte(clientFinal)
	defer clear(clientFinalBytes)
	final, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		config.SASLMechanism,
		clientFinalBytes,
		true,
	)
	defer final.clear()
	if err != nil {
		return err
	}
	if final.code != ldapwire.ResultSuccess && final.code != ldapwire.ResultSASLBindInProgress {
		return serviceSASLResultError(config.SASLMechanism, final.code)
	}
	if !final.hasServerCredentials {
		return fmt.Errorf("service SASL %s server omitted server-final proof", config.SASLMechanism)
	}
	if err := validateServiceSCRAMServerFinal(final.serverCredentials, generator().Size()); err != nil {
		return fmt.Errorf("service SASL %s server-final: %w", config.SASLMechanism, err)
	}
	if response, err := conversation.Step(string(final.serverCredentials)); err != nil || response != "" || !conversation.Done() || !conversation.Valid() {
		return fmt.Errorf("service SASL %s server signature is invalid", config.SASLMechanism)
	}
	if final.code == ldapwire.ResultSuccess {
		return nil
	}
	completed, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		config.SASLMechanism,
		[]byte{},
		true,
	)
	defer completed.clear()
	if err != nil {
		return err
	}
	if completed.code != ldapwire.ResultSuccess {
		return serviceSASLResultError(config.SASLMechanism, completed.code)
	}
	if completed.hasServerCredentials {
		return fmt.Errorf("service SASL %s server returned unexpected completion data", config.SASLMechanism)
	}
	return nil
}

func serviceSCRAMGenerator(mechanism string) (scram.HashGeneratorFcn, bool) {
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

func serviceSCRAMClientNonce(clientFirst string) (string, error) {
	fields := strings.Split(clientFirst, ",")
	if len(fields) != 4 || fields[0] != "n" ||
		(fields[1] != "" && !strings.HasPrefix(fields[1], "a=")) ||
		!strings.HasPrefix(fields[2], "n=") || !strings.HasPrefix(fields[3], "r=") {
		return "", errors.New("SCRAM client-first message is malformed")
	}
	nonce := strings.TrimPrefix(fields[3], "r=")
	if !serviceSCRAMNonceValid(nonce) {
		return "", errors.New("SCRAM client nonce is malformed")
	}
	return nonce, nil
}

func validateServiceSCRAMServerFirst(serverFirst []byte, clientNonce string) error {
	if len(serverFirst) == 0 || len(serverFirst) > serviceSASLMaxChallengeSize ||
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
		!serviceSCRAMNonceValid(nonce) {
		return errors.New("server nonce did not strictly extend the client nonce")
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(fields[1], "s="))
	if err != nil || len(salt) == 0 || len(salt) > serviceSCRAMMaxSaltSize {
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
	if err != nil || iterations < serviceSCRAMMinIterations ||
		iterations > serviceSCRAMMaxIterations {
		return fmt.Errorf(
			"server iteration count must be between %d and %d",
			serviceSCRAMMinIterations,
			serviceSCRAMMaxIterations,
		)
	}
	return nil
}

func validateServiceSCRAMServerFinal(serverFinal []byte, hashSize int) error {
	if len(serverFinal) == 0 || len(serverFinal) > serviceSASLMaxChallengeSize ||
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

func serviceSCRAMNonceValid(nonce string) bool {
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

type serviceDigestMD5Values struct {
	username      string
	realm         string
	nonce         string
	cnonce        string
	digestURI     string
	authorization string
}

func (backend *runtimeBackend) bindServiceSASLDigestMD5(
	connection net.Conn,
	nextMessageID *int64,
) error {
	first, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"DIGEST-MD5",
		nil,
		false,
	)
	defer first.clear()
	if err != nil {
		return err
	}
	if first.code != ldapwire.ResultSASLBindInProgress {
		return serviceSASLResultError("DIGEST-MD5", first.code)
	}
	if !first.hasServerCredentials {
		return errors.New("service SASL DIGEST-MD5 server omitted its challenge")
	}
	response, expectedRspauth, err := backend.serviceDigestMD5Response(
		first.serverCredentials,
	)
	if err != nil {
		return fmt.Errorf("service SASL DIGEST-MD5 challenge: %w", err)
	}
	defer clear(response)
	defer clear(expectedRspauth)
	second, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"DIGEST-MD5",
		response,
		true,
	)
	defer second.clear()
	if err != nil {
		return err
	}
	if second.code != ldapwire.ResultSuccess && second.code != ldapwire.ResultSASLBindInProgress {
		return serviceSASLResultError("DIGEST-MD5", second.code)
	}
	if err := verifyServiceDigestMD5Rspauth(
		second.serverCredentials,
		second.hasServerCredentials,
		expectedRspauth,
	); err != nil {
		return err
	}
	if second.code == ldapwire.ResultSuccess {
		return nil
	}
	final, err := backend.exchangeServiceSASLBind(
		connection,
		nextMessageID,
		"DIGEST-MD5",
		[]byte{},
		true,
	)
	defer final.clear()
	if err != nil {
		return err
	}
	if final.code != ldapwire.ResultSuccess {
		return serviceSASLResultError("DIGEST-MD5", final.code)
	}
	if final.hasServerCredentials {
		return errors.New("service SASL DIGEST-MD5 server returned unexpected final credentials")
	}
	return nil
}

func (backend *runtimeBackend) serviceDigestMD5Response(
	challenge []byte,
) ([]byte, []byte, error) {
	config := backend.proxy.config.Bind
	directives, realms, err := parseServiceDigestMD5Directives(challenge, true)
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(directives["algorithm"], "md5-sess") {
		return nil, nil, errors.New("challenge does not use md5-sess")
	}
	if charset, present := directives["charset"]; present &&
		!strings.EqualFold(charset, "utf-8") {
		return nil, nil, errors.New("challenge uses an unsupported charset")
	}
	if _, utf8Offered := directives["charset"]; utf8Offered &&
		!utf8.Valid(config.Credentials) {
		return nil, nil, errors.New("credentials are not valid UTF-8")
	}
	if stale, present := directives["stale"]; present && strings.EqualFold(stale, "true") {
		return nil, nil, errors.New("server marked its nonce stale")
	}
	nonce := directives["nonce"]
	if nonce == "" {
		return nil, nil, errors.New("challenge has no nonce")
	}
	qop := directives["qop"]
	if qop == "" {
		qop = "auth"
	}
	if !serviceDigestListContains(qop, "auth") {
		return nil, nil, errors.New("challenge does not offer auth qop")
	}
	if rawMaximum, present := directives["maxbuf"]; present {
		maximum, parseErr := strconv.ParseUint(rawMaximum, 10, 24)
		if parseErr != nil || maximum <= 16 || maximum > serviceDigestMaxBufferSize {
			return nil, nil, errors.New("challenge has invalid maxbuf")
		}
	}
	realm := config.Realm
	if realm == "" && len(realms) > 0 {
		realm = realms[0]
	}
	if config.Realm != "" && len(realms) > 0 && !serviceStringSliceContains(realms, config.Realm) {
		return nil, nil, errors.New("configured realm was not offered by the server")
	}
	entropy := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, nil, errors.New("generate DIGEST-MD5 cnonce")
	}
	cnonce := base64.RawStdEncoding.EncodeToString(entropy)
	clear(entropy)
	values := serviceDigestMD5Values{
		username:      config.AuthenticationID,
		realm:         realm,
		nonce:         nonce,
		cnonce:        cnonce,
		digestURI:     "ldap/" + backend.serviceSASLHost(),
		authorization: config.AuthorizationID,
	}
	responseDigest, rspauth := serviceDigestMD5Exchange(values, config.Credentials)
	response := fmt.Sprintf(
		`username="%s",realm="%s",nonce="%s",cnonce="%s",nc=00000001,`+
			`qop=auth,digest-uri="%s",response=%s`,
		serviceDigestQuote(values.username),
		serviceDigestQuote(values.realm),
		serviceDigestQuote(values.nonce),
		serviceDigestQuote(values.cnonce),
		serviceDigestQuote(values.digestURI),
		responseDigest,
	)
	if values.authorization != "" {
		response += `,authzid="` + serviceDigestQuote(values.authorization) + `"`
	}
	if _, present := directives["charset"]; present {
		response += ",charset=utf-8"
	}
	return []byte(response), []byte(rspauth), nil
}

func (backend *runtimeBackend) serviceSASLHost() string {
	if runtimeLDAPURLScheme(backend.config.URI) == "ldapi" {
		return "localhost"
	}
	parsed, err := url.Parse(backend.config.URI)
	if err != nil || parsed.Hostname() == "" {
		return "localhost"
	}
	return strings.ToLower(parsed.Hostname())
}

func serviceDigestMD5Exchange(values serviceDigestMD5Values, password []byte) (string, string) {
	secretHash := md5.New() //nolint:gosec
	_, _ = secretHash.Write([]byte(values.username + ":" + values.realm + ":"))
	_, _ = secretHash.Write(password)
	secret := secretHash.Sum(nil)
	a1 := md5.New() //nolint:gosec
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

func verifyServiceDigestMD5Rspauth(credentials []byte, present bool, expected []byte) error {
	if !present {
		return errors.New("service SASL DIGEST-MD5 server omitted rspauth")
	}
	directives, _, err := parseServiceDigestMD5Directives(credentials, false)
	if err != nil || len(directives) != 1 {
		return errors.New("service SASL DIGEST-MD5 server returned malformed rspauth")
	}
	rspauth, ok := directives["rspauth"]
	if !ok || len(rspauth) != len(expected) ||
		subtle.ConstantTimeCompare([]byte(rspauth), expected) != 1 {
		return errors.New("service SASL DIGEST-MD5 server proof is invalid")
	}
	return nil
}

func parseServiceDigestMD5Directives(
	input []byte,
	allowRepeatedRealm bool,
) (map[string]string, []string, error) {
	if len(input) == 0 || len(input) > serviceSASLMaxChallengeSize {
		return nil, nil, errors.New("DIGEST-MD5 directive list has invalid size")
	}
	directives := make(map[string]string)
	var realms []string
	for offset := 0; offset < len(input); {
		for offset < len(input) && (input[offset] == ' ' || input[offset] == '\t') {
			offset++
		}
		start := offset
		for offset < len(input) && serviceDigestTokenByte(input[offset]) {
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
				if !serviceDigestTokenByte(input[offset]) {
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

func serviceDigestTokenByte(value byte) bool {
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

func serviceDigestQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func serviceDigestListContains(values, wanted string) bool {
	for _, value := range strings.Split(values, ",") {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}

func serviceStringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
