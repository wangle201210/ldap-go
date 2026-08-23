package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	remoteAuthDefaultRetryCount            = 3
	defaultRemoteAuthConcurrentAttempts    = 16
	defaultRemoteAuthMaxConnectionLifetime = time.Minute
	remoteAuthRuntimePollInterval          = 10 * time.Millisecond
)

var errRemoteAuthConfigurationRetired = errors.New("remoteauth configuration retired")

type remoteAuthTLSPin struct {
	hash  string
	value []byte
}

type remoteAuthRuntimeConfiguration struct {
	dnAttribute     string
	domainAttribute string
	defaultDomain   string
	defaultRealm    string
	mappings        map[string]string
	storeOnSuccess  bool
	retryCount      int
	connection      syncConsumerConfig
	pins            map[string]remoteAuthTLSPin
	connections     *remoteAuthConnectionManager
}

// remoteauth performs a Simple Bind and has no operation that can safely prove
// the connection anonymous again. Keep every transport one-shot; this manager
// only bounds independent attempts and retires an old runtime configuration.
type remoteAuthConnectionManager struct {
	mu          sync.Mutex
	groups      map[string]*remoteAuthAttemptGroup
	limit       int
	maxLifetime time.Duration
	lifecycle   context.Context
	retire      context.CancelFunc
	retireOnce  sync.Once
}

type remoteAuthAttemptGroup struct {
	attempts   chan struct{}
	references int
}

func newRemoteAuthConnectionManager(
	limit int,
	maxLifetime time.Duration,
) *remoteAuthConnectionManager {
	if limit <= 0 {
		limit = defaultRemoteAuthConcurrentAttempts
	}
	if maxLifetime <= 0 {
		maxLifetime = defaultRemoteAuthMaxConnectionLifetime
	}
	lifecycle, retire := context.WithCancel(context.Background())
	return &remoteAuthConnectionManager{
		groups:      make(map[string]*remoteAuthAttemptGroup),
		limit:       limit,
		maxLifetime: maxLifetime,
		lifecycle:   lifecycle,
		retire:      retire,
	}
}

func (manager *remoteAuthConnectionManager) acquire(
	ctx context.Context,
	realm string,
	provider string,
) (func(), error) {
	if manager == nil {
		return func() {}, nil
	}
	if err := manager.lifecycle.Err(); err != nil {
		return nil, errRemoteAuthConfigurationRetired
	}
	key := realm + "\x00" + provider
	manager.mu.Lock()
	group := manager.groups[key]
	if group == nil {
		group = &remoteAuthAttemptGroup{
			attempts: make(chan struct{}, manager.limit),
		}
		manager.groups[key] = group
	}
	group.references++
	manager.mu.Unlock()

	releaseReference := func() {
		manager.mu.Lock()
		group.references--
		if group.references == 0 && len(group.attempts) == 0 {
			delete(manager.groups, key)
		}
		manager.mu.Unlock()
	}
	select {
	case group.attempts <- struct{}{}:
		if manager.lifecycle.Err() != nil {
			<-group.attempts
			releaseReference()
			return nil, errRemoteAuthConfigurationRetired
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				<-group.attempts
				releaseReference()
			})
		}, nil
	case <-ctx.Done():
		releaseReference()
		return nil, ctx.Err()
	case <-manager.lifecycle.Done():
		releaseReference()
		return nil, errRemoteAuthConfigurationRetired
	}
}

func (manager *remoteAuthConnectionManager) attemptContext(
	ctx context.Context,
) (context.Context, context.CancelFunc) {
	if manager == nil {
		return context.WithCancel(ctx)
	}
	lifetimeContext, lifetimeCancel := context.WithTimeout(ctx, manager.maxLifetime)
	attemptContext, attemptCancel := context.WithCancel(lifetimeContext)
	stopRetirement := context.AfterFunc(manager.lifecycle, attemptCancel)
	return attemptContext, func() {
		stopRetirement()
		attemptCancel()
		lifetimeCancel()
	}
}

func (manager *remoteAuthConnectionManager) retireConfiguration() {
	if manager == nil {
		return
	}
	manager.retireOnce.Do(manager.retire)
}

func loadRemoteAuthRuntimeConfiguration(
	entry directory.Entry,
) (remoteAuthRuntimeConfiguration, error) {
	configuration := remoteAuthRuntimeConfiguration{
		mappings:   make(map[string]string),
		retryCount: remoteAuthDefaultRetryCount,
		connection: syncConsumerConfig{
			securityProperties: defaultSyncConsumerSASLSecurityProperties(),
		},
		pins: make(map[string]remoteAuthTLSPin),
	}
	var err error
	for _, setting := range []struct {
		description string
		target      *string
	}{
		{"olcRemoteAuthDNAttribute", &configuration.dnAttribute},
		{"olcRemoteAuthDomainAttribute", &configuration.domainAttribute},
		{"olcRemoteAuthDefaultDomain", &configuration.defaultDomain},
		{"olcRemoteAuthDefaultRealm", &configuration.defaultRealm},
	} {
		value, present, parseErr := singleChainString(entry, setting.description)
		if parseErr != nil {
			return remoteAuthRuntimeConfiguration{}, parseErr
		}
		if present {
			value = strings.TrimSpace(value)
			if value == "" {
				return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
					"%s %s is empty",
					entry.DN,
					setting.description,
				)
			}
			*setting.target = value
		}
	}

	for _, raw := range entry.Values("olcRemoteAuthMapping") {
		value, parseErr := stripRemoteAuthOrderingPrefix(string(raw))
		if parseErr != nil {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRemoteAuthMapping: %w",
				entry.DN,
				parseErr,
			)
		}
		arguments, parseErr := tokenizeOpenLDAPConfig(value)
		if parseErr != nil || len(arguments) != 2 ||
			arguments[0] == "" || arguments[1] == "" {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRemoteAuthMapping has invalid value %q",
				entry.DN,
				raw,
			)
		}
		domain := strings.ToLower(arguments[0])
		if _, exists := configuration.mappings[domain]; !exists {
			configuration.mappings[domain] = arguments[1]
		}
	}

	configuration.storeOnSuccess, _, err = singleBoolean(
		entry,
		"olcRemoteAuthStore",
	)
	if err != nil {
		return remoteAuthRuntimeConfiguration{}, err
	}
	if values := entry.Values("olcRemoteAuthRetryCount"); len(values) > 1 {
		return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
			"%s olcRemoteAuthRetryCount must be single-valued",
			entry.DN,
		)
	} else if len(values) == 1 {
		configuration.retryCount, err = strconv.Atoi(strings.TrimSpace(string(values[0])))
		if err != nil || configuration.retryCount < 0 ||
			configuration.retryCount > 1000 {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRemoteAuthRetryCount has invalid value %q",
				entry.DN,
				values[0],
			)
		}
	}

	if value, present, parseErr := singleChainString(
		entry,
		"olcRemoteAuthTLS",
	); parseErr != nil {
		return remoteAuthRuntimeConfiguration{}, parseErr
	} else if !present {
		return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
			"%s remoteauth overlay requires olcRemoteAuthTLS",
			entry.DN,
		)
	} else {
		if parseErr := parseRemoteAuthTLS(value, &configuration.connection); parseErr != nil {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRemoteAuthTLS: %w",
				entry.DN,
				parseErr,
			)
		}
	}

	for _, raw := range entry.Values("olcRemoteAuthTLSPeerkeyHash") {
		value, parseErr := stripRemoteAuthOrderingPrefix(string(raw))
		if parseErr != nil {
			return remoteAuthRuntimeConfiguration{}, parseErr
		}
		arguments, parseErr := tokenizeOpenLDAPConfig(value)
		if parseErr != nil || len(arguments) != 2 {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRemoteAuthTLSPeerkeyHash has invalid value %q",
				entry.DN,
				raw,
			)
		}
		host := strings.ToLower(arguments[0])
		if _, exists := configuration.pins[host]; exists {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s configures multiple TLS pins for %s",
				entry.DN,
				host,
			)
		}
		pin, parseErr := parseRemoteAuthTLSPin(arguments[1])
		if parseErr != nil {
			return remoteAuthRuntimeConfiguration{}, fmt.Errorf(
				"%s TLS pin for %s: %w",
				entry.DN,
				host,
				parseErr,
			)
		}
		configuration.pins[host] = pin
	}
	configuration.connections = newRemoteAuthConnectionManager(
		defaultRemoteAuthConcurrentAttempts,
		defaultRemoteAuthMaxConnectionLifetime,
	)
	return configuration, nil
}

func validateRemoteAuthSchema(
	registry *schema.Registry,
	configuration *remoteAuthRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for _, setting := range []struct {
		name  string
		value string
	}{
		{"olcRemoteAuthDNAttribute", configuration.dnAttribute},
		{"olcRemoteAuthDomainAttribute", configuration.domainAttribute},
	} {
		if setting.value == "" {
			continue
		}
		if !registry.HasAttributeType(setting.value) {
			return fmt.Errorf("%s refers to undefined attribute %q", setting.name, setting.value)
		}
	}
	return nil
}

func stripRemoteAuthOrderingPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered-value prefix")
	}
	if _, err := strconv.Atoi(value[1:end]); err != nil {
		return "", errors.New("invalid ordered-value prefix")
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func parseRemoteAuthTLS(value string, configuration *syncConsumerConfig) error {
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return errors.New("empty TLS configuration")
	}
	for _, argument := range arguments {
		name, rawValue, found := strings.Cut(argument, "=")
		if !found || rawValue == "" {
			return fmt.Errorf("invalid TLS parameter %q", argument)
		}
		switch strings.ToLower(name) {
		case "starttls":
			configuration.startTLS, err = parseSyncConsumerStartTLS(rawValue)
		case "tls_cert":
			configuration.tls.certificateFile = rawValue
		case "tls_key":
			configuration.tls.keyFile = rawValue
		case "tls_cacert":
			configuration.tls.caCertificate = rawValue
		case "tls_cacertdir":
			configuration.tls.caDirectory = rawValue
		case "tls_reqcert":
			configuration.tls.requireCert, err =
				parseSyncConsumerTLSRequirement(rawValue)
		case "tls_reqsan":
			configuration.tls.requireSAN, err =
				parseSyncConsumerTLSRequirement(rawValue)
		case "tls_cipher_suite":
			configuration.tls.cipherSuite = rawValue
		case "tls_ecname":
			configuration.tls.ecName = rawValue
		case "tls_crlcheck":
			switch strings.ToLower(rawValue) {
			case "none", "peer", "all":
				configuration.tls.crlCheck = strings.ToLower(rawValue)
			default:
				err = fmt.Errorf("unknown tls_crlcheck value %q", rawValue)
			}
		case "tls_protocol_min":
			configuration.tls.protocolMinimum = rawValue
		default:
			return fmt.Errorf("unknown TLS parameter %q", name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func parseRemoteAuthTLSPin(value string) (remoteAuthTLSPin, error) {
	algorithm, encoded, found := strings.Cut(value, ":")
	if !found || encoded == "" {
		return remoteAuthTLSPin{}, errors.New("pin must be hash:base64")
	}
	algorithm = strings.ToLower(algorithm)
	var expectedSize int
	switch algorithm {
	case "sha1":
		expectedSize = sha1.Size
	case "sha256":
		expectedSize = sha256.Size
	case "sha384":
		expectedSize = sha512.Size384
	case "sha512":
		expectedSize = sha512.Size
	case "sm3":
		expectedSize = sm3.Size
	default:
		return remoteAuthTLSPin{}, fmt.Errorf("unsupported hash %q", algorithm)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != expectedSize {
		return remoteAuthTLSPin{}, errors.New("pin digest has invalid base64 or length")
	}
	return remoteAuthTLSPin{hash: algorithm, value: decoded}, nil
}

func (server *Server) remoteAuthSimpleBind(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	password []byte,
) (bool, ldapwire.Result, []ldapwire.Control) {
	if _, root := databaseAuthenticationRoot(runtime, database, dn); root {
		return false, ldapwire.Result{}, nil
	}
	configuration := database.remoteAuth
	if configuration == nil || configuration.dnAttribute == "" ||
		configuration.domainAttribute == "" {
		return false, ldapwire.Result{}, nil
	}

	var remoteDN, domain string
	var hasDomain bool
	localDN, err := normalizeRuntimeDatabaseDN(database, dn)
	if err != nil {
		return false, ldapwire.Result{}, nil
	}
	localEligible := false
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		databaseReader := readerForDatabase(reader, database)
		comparisonDN, err := storage.NormalizeReaderDN(databaseReader, localDN)
		if err != nil {
			return err
		}
		entry, err := databaseReader.Get(comparisonDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		storedDN, err := parseRuntimeDN(entry.DN, database.dnNormalizer)
		if err != nil {
			return err
		}
		storedDN, err = storage.NormalizeReaderDN(databaseReader, storedDN)
		if err != nil {
			return err
		}
		if entry.HasAttribute("userPassword") {
			return nil
		}
		dnValues := entry.Values(configuration.dnAttribute)
		if len(dnValues) == 0 || len(dnValues[0]) == 0 {
			return nil
		}
		domainValues := entry.Values(configuration.domainAttribute)
		if len(domainValues) > 0 {
			domain = string(domainValues[0])
			hasDomain = true
		} else if configuration.defaultDomain != "" {
			domain = configuration.defaultDomain
			hasDomain = true
		}
		if !hasDomain {
			return nil
		}
		mappedDN, err := parseRuntimeDN(
			string(dnValues[0]),
			remoteAuthDNNormalizer(runtime, database),
		)
		if err != nil {
			return nil
		}
		localDN = storedDN
		remoteDN = mappedDN.String()
		localEligible = true
		return nil
	})
	if err != nil {
		server.config.Logger.Warn("load remoteauth entry", "dn", dn.String(), "error", err)
		return true, ldapwire.ResultError(ldapwire.ResultOperationsError, "remoteauth entry lookup failed"), nil
	}
	if !localEligible {
		return false, ldapwire.Result{}, nil
	}
	configurationCurrent := func() bool {
		if server.runtime.Load() == nil {
			return database.remoteAuth != nil &&
				database.remoteAuth.connections == configuration.connections
		}
		return server.remoteAuthConfigurationCurrent(
			localDN,
			configuration.connections,
		)
	}
	if !configurationCurrent() {
		configuration.connections.retireConfiguration()
		return true, ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"remoteauth configuration changed",
		), nil
	}
	stopRetirementWatch := watchRemoteAuthRuntime(
		ctx,
		configuration.connections,
		configurationCurrent,
	)
	defer stopRetirementWatch()

	realm := remoteAuthRealm(*configuration, domain)
	providers, err := remoteAuthRealmProviders(realm)
	if err != nil || len(providers) == 0 {
		if err != nil {
			server.config.Logger.Debug("resolve remoteauth realm", "error", err)
		}
		return false, ldapwire.Result{}, nil
	}

	request := ldapwire.BindRequest{
		Version: 3,
		Name:    remoteDN,
		Authentication: ldapwire.Authentication{
			Simple: bytes.Clone(password),
		},
	}
	defer clear(request.Authentication.Simple)
	var lastResult *ldapwire.Result
	var lastError error
	for attempt := 0; attempt <= configuration.retryCount; attempt++ {
		retryBindResult := false
		for _, provider := range providers {
			result, err := executeRemoteAuthBind(
				ctx,
				*configuration,
				realm,
				provider,
				request,
			)
			if err != nil {
				lastError = err
				if ctx.Err() != nil ||
					errors.Is(err, errRemoteAuthConfigurationRetired) {
					break
				}
				continue
			}
			if !configurationCurrent() {
				configuration.connections.retireConfiguration()
				lastResult = nil
				lastError = errRemoteAuthConfigurationRetired
				break
			}
			lastResult = &result
			switch result.Code {
			case ldapwire.ResultSuccess:
				if configuration.storeOnSuccess {
					server.storeRemoteAuthPassword(ctx, runtime, database, localDN, password)
				}
				if !configurationCurrent() {
					configuration.connections.retireConfiguration()
					lastResult = nil
					lastError = errRemoteAuthConfigurationRetired
					break
				}
				return true, result, nil
			case ldapwire.ResultInvalidCredentials:
				return true, result, nil
			}
			retryBindResult = true
		}
		if ctx.Err() != nil ||
			errors.Is(lastError, errRemoteAuthConfigurationRetired) {
			break
		}
		if !retryBindResult {
			break
		}
	}
	if lastResult != nil {
		return true, *lastResult, nil
	}
	if lastError != nil {
		server.config.Logger.Warn("remoteauth provider failed", "error", lastError)
	}
	return true, ldapwire.ResultError(
		ldapwire.ResultOperationsError,
		"remoteauth bind operation failed",
	), nil
}

func (server *Server) remoteAuthConfigurationCurrent(
	dn directory.DN,
	manager *remoteAuthConnectionManager,
) bool {
	active := server.runtime.Load()
	if active == nil {
		return false
	}
	activeDatabase := databaseForDN(active, dn)
	return activeDatabase != nil &&
		activeDatabase.remoteAuth != nil &&
		activeDatabase.remoteAuth.connections == manager
}

func watchRemoteAuthRuntime(
	ctx context.Context,
	manager *remoteAuthConnectionManager,
	current func() bool,
) func() {
	if manager == nil || current == nil {
		return func() {}
	}
	watchContext, stop := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(remoteAuthRuntimePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watchContext.Done():
				return
			case <-manager.lifecycle.Done():
				return
			case <-ticker.C:
				if !current() {
					manager.retireConfiguration()
					return
				}
			}
		}
	}()
	return stop
}

func remoteAuthDNNormalizer(
	runtime *runtimeState,
	database runtimeDatabase,
) directory.DNAttributeNormalizer {
	if database.dnNormalizer != nil {
		return database.dnNormalizer
	}
	if runtime != nil {
		return runtime.schema
	}
	return nil
}

func remoteAuthRealm(
	configuration remoteAuthRuntimeConfiguration,
	domain string,
) string {
	if end := strings.IndexByte(domain, '\\'); end >= 0 {
		domain = domain[:end]
	} else if end := strings.IndexByte(domain, ':'); end >= 0 {
		domain = domain[:end]
	}
	if realm, found := configuration.mappings[strings.ToLower(domain)]; found {
		return realm
	}
	return configuration.defaultRealm
}

func remoteAuthRealmProviders(realm string) ([]string, error) {
	realm = strings.TrimSpace(realm)
	if realm == "" {
		return nil, nil
	}
	if !strings.HasPrefix(strings.ToLower(realm), "file://") {
		return []string{remoteAuthLDAPURL(realm)}, nil
	}
	file, err := os.Open(realm[len("file://"):])
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var providers []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 512), 512)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		providers = append(providers, remoteAuthLDAPURL(fields[0]))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return providers, nil
}

func remoteAuthLDAPURL(value string) string {
	if strings.Contains(value, "://") {
		return value
	}
	return "ldap://" + value
}

func executeRemoteAuthBind(
	ctx context.Context,
	configuration remoteAuthRuntimeConfiguration,
	realm string,
	provider string,
	request ldapwire.BindRequest,
) (ldapwire.Result, error) {
	release, err := configuration.connections.acquire(ctx, realm, provider)
	if err != nil {
		return ldapwire.Result{}, err
	}
	defer release()
	attemptContext, cancelAttempt := configuration.connections.attemptContext(ctx)
	defer cancelAttempt()

	transport, err := dialSyncConsumer(
		attemptContext,
		configuration.connection,
		provider,
	)
	if err != nil {
		return ldapwire.Result{}, err
	}
	stopCancellation := context.AfterFunc(attemptContext, func() {
		_ = transport.close()
	})
	defer stopCancellation()
	defer transport.close()
	attemptRequest := request
	attemptRequest.Authentication.Simple = bytes.Clone(
		request.Authentication.Simple,
	)
	defer clear(attemptRequest.Authentication.Simple)
	parsed, err := parseSyncConsumerProviderURL(provider)
	if err != nil {
		return ldapwire.Result{}, err
	}
	if configuration.connection.startTLS != syncConsumerStartTLSOff &&
		strings.EqualFold(parsed.Scheme, "ldap") {
		if err := performSyncConsumerStartTLS(
			transport,
			configuration.connection,
			parsed,
		); err != nil {
			if configuration.connection.startTLS == syncConsumerStartTLSCritical {
				return ldapwire.Result{}, err
			}
		}
	}
	if err := validateRemoteAuthTLSPeer(
		transport,
		parsed.Hostname(),
		configuration.pins,
	); err != nil {
		return ldapwire.Result{}, err
	}
	result, _, err := exchangePBind(
		transport,
		nil,
		attemptRequest,
	)
	if err != nil {
		return ldapwire.Result{}, err
	}
	return result, nil
}

func validateRemoteAuthTLSPeer(
	transport *syncConsumerTransport,
	host string,
	pins map[string]remoteAuthTLSPin,
) error {
	if len(pins) == 0 {
		return nil
	}
	pin, found := pins[strings.ToLower(host)]
	if !found {
		return fmt.Errorf("no TLS public-key pin configured for %s", host)
	}
	connection, ok := transport.currentConnection().(*tls.Conn)
	if !ok {
		return errors.New("TLS public-key pin requires a TLS connection")
	}
	certificates := connection.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return errors.New("TLS peer did not provide a certificate")
	}
	publicKey := certificates[0].RawSubjectPublicKeyInfo
	var digest []byte
	switch pin.hash {
	case "sha1":
		value := sha1.Sum(publicKey)
		digest = value[:]
	case "sha256":
		value := sha256.Sum256(publicKey)
		digest = value[:]
	case "sha384":
		value := sha512.Sum384(publicKey)
		digest = value[:]
	case "sha512":
		value := sha512.Sum512(publicKey)
		digest = value[:]
	case "sm3":
		value := sm3.Sum(publicKey)
		digest = value[:]
	}
	if len(digest) != len(pin.value) ||
		subtle.ConstantTimeCompare(digest, pin.value) != 1 {
		return errors.New("TLS peer public-key pin does not match")
	}
	return nil
}

func (server *Server) storeRemoteAuthPassword(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	password []byte,
) {
	if len(runtime.passwordHashSchemes) == 0 {
		return
	}
	stored, err := hashPasswordForRuntime(runtime, password, runtime.passwordHashSchemes[0])
	if err != nil {
		server.config.Logger.Warn(
			"remoteauth password hashing failed; storing cleartext for OpenLDAP compatibility",
			"scheme",
			runtime.passwordHashSchemes[0],
			"error",
			err,
		)
		stored = bytes.Clone(password)
	}
	defer clear(stored)
	var syncChange *syncChange
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		comparisonDN, err := storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return err
		}
		entry, err := tx.Get(comparisonDN)
		if err != nil {
			return err
		}
		if entry.HasAttribute("userPassword") {
			return nil
		}
		before := entry.Clone()
		entry.ReplaceValues("userPassword", [][]byte{bytes.Clone(stored)})
		return server.finishPasswordBindStateWrite(
			writer,
			runtime,
			database,
			before,
			&entry,
			&syncChange,
		)
	})
	if err != nil {
		server.config.Logger.Warn("store remoteauth password", "dn", dn.String(), "error", err)
		return
	}
	server.finishWriteEffects(ctx, nil, syncChange)
}
