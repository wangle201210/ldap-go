package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type pbindRuntimeConfiguration struct {
	providers    []string
	providerKeys []string
	connection   syncConsumerConfig
	quarantine   []syncConsumerRetry
	health       *pbindQuarantineState
	identity     *pbindRuntimeIdentity
}

const (
	// OpenLDAP bounds explicit pbind connections through slapd's worker pool,
	// whose default maximum is 16. Go handlers need an equivalent local bound.
	defaultPBindConcurrentAttempts = 16
	pbindProviderRetries           = 1
	pbindRuntimePollInterval       = 10 * time.Millisecond
)

type pbindRuntimeIdentity struct {
	lifecycle  context.Context
	retire     context.CancelFunc
	retireOnce sync.Once
}

var pbindGlobalAttempts = make(chan struct{}, defaultPBindConcurrentAttempts)

func newPBindRuntimeIdentity() *pbindRuntimeIdentity {
	lifecycle, retire := context.WithCancel(context.Background())
	return &pbindRuntimeIdentity{lifecycle: lifecycle, retire: retire}
}

func (identity *pbindRuntimeIdentity) retireConfiguration() {
	if identity == nil {
		return
	}
	identity.retireOnce.Do(identity.retire)
}

type pbindQuarantineState struct {
	mu          sync.Mutex
	now         func() time.Time
	quarantined bool
	retrying    bool
	index       int
	attempts    int
	lastFailure time.Time
}

func loadPBindRuntimeConfiguration(
	entry directory.Entry,
) (pbindRuntimeConfiguration, error) {
	configuration := pbindRuntimeConfiguration{
		connection: syncConsumerConfig{
			securityProperties: defaultSyncConsumerSASLSecurityProperties(),
		},
		identity: newPBindRuntimeIdentity(),
	}

	uri, present, err := singleChainString(entry, "olcDbURI")
	if err != nil {
		return pbindRuntimeConfiguration{}, err
	}
	if !present {
		return pbindRuntimeConfiguration{}, fmt.Errorf(
			"%s pbind overlay requires olcDbURI",
			entry.DN,
		)
	}
	for _, provider := range strings.Fields(uri) {
		parsed, parseErr := parseSyncConsumerProviderURL(provider)
		if parseErr != nil {
			return pbindRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDbURI: %w",
				entry.DN,
				parseErr,
			)
		}
		providerKey, parseErr := chainEndpointKey(parsed)
		if parseErr != nil {
			return pbindRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDbURI: %w",
				entry.DN,
				parseErr,
			)
		}
		configuration.providers = append(configuration.providers, provider)
		configuration.providerKeys = append(
			configuration.providerKeys,
			providerKey,
		)
	}
	if len(configuration.providers) == 0 {
		return pbindRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDbURI contains no LDAP endpoints",
			entry.DN,
		)
	}

	startTLS, present, err := singleChainString(entry, "olcDbStartTLS")
	if err != nil {
		return pbindRuntimeConfiguration{}, err
	}
	if present {
		if err := parsePBindTLS(startTLS, &configuration.connection); err != nil {
			return pbindRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDbStartTLS: %w",
				entry.DN,
				err,
			)
		}
	}

	networkTimeout, present, err := singleChainString(
		entry,
		"olcDbNetworkTimeout",
	)
	if err != nil {
		return pbindRuntimeConfiguration{}, err
	}
	if present {
		configuration.connection.networkTimeout, err = parseChainTimeInterval(
			networkTimeout,
		)
		if err != nil {
			return pbindRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDbNetworkTimeout: %w",
				entry.DN,
				err,
			)
		}
		configuration.connection.operationTimeout =
			configuration.connection.networkTimeout
	}

	quarantine, present, err := singleChainString(entry, "olcDbQuarantine")
	if err != nil {
		return pbindRuntimeConfiguration{}, err
	}
	if present {
		configuration.quarantine, err = parseChainQuarantine(quarantine)
		if err != nil {
			return pbindRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDbQuarantine: %w",
				entry.DN,
				err,
			)
		}
		configuration.health = &pbindQuarantineState{now: time.Now}
	}
	return configuration, nil
}

func parsePBindTLS(value string, configuration *syncConsumerConfig) error {
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return errors.New("empty TLS configuration")
	}
	if !strings.Contains(arguments[0], "=") {
		configuration.startTLS, err = parseChainStartTLS(arguments[0])
		if err != nil {
			return err
		}
		arguments = arguments[1:]
	}
	for _, argument := range arguments {
		name, value, found := strings.Cut(argument, "=")
		if !found || value == "" {
			return fmt.Errorf("invalid TLS parameter %q", argument)
		}
		switch strings.ToLower(name) {
		case "tls_cert":
			configuration.tls.certificateFile = value
		case "tls_key":
			configuration.tls.keyFile = value
		case "tls_cacert":
			configuration.tls.caCertificate = value
		case "tls_cacertdir":
			configuration.tls.caDirectory = value
		case "tls_reqcert":
			configuration.tls.requireCert, err =
				parseSyncConsumerTLSRequirement(value)
		case "tls_reqsan":
			configuration.tls.requireSAN, err =
				parseSyncConsumerTLSRequirement(value)
		case "tls_cipher_suite":
			configuration.tls.cipherSuite = value
		case "tls_ecname":
			configuration.tls.ecName = value
		case "tls_crlcheck":
			switch strings.ToLower(value) {
			case "none", "peer", "all":
				configuration.tls.crlCheck = strings.ToLower(value)
			default:
				err = fmt.Errorf("unknown tls_crlcheck value %q", value)
			}
		case "tls_protocol_min":
			configuration.tls.protocolMinimum = value
		default:
			return fmt.Errorf("unknown TLS parameter %q", name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) proxySimpleBind(
	ctx context.Context,
	configuration pbindRuntimeConfiguration,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) (ldapwire.Result, []ldapwire.Control) {
	request, failure := preparePBindRequest(
		server.runtime.Load(),
		configuration,
		request,
	)
	if failure != nil {
		return *failure, nil
	}
	requestName := request.Name
	current := func() bool {
		return server.pbindConfigurationCurrent(requestName, configuration.identity)
	}
	if !current() {
		configuration.identity.retireConfiguration()
		return ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"proxy bind target configuration changed",
		), nil
	}
	stopRetirementWatch := watchPBindRuntime(
		ctx,
		configuration.identity,
		current,
	)
	defer stopRetirementWatch()
	attemptContext, cancelAttempt := configuration.runtimeAttemptContext(ctx)
	defer cancelAttempt()
	release, acquireErr := configuration.acquirePBindAttempt(attemptContext)
	if acquireErr != nil {
		diagnostic := "proxy bind attempt canceled"
		if configuration.retired() {
			diagnostic = "proxy bind target configuration changed"
		}
		return ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			diagnostic,
		), nil
	}
	defer release()
	request, failure = preparePBindRequest(
		server.runtime.Load(),
		configuration,
		request,
	)
	if failure != nil {
		configuration.identity.retireConfiguration()
		return *failure, nil
	}
	if !configuration.beginPBindAttempt() {
		return ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"proxy bind target is quarantined",
		), nil
	}

	var (
		lastError    error
		lastResult   *ldapwire.Result
		lastControls []ldapwire.Control
	)
	for _, provider := range configuration.providers {
		for retry := 0; retry <= pbindProviderRetries; retry++ {
			providerContext, cancel := configuration.providerAttemptContext(attemptContext)
			result, controls, err := executePBind(
				providerContext,
				configuration.connection,
				provider,
				message.Controls,
				request,
			)
			attemptFailure := providerContext.Err()
			cancel()
			if err == nil && result.Code != ldapwire.ResultUnavailable {
				if !server.pbindConfigurationCurrent(request.Name, configuration.identity) {
					configuration.cancelPBindAttempt()
					return ldapwire.ResultError(
						ldapwire.ResultUnavailable,
						"proxy bind target configuration changed",
					), nil
				}
				configuration.finishPBindAttempt(result.Code)
				return result, controls
			}
			if err == nil {
				resultCopy := result
				lastResult = &resultCopy
				lastControls = controls
				lastError = fmt.Errorf(
					"pbind provider %s returned unavailable",
					provider,
				)
			} else {
				lastResult = nil
				lastControls = nil
				lastError = fmt.Errorf("pbind provider %s: %w", provider, err)
			}

			// A canceled client/server request must not start another outbound
			// connection. A provider attempt timeout moves directly to failover;
			// immediate connection loss gets one OpenLDAP-compatible retry.
			if attemptContext.Err() != nil {
				break
			}
			if attemptFailure != nil || !pbindRetryableError(err) ||
				retry == pbindProviderRetries {
				break
			}
		}
		if attemptContext.Err() != nil {
			break
		}
	}
	if attemptContext.Err() != nil {
		configuration.cancelPBindAttempt()
		diagnostic := "proxy bind attempt canceled"
		if configuration.retired() {
			diagnostic = "proxy bind target configuration changed"
		}
		return ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			diagnostic,
		), nil
	}
	configuration.finishPBindAttempt(ldapwire.ResultUnavailable)
	if lastResult != nil {
		return *lastResult, lastControls
	}

	diagnostic := "proxy bind provider is unavailable"
	if lastError != nil {
		server.config.Logger.Warn(
			"pbind provider failed",
			"error",
			lastError,
		)
	}
	return ldapwire.ResultError(ldapwire.ResultUnavailable, diagnostic), nil
}

func pbindRetryableError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) || pbindAttemptTimedOut(err) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	var operationError *net.OpError
	return errors.As(err, &operationError) && !operationError.Timeout()
}

func pbindAttemptTimedOut(err error) bool {
	if err == nil {
		return false
	}
	var networkError net.Error
	return errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkError) && networkError.Timeout())
}

func (configuration pbindRuntimeConfiguration) acquirePBindAttempt(
	ctx context.Context,
) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var retired <-chan struct{}
	if configuration.identity != nil && configuration.identity.lifecycle != nil {
		retired = configuration.identity.lifecycle.Done()
	}
	select {
	case pbindGlobalAttempts <- struct{}{}:
		if configuration.retired() {
			<-pbindGlobalAttempts
			return nil, context.Canceled
		}
		var once sync.Once
		return func() {
			once.Do(func() { <-pbindGlobalAttempts })
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-retired:
		return nil, context.Canceled
	}
}

func (configuration pbindRuntimeConfiguration) runtimeAttemptContext(
	ctx context.Context,
) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	attemptContext, cancel := context.WithCancel(ctx)
	if configuration.identity == nil || configuration.identity.lifecycle == nil {
		return attemptContext, cancel
	}
	stopRetirement := context.AfterFunc(configuration.identity.lifecycle, cancel)
	return attemptContext, func() {
		stopRetirement()
		cancel()
	}
}

func (configuration pbindRuntimeConfiguration) retired() bool {
	return configuration.identity != nil &&
		configuration.identity.lifecycle != nil &&
		configuration.identity.lifecycle.Err() != nil
}

func watchPBindRuntime(
	ctx context.Context,
	identity *pbindRuntimeIdentity,
	current func() bool,
) func() {
	if identity == nil || identity.lifecycle == nil || current == nil {
		return func() {}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	watchContext, stop := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(pbindRuntimePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watchContext.Done():
				return
			case <-identity.lifecycle.Done():
				return
			case <-ticker.C:
				if !current() {
					identity.retireConfiguration()
					return
				}
			}
		}
	}()
	return stop
}

func (configuration pbindRuntimeConfiguration) providerAttemptContext(
	ctx context.Context,
) (context.Context, context.CancelFunc) {
	if configuration.connection.networkTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, configuration.connection.networkTimeout)
}

func preparePBindRequest(
	runtime *runtimeState,
	configuration pbindRuntimeConfiguration,
	request ldapwire.BindRequest,
) (ldapwire.BindRequest, *ldapwire.Result) {
	if runtime == nil {
		failure := ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"runtime configuration is unavailable",
		)
		return ldapwire.BindRequest{}, &failure
	}
	target, err := parseRuntimeConnectionDN(runtime, request.Name)
	if err != nil {
		failure := ldapwire.ResultError(
			ldapwire.ResultInvalidDNSyntax,
			"invalid DN",
		)
		return ldapwire.BindRequest{}, &failure
	}
	database := databaseForDN(runtime, target)
	if database == nil || database.pbind == nil ||
		(configuration.identity != nil &&
			database.pbind.identity != configuration.identity) {
		failure := ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"proxy bind target configuration changed",
		)
		return ldapwire.BindRequest{}, &failure
	}

	request.Name = target.String()
	return request, nil
}

func (server *Server) pbindConfigurationCurrent(
	rawDN string,
	identity *pbindRuntimeIdentity,
) bool {
	active := server.runtime.Load()
	if active == nil {
		return false
	}
	target, err := parseRuntimeConnectionDN(active, rawDN)
	if err != nil {
		return false
	}
	database := databaseForDN(active, target)
	return database != nil && database.pbind != nil &&
		(identity == nil || database.pbind.identity == identity)
}

func (configuration pbindRuntimeConfiguration) beginPBindAttempt() bool {
	return beginProxyQuarantineAttempt(configuration.health, configuration.quarantine)
}

func beginProxyQuarantineAttempt(
	state *pbindQuarantineState,
	quarantine []syncConsumerRetry,
) bool {
	if state == nil || len(quarantine) == 0 {
		return true
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.quarantined {
		return true
	}
	if state.retrying || state.index >= len(quarantine) {
		return false
	}
	now := state.currentTime()
	if now.Before(
		state.lastFailure.Add(quarantine[state.index].interval),
	) {
		return false
	}
	state.retrying = true
	return true
}

func (configuration pbindRuntimeConfiguration) finishPBindAttempt(
	code ldapwire.ResultCode,
) {
	finishProxyQuarantineAttempt(configuration.health, configuration.quarantine, code)
}

func (configuration pbindRuntimeConfiguration) cancelPBindAttempt() {
	cancelProxyQuarantineAttempt(configuration.health)
}

func cancelProxyQuarantineAttempt(state *pbindQuarantineState) {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.retrying = false
	state.mu.Unlock()
}

func finishProxyQuarantineAttempt(
	state *pbindQuarantineState,
	quarantine []syncConsumerRetry,
	code ldapwire.ResultCode,
) {
	if state == nil || len(quarantine) == 0 {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if code != ldapwire.ResultUnavailable {
		state.quarantined = false
		state.retrying = false
		state.index = 0
		state.attempts = 0
		state.lastFailure = time.Time{}
		return
	}

	now := state.currentTime()
	if !state.quarantined {
		state.index = 0
		state.attempts = 0
	} else if state.retrying {
		state.attempts++
		pattern := quarantine[state.index]
		if pattern.attempts >= 0 && state.attempts >= pattern.attempts {
			state.index++
			state.attempts = 0
		}
	}
	state.quarantined = true
	state.retrying = false
	state.lastFailure = now
}

func (state *pbindQuarantineState) currentTime() time.Time {
	if state.now != nil {
		return state.now()
	}
	return time.Now()
}

func executePBind(
	ctx context.Context,
	configuration syncConsumerConfig,
	provider string,
	controls []ldapwire.Control,
	request ldapwire.BindRequest,
) (ldapwire.Result, []ldapwire.Control, error) {
	transport, err := dialSyncConsumer(ctx, configuration, provider)
	if err != nil {
		return ldapwire.Result{}, nil, err
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = transport.close()
	})
	defer stopCancellation()
	defer transport.close()

	parsed, err := parseSyncConsumerProviderURL(provider)
	if err != nil {
		return ldapwire.Result{}, nil, err
	}
	if configuration.startTLS != syncConsumerStartTLSOff &&
		strings.EqualFold(parsed.Scheme, "ldap") {
		if err := performSyncConsumerStartTLS(
			transport,
			configuration,
			parsed,
		); err != nil {
			if configuration.startTLS == syncConsumerStartTLSCritical {
				return ldapwire.Result{}, nil, fmt.Errorf("pbind StartTLS: %w", err)
			}
		}
	}
	return exchangePBind(transport, controls, request)
}

func exchangePBind(
	transport *syncConsumerTransport,
	controls []ldapwire.Control,
	request ldapwire.BindRequest,
) (ldapwire.Result, []ldapwire.Control, error) {
	messageID := transport.nextMessageID()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID:       messageID,
		Request:  request,
		Controls: cloneLDAPControls(controls),
	})
	if err != nil {
		return ldapwire.Result{}, nil, err
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		return ldapwire.Result{}, nil, err
	}
	remote, err := transport.exchangeLDAPResult(
		messageID,
		packet,
		ldapwire.ApplicationBindResponse,
	)
	if err != nil {
		return ldapwire.Result{}, nil, err
	}
	responseControls, err := decodePBindResponseControls(remote.packet)
	if err != nil {
		return ldapwire.Result{}, nil, err
	}
	return ldapwire.Result{
		Code:              ldapwire.ResultCode(remote.code),
		MatchedDN:         remote.matchedDN,
		DiagnosticMessage: remote.diagnosticMessage,
		Referrals:         pbindResultReferrals(remote.packet),
	}, responseControls, nil
}

func decodePBindResponseControls(packet *ber.Packet) ([]ldapwire.Control, error) {
	if packet == nil || len(packet.Children) < 3 {
		return nil, nil
	}
	wrapper := packet.Children[2]
	if !syncConsumerPacketIs(wrapper, ber.ClassContext, ber.TypeConstructed, 0) {
		return nil, errors.New("malformed pbind response controls")
	}
	controls := make([]ldapwire.Control, 0, len(wrapper.Children))
	for _, encoded := range wrapper.Children {
		if !syncConsumerPacketIs(
			encoded,
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSequence,
		) || len(encoded.Children) < 1 || len(encoded.Children) > 3 {
			return nil, errors.New("malformed pbind response control")
		}
		oid, err := syncConsumerPacketBytes(encoded.Children[0])
		if err != nil || len(oid) == 0 {
			return nil, errors.New("malformed pbind response control OID")
		}
		control := ldapwire.Control{OID: string(oid)}
		position := 1
		if position < len(encoded.Children) &&
			syncConsumerPacketIs(
				encoded.Children[position],
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagBoolean,
			) {
			value := encoded.Children[position].Data.Bytes()
			if len(value) != 1 {
				return nil, errors.New("malformed pbind control criticality")
			}
			control.Critical = value[0] != 0
			position++
		}
		if position < len(encoded.Children) {
			value, err := syncConsumerPacketBytes(encoded.Children[position])
			if err != nil {
				return nil, errors.New("malformed pbind response control value")
			}
			control.Value = value
			control.HasValue = true
			position++
		}
		if position != len(encoded.Children) {
			return nil, errors.New("malformed pbind response control order")
		}
		controls = append(controls, control)
	}
	return controls, nil
}

func pbindResultReferrals(packet *ber.Packet) []string {
	if packet == nil || len(packet.Children) < 2 {
		return nil
	}
	operation := packet.Children[1]
	for _, child := range operation.Children[3:] {
		if !syncConsumerPacketIs(child, ber.ClassContext, ber.TypeConstructed, 3) {
			continue
		}
		referrals := make([]string, 0, len(child.Children))
		for _, encoded := range child.Children {
			value, err := syncConsumerPacketBytes(encoded)
			if err == nil {
				referrals = append(referrals, string(bytes.Clone(value)))
			}
		}
		return referrals
	}
	return nil
}
