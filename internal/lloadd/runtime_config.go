package lloadd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
)

type RuntimeOption func(*RuntimeConfig) error

func WithLogger(logger *slog.Logger) RuntimeOption {
	return func(config *RuntimeConfig) error {
		config.Logger = logger
		return nil
	}
}

func WithDialContext(dial DialContextFunc) RuntimeOption {
	return func(config *RuntimeConfig) error {
		if dial == nil {
			return errors.New("lloadd dial function is nil")
		}
		config.DialContext = dial
		return nil
	}
}

func WithBackendTLS(config *tls.Config) RuntimeOption {
	return func(runtime *RuntimeConfig) error {
		if config == nil {
			return errors.New("lloadd backend TLS configuration is nil")
		}
		runtime.BackendTLS = config.Clone()
		return nil
	}
}

func New(config Config, options ...RuntimeOption) (*Proxy, error) {
	runtime, err := config.RuntimeConfig()
	if err != nil {
		return nil, err
	}
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("lloadd runtime option %d is nil", index)
		}
		if err := option(&runtime); err != nil {
			return nil, err
		}
	}
	return NewProxy(runtime)
}

func (config Config) RuntimeConfig() (RuntimeConfig, error) {
	if err := config.Validate(); err != nil {
		return RuntimeConfig{}, err
	}
	for _, feature := range config.Features {
		switch feature {
		case FeatureProxyAuthz:
		case FeatureVerifyCredentials, FeatureReadPause:
			return RuntimeConfig{}, fmt.Errorf("lloadd feature %q is not implemented", feature)
		}
	}
	if config.BindConf.KeepAlive.Set {
		return RuntimeConfig{}, errors.New("lloadd upstream keepalive configuration is not implemented")
	}
	if config.BindConf.TCPUserTimeout != 0 {
		return RuntimeConfig{}, errors.New("lloadd upstream TCP user timeout is not implemented")
	}
	if config.BindConf.TLS != (BindTLSConfig{}) {
		return RuntimeConfig{}, errors.New("lloadd config-driven upstream TLS is not implemented")
	}
	runtime := RuntimeConfig{
		ClientMaxMessageSize:   int64(config.MaxIncomingClient),
		UpstreamMaxMessageSize: int64(config.MaxIncomingUpstream),
		ClientMaxPending:       config.ClientMaxPending,
		WriteCoherence:         config.WriteCoherence,
		NetworkTimeout:         config.NetworkTimeout,
		IOTimeout:              config.IOTimeout,
		ProxyAuthz:             config.ProxyAuthz,
		RestrictExtended:       make(map[string]RuntimeRestriction),
		RestrictControls:       make(map[string]RuntimeRestriction),
		Bind: RuntimeBindConfig{
			Method:      string(config.BindConf.Method),
			DN:          config.BindConf.BindDN,
			Credentials: []byte(config.BindConf.Credentials),
			Timeout:     config.BindConf.Timeout,
		},
	}
	if config.BindConf.Method == BindNone {
		runtime.Bind.Method = ""
	}
	if config.BindConf.Method == BindSimple && config.BindConf.BindDN != "" {
		runtime.PrivilegedIdentity = "dn:" + config.BindConf.BindDN
	}
	if config.BindConf.Method == BindSASL {
		return RuntimeConfig{}, errors.New("lloadd service-account SASL bind is not implemented")
	}
	for _, restriction := range config.Restrictions {
		converted, err := runtimeRestriction(restriction.Action)
		if err != nil {
			return RuntimeConfig{}, err
		}
		switch restriction.Kind {
		case RestrictionExtendedOperation:
			runtime.RestrictExtended[restriction.OID] = converted
		case RestrictionControl:
			runtime.RestrictControls[restriction.OID] = converted
		}
	}
	for _, tier := range config.Tiers {
		runtimeTier := RuntimeTierConfig{Strategy: string(tier.Policy)}
		for _, backend := range tier.Backends {
			if backend.StartTLS == StartTLSOptional || backend.StartTLS == StartTLSCritical {
				return RuntimeConfig{}, fmt.Errorf(
					"backend %s requests StartTLS, which is not implemented",
					backend.URI,
				)
			}
			runtimeTier.Backends = append(runtimeTier.Backends, RuntimeBackendConfig{
				URI:                  backend.URI,
				RegularConnections:   backend.NumConns,
				BindConnections:      backend.BindConns,
				Retry:                backend.Retry,
				MaxPendingOperations: backend.MaxPendingOps,
				ConnectionMaxPending: backend.ConnMaxPending,
				Weight:               backend.Weight,
			})
		}
		runtime.Tiers = append(runtime.Tiers, runtimeTier)
	}
	if len(runtime.RestrictExtended) == 0 {
		runtime.RestrictExtended = nil
	}
	if len(runtime.RestrictControls) == 0 {
		runtime.RestrictControls = nil
	}
	return runtime, nil
}

func runtimeRestriction(action RestrictionAction) (RuntimeRestriction, error) {
	switch action {
	case RestrictionActionIgnore:
		return RuntimeRestrictionNone, nil
	case RestrictionActionWrite:
		return RuntimeRestrictionWrite, nil
	case RestrictionActionBackend:
		return RuntimeRestrictionBackend, nil
	case RestrictionActionConnection:
		return RuntimeRestrictionConnection, nil
	case RestrictionActionIsolate:
		return RuntimeRestrictionIsolate, nil
	case RestrictionActionReject:
		return RuntimeRestrictionReject, nil
	default:
		return RuntimeRestrictionNone, fmt.Errorf("unsupported lloadd restriction %q", action)
	}
}
