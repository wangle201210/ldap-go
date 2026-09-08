package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	maxLDAPClientURIListLength = 64 << 10
	maxLDAPClientURIs          = 32
)

type ldapClientEndpoint struct {
	parsedURI *url.URL
	dialURI   string
	tlsConfig *tls.Config
}

type ldapClientTransportError struct {
	err error
}

func (failure ldapClientTransportError) Error() string {
	return failure.err.Error()
}

func (failure ldapClientTransportError) Unwrap() error {
	return failure.err
}

func markLDAPClientTransportError(err error) error {
	if err == nil {
		return nil
	}
	return ldapClientTransportError{err: err}
}

func parseLDAPClientURIList(raw string) ([]string, error) {
	if len(raw) > maxLDAPClientURIListLength {
		return nil, fmt.Errorf("-H URI list exceeds %d bytes", maxLDAPClientURIListLength)
	}
	values := strings.FieldsFunc(raw, func(character rune) bool {
		return character == ',' || character == ' '
	})
	if len(values) == 0 {
		return nil, errors.New("-H requires at least one LDAP URI")
	}
	if len(values) > maxLDAPClientURIs {
		return nil, fmt.Errorf("-H supports at most %d LDAP URIs", maxLDAPClientURIs)
	}
	return values, nil
}

func parseLDAPSearchInitialURIList(raw string) ([]string, error) {
	if len(raw) > maxLDAPClientURIListLength {
		return nil, fmt.Errorf("-H URI list exceeds %d bytes", maxLDAPClientURIListLength)
	}
	values := make([]string, 0, 1)
	for _, field := range strings.Fields(raw) {
		field = strings.TrimLeft(field, ",")
		for field != "" {
			separator := ldapClientSearchURISeparator(field)
			if separator < 0 {
				values = append(values, field)
				break
			}
			values = append(values, field[:separator])
			field = field[separator+1:]
		}
	}
	if len(values) == 0 {
		return nil, errors.New("-H requires at least one LDAP URI")
	}
	if len(values) > maxLDAPClientURIs {
		return nil, fmt.Errorf("-H supports at most %d LDAP URIs", maxLDAPClientURIs)
	}
	return values, nil
}

func ldapClientSearchURISeparator(raw string) int {
	for index := strings.IndexByte(raw, ','); index >= 0; {
		remainder := raw[index+1:]
		if ldapClientURIUsesLDAPI(remainder) ||
			strings.HasPrefix(strings.ToLower(remainder), "ldap://") ||
			strings.HasPrefix(strings.ToLower(remainder), "ldaps://") {
			return index
		}
		next := strings.IndexByte(remainder, ',')
		if next < 0 {
			return -1
		}
		index += next + 1
	}
	return -1
}

func ldapClientURIListUsesOnlyLDAPI(raw string) bool {
	values, err := parseLDAPClientURIList(raw)
	if err != nil {
		return false
	}
	for _, value := range values {
		if !ldapClientURIUsesLDAPI(value) {
			return false
		}
	}
	return true
}

func ldapClientURIListSupportsTLS(raw string, startTLS bool) bool {
	values, err := parseLDAPClientURIList(raw)
	if err != nil {
		return false
	}
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || (!strings.EqualFold(parsed.Scheme, "ldaps") && !startTLS) {
			return false
		}
	}
	return true
}

func (options *ldapClientOptions) connectionConfigurations(
	flags *flag.FlagSet,
) ([]ldapClientEndpoint, error) {
	values, err := parseLDAPClientURIList(options.uri)
	if err != nil {
		return nil, err
	}
	tlsOptions := flagWasSet(flags, "tls-ca") || flagWasSet(flags, "tls-cert") ||
		flagWasSet(flags, "tls-key") || flagWasSet(flags, "tls-server-name")
	if tlsOptions && !options.tryStartTLS && !options.requireStartTLS {
		tlsEndpoint := false
		for _, value := range values {
			parsed, parseErr := url.Parse(value)
			if parseErr == nil && strings.EqualFold(parsed.Scheme, "ldaps") {
				tlsEndpoint = true
				break
			}
		}
		if !tlsEndpoint {
			return nil, errors.New("TLS options require ldaps://, -Z, or -ZZ")
		}
	}
	endpoints := make([]ldapClientEndpoint, 0, len(values))
	for index, value := range values {
		parsedURI, dialURI, tlsConfig, err := options.connectionConfigurationForURI(
			flags,
			value,
		)
		if err != nil {
			return nil, fmt.Errorf("-H URI %d: %w", index+1, err)
		}
		endpoints = append(endpoints, ldapClientEndpoint{
			parsedURI: parsedURI,
			dialURI:   dialURI,
			tlsConfig: tlsConfig,
		})
	}
	return endpoints, nil
}

func ldapClientFailoverRetryable(err error) bool {
	if err == nil {
		return false
	}
	var transportError ldapClientTransportError
	if errors.As(err, &transportError) {
		return true
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapError.ResultCode == ldap.ErrorNetwork
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) {
		return true
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return true
	}
	var recordHeaderError tls.RecordHeaderError
	if errors.As(err, &recordHeaderError) {
		return true
	}
	var certificateInvalidError x509.CertificateInvalidError
	if errors.As(err, &certificateInvalidError) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var unknownAuthorityError x509.UnknownAuthorityError
	return errors.As(err, &unknownAuthorityError)
}

func ldapClientFailoverError(attempts []error) error {
	if len(attempts) == 1 {
		return attempts[0]
	}
	return ldapClientURIListError{attempts: attempts}
}

type ldapClientURIListError struct {
	attempts []error
}

func (failure ldapClientURIListError) Error() string {
	messages := make([]string, 0, len(failure.attempts))
	for _, err := range failure.attempts {
		messages = append(messages, err.Error())
	}
	return "all LDAP URIs failed: " + strings.Join(messages, "; ")
}

func (failure ldapClientURIListError) Unwrap() error {
	if len(failure.attempts) == 0 {
		return nil
	}
	return failure.attempts[len(failure.attempts)-1]
}
