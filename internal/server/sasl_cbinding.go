package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/xdg-go/scram"
)

const saslCBindingAttribute = "olcSaslCBinding"
const saslCBindingOID = "1.3.6.1.4.1.4203.1.12.2.3.0.100"

type saslCBindingPolicy uint8

const (
	saslCBindingNone saslCBindingPolicy = iota
	saslCBindingUnique
	saslCBindingEndpoint
)

func parseSASLCBindingPolicy(value string) (saslCBindingPolicy, error) {
	// slapd stores ARG_STRING verbatim; cyrus.c uses strcasecmp, not a
	// tokenizer. Unknown strings are deliberately rejected instead of ignored.
	for index := range len(value) {
		if value[index] >= 0x80 {
			return saslCBindingNone, fmt.Errorf("%s: unsupported policy %q", saslCBindingAttribute, value)
		}
	}
	switch strings.ToLower(value) {
	case "none":
		return saslCBindingNone, nil
	case "tls-unique":
		return saslCBindingUnique, nil
	case "tls-endpoint":
		return saslCBindingEndpoint, nil
	default:
		return saslCBindingNone, fmt.Errorf("%s: unsupported policy %q", saslCBindingAttribute, value)
	}
}

func saslCBindingEntryPolicy(entry directory.Entry) (saslCBindingPolicy, error) {
	policy := saslCBindingNone
	seen := false
	for _, attribute := range entry.Attributes {
		base, _, options := strings.Cut(attribute.Description, ";")
		if !strings.EqualFold(base, saslCBindingAttribute) && base != saslCBindingOID {
			continue
		}
		if !isGlobalConfigurationEntry(entry.DN) {
			return policy, saslCBindingFailure(ldapwire.ResultObjectClassViolation,
				saslCBindingAttribute+" is only allowed on cn=config")
		}
		if options || seen || len(attribute.Values) != 1 {
			return policy, saslCBindingFailure(ldapwire.ResultConstraintViolation,
				saslCBindingAttribute+" requires one value without attribute options")
		}
		if len(attribute.Values[0]) == 0 {
			return policy, saslCBindingFailure(ldapwire.ResultInvalidAttributeSyntax,
				saslCBindingAttribute+" is an empty Directory String")
		}
		var err error
		policy, err = parseSASLCBindingPolicy(string(attribute.Values[0]))
		if err != nil {
			return policy, saslCBindingFailure(ldapwire.ResultConstraintViolation, err.Error())
		}
		seen = true
	}
	return policy, nil
}

func saslCBindingFailure(code ldapwire.ResultCode, diagnostic string) error {
	// Retain the diagnostic for startup/offline callers and the LDAP result
	// for online callers using asOperationFailure.
	return fmt.Errorf("%s: %w", diagnostic, operationFailed(code, diagnostic))
}

func validateSASLCBindingEntry(entry directory.Entry) error {
	_, err := saslCBindingEntryPolicy(entry)
	return err
}

func canonicalizeSASLCBindingAttribute(entry *directory.Entry) {
	for index := range entry.Attributes {
		attribute := &entry.Attributes[index]
		if strings.EqualFold(attribute.Description, saslCBindingAttribute) || attribute.Description == saslCBindingOID {
			attribute.Description = saslCBindingAttribute
		}
	}
}

// Capture after TLS completes, as connection_read calls slap_sasl_cbinding.
// The result belongs to the SASL context and must not follow later runtime
// snapshots. A rebind after SASL success discards it (see handleSASLBind).
// Plain connections capture at StartTLS.
func (server *Server) captureSASLCBinding(connection net.Conn) []byte {
	runtime := server.runtime.Load()
	if runtime == nil {
		return nil
	}
	return runtime.sasl.channelBinding.applicationData(connection)
}

func (policy saslCBindingPolicy) applicationData(connection net.Conn) []byte {
	switch policy {
	case saslCBindingEndpoint:
		data := connectionTLSChannelBinding(connection)
		if bytes.HasPrefix(data, []byte(saslSCRAMTLSEndpointPrefix)) &&
			len(data) > len(saslSCRAMTLSEndpointPrefix) {
			return data
		}
		clear(data)
	case saslCBindingUnique:
		// Use only Go's standard TLS provider. TLCP and arbitrary secure
		// transports cannot assert RFC 5929 Finished-message semantics.
		if secured, ok := connection.(*standardTLSConnection); ok {
			return saslTLSUniqueApplicationData(secured.ConnectionState())
		}
	}
	return nil
}

func saslTLSUniqueApplicationData(state tls.ConnectionState) []byte {
	// Go intentionally omits TLSUnique on TLS 1.3 and resumed sessions.
	// Do not substitute exporter data or the certificate hash for tls-unique.
	if !state.HandshakeComplete || state.Version != tls.VersionTLS12 ||
		state.DidResume || len(state.TLSUnique) != 12 {
		return nil
	}
	return append([]byte("tls-unique:"), state.TLSUnique...)
}

func saslSCRAMConnectionBinding(state *connectionState, first []byte) (scram.ChannelBinding, bool) {
	data := state.saslChannelBinding
	if len(data) == 0 {
		return scram.ChannelBinding{}, false
	}
	// OpenLDAP/Cyrus names its binding "ldap" and includes the TLS type
	// prefix in the authenticated data. Retain the existing standard SCRAM
	// forms as well; each uses only this connection's selected TLS policy.
	if bytes.HasPrefix(first, []byte("p=ldap,")) {
		return scram.ChannelBinding{Type: "ldap", Data: bytes.Clone(data)}, true
	}
	for _, bindingType := range []scram.ChannelBindingType{
		scram.ChannelBindingTLSUnique, scram.ChannelBindingTLSServerEndpoint,
	} {
		prefix := []byte(string(bindingType) + ":")
		if bytes.HasPrefix(data, prefix) && len(data) > len(prefix) {
			return scram.ChannelBinding{Type: bindingType, Data: bytes.Clone(data[len(prefix):])}, true
		}
	}
	return scram.ChannelBinding{}, false
}
