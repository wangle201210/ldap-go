package server

import (
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type domainScopeConnection struct {
	net.Conn
	messageID int64
}

func (connection *domainScopeConnection) Write(value []byte) (int, error) {
	transformed, suppress, err := connection.transform(value)
	if err != nil {
		return 0, err
	}
	if suppress {
		return len(value), nil
	}
	if err := ldapwire.Write(connection.Conn, transformed); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (connection *domainScopeConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface{ beginFinalResponse() error }); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}

func (connection *domainScopeConnection) transform(
	value []byte,
) (transformed []byte, suppress bool, err error) {
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return nil, false, fmt.Errorf("decode domain-scope LDAP response: %w", err)
	}
	if len(packet.Children) < 2 {
		return value, false, nil
	}
	messageID, err := syncConsumerPacketInteger(packet.Children[0])
	if err != nil || messageID != connection.messageID ||
		packet.Children[1].ClassType != ber.ClassApplication {
		return value, false, nil
	}
	switch uint64(packet.Children[1].Tag) {
	case ldapwire.ApplicationSearchResultReference:
		return nil, true, nil
	case ldapwire.ApplicationSearchResultDone:
		result, err := chainLDAPResult(
			packet,
			messageID,
			ldapwire.ApplicationSearchResultDone,
		)
		if err != nil {
			return nil, false, fmt.Errorf("decode domain-scope search result: %w", err)
		}
		if result.Code != ldapwire.ResultReferral {
			return value, false, nil
		}
		controls, err := decodePBindResponseControls(packet)
		if err != nil {
			return nil, false, fmt.Errorf("decode domain-scope response controls: %w", err)
		}
		result.Code = ldapwire.ResultNoSuchObject
		result.Referrals = nil
		return ldapwire.EncodeSearchResultDone(messageID, result, controls), false, nil
	default:
		return value, false, nil
	}
}

func withoutDomainScopeControls(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != domainScopeControlOID &&
			control.OID != searchOptionsControlOID {
			filtered = append(filtered, control)
		}
	}
	return filtered
}
