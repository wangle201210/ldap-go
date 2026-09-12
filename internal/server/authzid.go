package server

import (
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	authzidRequestControlOID  = "2.16.840.1.113730.3.4.16"
	authzidResponseControlOID = "2.16.840.1.113730.3.4.15"
)

func runtimeAuthzidEnabled(runtime *runtimeState) bool {
	return runtime != nil && runtime.features.authzid
}

func bindRequestControlSupport(runtime *runtimeState) requestControlSupport {
	support := supportsPasswordPolicy
	if runtimeAuthzidEnabled(runtime) {
		support |= supportsAuthzid
	}
	return support
}

// prepareAuthzidBind runs after the LDAPv2 controls check and before Bind
// delegation or security checks. Consuming the request here makes the global
// overlay work with both local and delegated Bind implementations.
func prepareAuthzidBind(
	connection net.Conn,
	state *connectionState,
	message *ldapwire.Message,
) (net.Conn, *ldapwire.Result) {
	if message == nil || state == nil {
		return connection, nil
	}
	request, bind := message.Request.(ldapwire.BindRequest)
	if !bind ||
		!hasLDAPControl(message.Controls, authzidRequestControlOID) {
		return connection, nil
	}
	controls, failure := parseRequestControls(message.Controls, bindRequestControlSupport(state.runtime))
	if failure != nil {
		clearSockOverlayBindState(state)
		setAuditAuthorizationDN(connection, "")
		return connection, failure
	}
	if !controls.authzid {
		return connection, nil
	}
	remaining := make([]ldapwire.Control, 0, len(message.Controls)-1)
	for _, control := range message.Controls {
		if control.OID != authzidRequestControlOID {
			remaining = append(remaining, control)
		}
	}
	message.Controls = remaining
	return &authzidBindResponseConnection{
		Conn:      connection,
		state:     state,
		messageID: message.ID,
		sasl:      request.Authentication.IsSASL,
	}, nil
}

type authzidBindResponseConnection struct {
	net.Conn
	state     *connectionState
	messageID int64
	sasl      bool
	entryDN   string
}

// setAuthzidBindDN captures the effective DN from the same authentication
// transaction that verified the password (OpenLDAP's orb_edn).
func setAuthzidBindDN(connection net.Conn, dn string) {
	for depth := 0; connection != nil && depth < 16; depth++ {
		switch wrapped := connection.(type) {
		case *authzidBindResponseConnection:
			wrapped.entryDN = dn
			return
		case *lastBindResponseConnection:
			connection = wrapped.Conn
		case *sockOverlayResponseConnection:
			connection = wrapped.Conn
		default:
			return
		}
	}
}

func (connection *authzidBindResponseConnection) setAuditAuthorizationDN(value string) {
	setAuditAuthorizationDN(connection.Conn, value)
}

func (connection *authzidBindResponseConnection) setAuditSessionTracking(values []audit.SessionTracking) {
	setAuditSessionTracking(connection.Conn, values)
}

func (connection *authzidBindResponseConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface{ beginFinalResponse() error }); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}

func (connection *authzidBindResponseConnection) Write(value []byte) (int, error) {
	transformed, err := connection.transform(value)
	if err != nil {
		return 0, err
	}
	if err := ldapwire.Write(connection.Conn, transformed); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (connection *authzidBindResponseConnection) transform(value []byte) ([]byte, error) {
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return nil, fmt.Errorf("decode authzid Bind response: %w", err)
	}
	if len(packet.Children) < 2 || !syncConsumerPacketIs(
		packet.Children[1], ber.ClassApplication, ber.TypeConstructed, ldapwire.ApplicationBindResponse,
	) {
		return value, nil
	}
	messageID, err := syncConsumerPacketInteger(packet.Children[0])
	if err != nil || messageID != connection.messageID {
		return value, nil
	}
	response := packet.Children[1]
	if len(response.Children) < 3 {
		return nil, fmt.Errorf("malformed authzid Bind result")
	}
	code, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil {
		return nil, fmt.Errorf("decode authzid Bind result code: %w", err)
	}
	if ldapwire.ResultCode(code) != ldapwire.ResultSuccess {
		return value, nil
	}
	controls, err := decodePBindResponseControls(packet)
	if err != nil {
		return nil, err
	}
	result := ldapwire.Result{
		Code:              ldapwire.ResultSuccess,
		MatchedDN:         string(response.Children[1].Data.Bytes()),
		DiagnosticMessage: string(response.Children[2].Data.Bytes()),
		Referrals:         pbindResultReferrals(packet),
	}
	if failure := authzidDisclosureResult(connection.state, connection.sasl); failure != nil {
		result.Code = ldapwire.ResultConfidentialityRequired
		result.DiagnosticMessage = failure.DiagnosticMessage
	} else {
		identity := ""
		dn := connection.entryDN
		if dn == "" {
			dn = connection.state.boundDN
		}
		if dn != "" {
			identity = "dn:" + dn
		}
		controls = append(controls, ldapwire.Control{
			OID: authzidResponseControlOID, HasValue: true, Value: []byte(identity),
		})
	}
	var credentials []byte
	hasCredentials := false
	for _, child := range response.Children[3:] {
		if syncConsumerPacketIs(child, ber.ClassContext, ber.TypePrimitive, 7) {
			credentials = child.Data.Bytes()
			hasCredentials = true
		}
	}
	return ldapwire.EncodeSASLBindResponse(messageID, result, credentials, hasCredentials, controls), nil
}

func authzidDisclosureResult(state *connectionState, sasl bool) *ldapwire.Result {
	if state == nil || state.runtime == nil || state.boundDN == "" {
		return nil
	}
	var database *runtimeDatabase
	// SASL Bind stays on frontendDB; its authorization DN does not select a
	// data backend for this callback's restriction check.
	if !sasl {
		dn, err := parseRuntimeConnectionDN(state.runtime, state.boundDN)
		if err != nil {
			return controlResult(ldapwire.ResultConfidentialityRequired, "invalid authorization DN")
		}
		database = databaseForDN(state.runtime, dn)
	}
	// Native authzid checks restrictions as an Extended operation without
	// request data, which backend_check_restrictions treats as Modify.
	if failure := operationSecurityResult(state, database, policyUpdate); failure != nil {
		return failure
	}
	restricted := frontendRestricts(state.runtime, restrictModify)
	if database != nil {
		restricted = databaseRestricts(*database, restrictModify)
	}
	if restricted {
		return controlResult(ldapwire.ResultConfidentialityRequired, "operation restricted")
	}
	return nil
}
