package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func verifyCredentialsModuleName(module string) bool {
	switch filepath.Base(module) {
	case "vc", "vc.la", "vc.so":
		return true
	default:
		return false
	}
}

func loadVerifyCredentialsModule(reader storage.Reader) (bool, error) {
	enabled := false
	err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if !configurationSuffix.Equal(dn) && !configurationSuffix.AncestorOf(dn) {
			return nil
		}
		for _, value := range entry.Values("olcModuleLoad") {
			module, _, err := parseOpenLDAPModuleLoad(string(value))
			if err != nil {
				return err
			}
			enabled = enabled || verifyCredentialsModuleName(module)
		}
		return nil
	})
	return enabled, err
}

func (server *Server) handleVerifyCredentials(ctx context.Context, connection net.Conn,
	state *connectionState, message ldapwire.Message, request ldapwire.ExtendedRequest,
) error {
	fail := func(code ldapwire.ResultCode, diagnostic string) error {
		return server.writeLDAPResultResponse(connection, message.ID,
			ldapwire.ApplicationExtendedResponse, ldapwire.ResultError(code, diagnostic), "", nil, nil)
	}
	if frontendRestricts(state.runtime, restrictExtended) {
		return fail(ldapwire.ResultUnwillingToPerform, "operation restricted")
	}
	if !request.HasValue || len(request.Value) == 0 {
		return fail(ldapwire.ResultProtocolError, "empty request data field in VerifyCredentials exop")
	}
	decoded, err := ldapwire.DecodeVerifyCredentialsRequestValue(request.Value, request.HasValue)
	if err != nil {
		return fail(ldapwire.ResultProtocolError, "")
	}
	defer clear(decoded.Authentication.Simple)
	defer clear(decoded.Authentication.SASLCredentials)
	defer clear(decoded.Cookie)
	if _, err := parseRuntimeConnectionDN(state.runtime, decoded.Name); err != nil {
		return fail(ldapwire.ResultProtocolError, "")
	}
	if decoded.HasCookie {
		return fail(ldapwire.ResultProtocolError, "")
	}
	// Native VC maps get_ctrls2 decoding/registration failures to the outer
	// protocolError. Its ppolicy parser accepts repeated valueless requests.
	var policySeen bool
	innerControls := make([]ldapwire.Control, 0, len(decoded.Controls))
	for _, control := range decoded.Controls {
		if control.OID == passwordPolicyControlOID && !control.HasValue {
			if policySeen {
				continue
			}
			policySeen = true
		}
		innerControls = append(innerControls, control)
	}
	if _, failure := parseRequestControls(innerControls,
		bindRequestControlSupport(state.runtime)); failure != nil {
		return fail(ldapwire.ResultProtocolError, "")
	}
	if decoded.Authentication.IsSASL {
		result := ldapwire.ResultError(ldapwire.ResultAuthMethodNotSupported, "SASL not supported")
		value, err := ldapwire.EncodeVerifyCredentialsResponseValue(result, nil)
		if err != nil {
			return fail(ldapwire.ResultOther, "")
		}
		return server.writeLDAPResultResponse(connection, message.ID, ldapwire.ApplicationExtendedResponse,
			ldapwire.Result{Code: result.Code}, "", value, nil)
	}

	// OpenLDAP vc uses connection_fake_init2: the verification operation has
	// neither the caller's identity nor its transport or SASL security state.
	inner := newSASLBackendCredentialState(state.runtime)
	defer inner.metaTransports.close()
	defer clearBindCredentials(inner)
	defer clearSASLSession(inner)
	defer clearSearchSessions(inner)
	capture := &verifyCredentialsResponseCapture{}
	defer clear(capture.Bytes())
	bind := ldapwire.Message{ID: message.ID, Request: ldapwire.BindRequest{
		Version: 3, Name: decoded.Name, Authentication: decoded.Authentication,
	}, Controls: innerControls}
	closed, err := server.dispatch(ctx, capture, inner, bind)
	if err != nil || closed {
		return fail(ldapwire.ResultOther, "Verify Credentials authentication failed")
	}
	reader := bytes.NewReader(capture.Bytes())
	packet, err := ber.ReadPacket(reader)
	if err != nil || reader.Len() != 0 {
		return fail(ldapwire.ResultOther, "Verify Credentials returned an invalid Bind response")
	}
	defer clearSASLCredentialPacket(packet)
	result, err := parseSyncConsumerLDAPResult(packet, message.ID, ldapwire.ApplicationBindResponse)
	if err != nil {
		return fail(ldapwire.ResultOther, "Verify Credentials returned an invalid Bind response")
	}
	controls, err := decodePBindResponseControls(packet)
	if err != nil {
		return fail(ldapwire.ResultOther, "Verify Credentials returned invalid Bind controls")
	}
	innerResult := ldapwire.Result{Code: ldapwire.ResultCode(result.code), DiagnosticMessage: result.diagnosticMessage}
	value, err := ldapwire.EncodeVerifyCredentialsResponseValue(innerResult, controls)
	if err != nil {
		return fail(ldapwire.ResultOther, "Verify Credentials response exceeds its limits")
	}
	defer clear(value)
	return server.writeLDAPResultResponse(connection, message.ID, ldapwire.ApplicationExtendedResponse,
		ldapwire.Result{Code: innerResult.Code}, "", value, nil)
}

// Bind handlers write an ordinary LDAP response into a bounded local sink.
// It deliberately exposes no real socket or deadline operations to them.
type verifyCredentialsResponseCapture struct{ bytes.Buffer }

func (capture *verifyCredentialsResponseCapture) Write(value []byte) (int, error) {
	if int64(len(value)) > ldapwire.DefaultMaxMessageSize-int64(capture.Len()) {
		return 0, errors.New("Verify Credentials Bind response exceeds its size limit")
	}
	return capture.Buffer.Write(value)
}

func (*verifyCredentialsResponseCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (*verifyCredentialsResponseCapture) Close() error                     { return nil }
func (*verifyCredentialsResponseCapture) LocalAddr() net.Addr              { return nil }
func (*verifyCredentialsResponseCapture) RemoteAddr() net.Addr             { return nil }
func (*verifyCredentialsResponseCapture) SetDeadline(time.Time) error      { return nil }
func (*verifyCredentialsResponseCapture) SetReadDeadline(time.Time) error  { return nil }
func (*verifyCredentialsResponseCapture) SetWriteDeadline(time.Time) error { return nil }
