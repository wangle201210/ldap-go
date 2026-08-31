package server

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const maximumAuditStringSize = 4096

type operationAuditObservation struct {
	mu                     sync.Mutex
	started                time.Time
	event                  audit.Event
	message                ldapwire.Message
	runtime                *runtimeState
	initialAuthorizationDN string
	result                 int
	hasResult              bool
	diagnostic             string
	entries                int
	referrals              []string
	responseControls       []ldapwire.Control
}

func (server *Server) newOperationAuditObservation(
	state *connectionState,
	message ldapwire.Message,
) *operationAuditObservation {
	return server.newAuditObservation(state, message, true)
}

func (server *Server) newImmediateAuditObservation(
	state *connectionState,
	message ldapwire.Message,
) *operationAuditObservation {
	return server.newAuditObservation(state, message, false)
}

func (server *Server) newAuditObservation(
	state *connectionState,
	message ldapwire.Message,
	includeIdentity bool,
) *operationAuditObservation {
	runtime := server.runtime.Load()
	if runtime == nil {
		runtime = state.runtime
	}
	if server.config.AuditSink == nil && !runtimeHasAccesslog(runtime) {
		return nil
	}
	identity := state.loadAuditIdentity()
	operation, targetDN, extendedOperation, mechanism, relatedID :=
		auditRequestMetadata(message)
	controls := make([]string, 0, len(message.Controls))
	for _, control := range message.Controls {
		controls = append(controls, auditSafeString(control.OID))
	}
	sort.Strings(controls)
	authenticationDN := ""
	authorizationDN := ""
	if includeIdentity {
		authenticationDN = auditSafeString(identity.boundDN)
		authorizationDN = authenticationDN
	}
	return &operationAuditObservation{
		started:                time.Now(),
		message:                message,
		runtime:                runtime,
		initialAuthorizationDN: identity.boundDN,
		event: audit.Event{
			ConnectionID:            state.connectionID,
			MessageID:               message.ID,
			RelatedMessageID:        relatedID,
			Operation:               operation,
			TargetDN:                auditSafeString(targetDN),
			ExtendedOperation:       auditSafeString(extendedOperation),
			AuthenticationDN:        authenticationDN,
			AuthorizationDN:         authorizationDN,
			AuthenticationMechanism: auditSafeString(mechanism),
			RemoteAddress:           auditRemoteAddress(state.connection),
			Secure:                  state.secure,
			SecurityStrengthFactor:  connectionOverallSSF(state),
			RequestControls:         controls,
		},
	}
}

func auditRequestMetadata(
	message ldapwire.Message,
) (operation, targetDN, extendedOperation, mechanism string, relatedID int64) {
	switch request := message.Request.(type) {
	case ldapwire.BindRequest:
		mechanism = "SIMPLE"
		if request.Authentication.IsSASL {
			mechanism = request.Authentication.SASLMechanism
		}
		return "bind", request.Name, "", mechanism, 0
	case ldapwire.SearchRequest:
		return "search", request.BaseDN, "", "", 0
	case ldapwire.AddRequest:
		return "add", request.Entry.DN, "", "", 0
	case ldapwire.ModifyRequest:
		return "modify", request.DN, "", "", 0
	case ldapwire.DeleteRequest:
		return "delete", request.DN, "", "", 0
	case ldapwire.ModifyDNRequest:
		return "modify_dn", request.DN, "", "", 0
	case ldapwire.CompareRequest:
		return "compare", request.DN, "", "", 0
	case ldapwire.AbandonRequest:
		return "abandon", "", "", "", request.MessageID
	case ldapwire.UnbindRequest:
		return "unbind", "", "", "", 0
	case ldapwire.ExtendedRequest:
		if request.Name == cancelOID {
			if target, err := ldapwire.DecodeCancelRequestValue(request.Value); err == nil {
				relatedID = target
			}
		}
		return "extended", "", request.Name, "", relatedID
	case ldapwire.UnsupportedRequest:
		return fmt.Sprintf("application_%d", request.Tag), "", "", "", 0
	default:
		return "unknown", "", "", "", 0
	}
}

func (observation *operationAuditObservation) observeResponse(encoded []byte) {
	if observation == nil {
		return
	}
	if operationTag, ok := monitorResponseTag(encoded); ok &&
		operationTag == ldapwire.ApplicationSearchResultEntry {
		observation.mu.Lock()
		observation.entries++
		observation.mu.Unlock()
		return
	}
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil || len(packet.Children) < 2 {
		return
	}
	operation := packet.Children[1]
	if len(operation.Children) == 0 {
		return
	}
	result := operation.Children[0]
	if result.ClassType != ber.ClassUniversal ||
		result.TagType != ber.TypePrimitive ||
		result.Tag != ber.TagEnumerated {
		return
	}
	code, err := ber.ParseInt64(result.Data.Bytes())
	if err != nil {
		return
	}
	diagnostic := ""
	if len(operation.Children) > 2 {
		diagnostic = operation.Children[2].Data.String()
	}
	var referrals []string
	for _, child := range operation.Children[3:] {
		if child.ClassType == ber.ClassContext && child.Tag == 3 {
			for _, referral := range child.Children {
				referrals = append(referrals, referral.Data.String())
			}
		}
	}
	responseControls := auditDecodeResponseControls(packet)
	observation.mu.Lock()
	observation.result = int(code)
	observation.hasResult = true
	observation.diagnostic = diagnostic
	observation.referrals = referrals
	observation.responseControls = responseControls
	observation.mu.Unlock()
}

func auditDecodeResponseControls(packet *ber.Packet) []ldapwire.Control {
	if packet == nil || len(packet.Children) < 3 {
		return nil
	}
	wrapper := packet.Children[2]
	if wrapper.ClassType != ber.ClassContext ||
		wrapper.TagType != ber.TypeConstructed || wrapper.Tag != 0 {
		return nil
	}
	controls := make([]ldapwire.Control, 0, len(wrapper.Children))
	for _, encoded := range wrapper.Children {
		if len(encoded.Children) < 1 || len(encoded.Children) > 3 {
			continue
		}
		control := ldapwire.Control{OID: encoded.Children[0].Data.String()}
		position := 1
		if position < len(encoded.Children) &&
			encoded.Children[position].ClassType == ber.ClassUniversal &&
			encoded.Children[position].Tag == ber.TagBoolean {
			value := encoded.Children[position].Data.Bytes()
			control.Critical = len(value) == 1 && value[0] != 0
			position++
		}
		if position < len(encoded.Children) {
			control.Value = bytes.Clone(encoded.Children[position].Data.Bytes())
			control.HasValue = true
		}
		controls = append(controls, control)
	}
	return controls
}

func (observation *operationAuditObservation) setResult(code ldapwire.ResultCode) {
	if observation == nil {
		return
	}
	observation.mu.Lock()
	observation.result = int(code)
	observation.hasResult = true
	observation.mu.Unlock()
}

func auditLDAPResultCode(encoded []byte) (int, bool) {
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil || len(packet.Children) < 2 {
		return 0, false
	}
	operation := packet.Children[1]
	if len(operation.Children) == 0 {
		return 0, false
	}
	result := operation.Children[0]
	if result.ClassType != ber.ClassUniversal ||
		result.TagType != ber.TypePrimitive ||
		result.Tag != ber.TagEnumerated {
		return 0, false
	}
	code, err := ber.ParseInt64(result.Data.Bytes())
	if err != nil {
		return 0, false
	}
	return int(code), true
}

func (observation *operationAuditObservation) setAuthorizationDN(value string) {
	if observation == nil {
		return
	}
	observation.mu.Lock()
	observation.event.AuthorizationDN = auditSafeString(value)
	observation.mu.Unlock()
}

func (observation *operationAuditObservation) setSessionTracking(
	values []audit.SessionTracking,
) {
	if observation == nil {
		return
	}
	cloned := append([]audit.SessionTracking(nil), values...)
	observation.mu.Lock()
	observation.event.SessionTracking = cloned
	observation.mu.Unlock()
}

func (server *Server) finishOperationAudit(
	observation *operationAuditObservation,
	state *connectionState,
	stop operationStopMode,
	operationErr error,
) {
	if observation == nil {
		return
	}
	observation.mu.Lock()
	event := observation.event
	hasResult := observation.hasResult
	result := observation.result
	observation.mu.Unlock()
	server.finishAccesslogObservation(
		observation,
		stop,
		operationErr,
	)

	event.Timestamp = observation.started.UTC()
	event.DurationMicros = time.Since(observation.started).Microseconds()
	if event.Operation == "bind" && hasResult && result == int(ldapwire.ResultSuccess) {
		identity := state.loadAuditIdentity()
		event.AuthorizationDN = auditSafeString(identity.boundDN)
		event.AuthenticationMechanism = auditSafeString(identity.authMechanism)
	}
	switch stop {
	case operationAbandoned:
		event.Outcome = "abandoned"
	case operationCanceled:
		code := int(ldapwire.ResultCanceled)
		event.ResultCode = &code
		event.Outcome = "canceled"
	case operationRunning:
		if hasResult {
			code := result
			event.ResultCode = &code
			event.Outcome = auditResultOutcome(result)
		} else if operationErr != nil {
			event.Outcome = "transport_error"
		} else {
			event.Outcome = "no_response"
		}
	}
	server.writeAuditEvent(event)
}

func auditResultOutcome(code int) string {
	switch ldapwire.ResultCode(code) {
	case ldapwire.ResultSuccess,
		ldapwire.ResultCompareFalse,
		ldapwire.ResultCompareTrue:
		return "success"
	case ldapwire.ResultSASLBindInProgress:
		return "in_progress"
	default:
		return "failure"
	}
}

func (server *Server) writeAuditEvent(event audit.Event) {
	if server.config.AuditSink == nil {
		return
	}
	if err := server.config.AuditSink.Record(event); err != nil {
		server.config.Logger.Error("write LDAP audit event", "error", err)
	}
}

func (server *Server) writeMalformedMessageAudit(state *connectionState) {
	if server.config.AuditSink == nil {
		return
	}
	code := int(ldapwire.ResultProtocolError)
	server.writeAuditEvent(audit.Event{
		Timestamp:              time.Now().UTC(),
		ConnectionID:           state.connectionID,
		Operation:              "malformed_message",
		RemoteAddress:          auditRemoteAddress(state.connection),
		Secure:                 state.secure,
		SecurityStrengthFactor: connectionOverallSSF(state),
		ResultCode:             &code,
		Outcome:                "failure",
	})
}

func auditRemoteAddress(connection net.Conn) string {
	if connection == nil || connection.RemoteAddr() == nil {
		return ""
	}
	return auditSafeString(connection.RemoteAddr().String())
}

func auditSafeString(value string) string {
	value = strings.ToValidUTF8(value, "\ufffd")
	if len(value) <= maximumAuditStringSize {
		return value
	}
	value = value[:maximumAuditStringSize]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

type auditResponseConnection struct {
	net.Conn
	observation *operationAuditObservation
}

func (connection *auditResponseConnection) Write(value []byte) (int, error) {
	written, err := connection.Conn.Write(value)
	if written == len(value) {
		connection.observation.observeResponse(value)
	}
	return written, err
}

func setAuditAuthorizationDN(connection net.Conn, value string) {
	if audited, ok := connection.(interface{ setAuditAuthorizationDN(string) }); ok {
		audited.setAuditAuthorizationDN(value)
	}
}

func setAuditSessionTracking(
	connection net.Conn,
	values []audit.SessionTracking,
) {
	if audited, ok := connection.(interface {
		setAuditSessionTracking([]audit.SessionTracking)
	}); ok {
		audited.setAuditSessionTracking(values)
	}
}
