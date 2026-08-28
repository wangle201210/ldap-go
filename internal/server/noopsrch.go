package server

import (
	"context"
	"fmt"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type noOpSearchContextKey struct{}

type noOpSearchContext struct {
	sizeLimit int
}

type noOpSearchResponseConnection struct {
	net.Conn
	messageID  int64
	sizeLimit  int
	entries    int64
	references int64
}

func newNoOpSearchResponseConnection(
	connection net.Conn,
	messageID int64,
	sizeLimit int,
) *noOpSearchResponseConnection {
	return &noOpSearchResponseConnection{
		Conn:      connection,
		messageID: messageID,
		sizeLimit: sizeLimit,
	}
}

func withNoOpSearch(ctx context.Context, sizeLimit int) context.Context {
	return context.WithValue(ctx, noOpSearchContextKey{}, noOpSearchContext{
		sizeLimit: sizeLimit,
	})
}

func isNoOpSearch(ctx context.Context) bool {
	_, enabled := ctx.Value(noOpSearchContextKey{}).(noOpSearchContext)
	return enabled
}

func noOpSearchRequestedSize(ctx context.Context, fallback int) int {
	state, enabled := ctx.Value(noOpSearchContextKey{}).(noOpSearchContext)
	if !enabled {
		return fallback
	}
	return state.sizeLimit
}

func (connection *noOpSearchResponseConnection) Write(value []byte) (int, error) {
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return 0, fmt.Errorf("decode noopsrch response: %w", err)
	}
	if len(packet.Children) < 2 {
		return 0, fmt.Errorf("decode noopsrch response: malformed LDAP message")
	}
	messageID, err := ber.ParseInt64(packet.Children[0].Data.Bytes())
	if err != nil || messageID != connection.messageID {
		return 0, fmt.Errorf("noopsrch response message ID is invalid")
	}
	operation := packet.Children[1]
	switch uint64(operation.Tag) {
	case ldapwire.ApplicationSearchResultEntry:
		connection.entries++
		return len(value), nil
	case ldapwire.ApplicationSearchResultReference:
		connection.references++
		return len(value), nil
	case ldapwire.ApplicationSearchResultDone:
		if len(operation.Children) < 1 {
			return 0, fmt.Errorf("noopsrch SearchResultDone is malformed")
		}
		resultCode, err := ber.ParseInt64(operation.Children[0].Data.Bytes())
		if err != nil {
			return 0, fmt.Errorf("decode noopsrch result: %w", err)
		}
		controlResult := resultCode
		if connection.sizeLimit >= 0 && connection.sizeLimit > 0 &&
			connection.entries >= int64(connection.sizeLimit) {
			controlResult = int64(ldapwire.ResultSizeLimitExceeded)
		}
		encoded := encodeNoOpSearchResponseControl(
			packet,
			controlResult,
			connection.entries,
			connection.references,
		)
		if err := ldapwire.Write(connection.Conn, encoded); err != nil {
			return 0, err
		}
		return len(value), nil
	default:
		return connection.Conn.Write(value)
	}
}

func (connection *noOpSearchResponseConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface{ beginFinalResponse() error }); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}

func encodeNoOpSearchResponseControl(
	message *ber.Packet,
	result,
	entries,
	references int64,
) []byte {
	value := ber.NewSequence("No-op Search response")
	for _, number := range []int64{result, entries, references} {
		value.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			number,
			"",
		))
	}
	control := ber.NewSequence("Control")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		noOpSearchControlOID,
		"controlType",
	))
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		string(value.Bytes()),
		"controlValue",
	))
	encoded := ber.NewSequence("LDAPMessage")
	encoded.AppendChild(message.Children[0])
	encoded.AppendChild(message.Children[1])
	controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	if len(message.Children) >= 3 &&
		message.Children[2].ClassType == ber.ClassContext &&
		message.Children[2].Tag == 0 {
		for _, existing := range message.Children[2].Children {
			controls.AppendChild(existing)
		}
	}
	controls.AppendChild(control)
	encoded.AppendChild(controls)
	return encoded.Bytes()
}

func runtimeSupportsNoOpSearch(databases []runtimeDatabase) bool {
	for _, database := range databases {
		if database.noOpSearchOverlay {
			return true
		}
	}
	return false
}

func noOpSearchEnabledForRequest(
	runtime *runtimeState,
	request ldapwire.SearchRequest,
) bool {
	if runtime == nil {
		return false
	}
	for _, database := range runtime.databases {
		if databaseType(database.name) == "frontend" && database.noOpSearchOverlay {
			return true
		}
	}
	base, err := parseRuntimeConnectionDN(runtime, request.BaseDN)
	if err != nil || base.Depth() == 0 {
		return false
	}
	database := databaseForDN(runtime, base)
	return database != nil && database.noOpSearchOverlay
}

func withoutNoOpSearchControl(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != noOpSearchControlOID {
			filtered = append(filtered, control)
		}
	}
	return filtered
}
