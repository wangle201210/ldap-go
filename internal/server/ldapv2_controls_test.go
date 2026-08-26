package server

import (
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const ldapV2TestControlOID = "1.2.3.4.5"

func TestLDAPv2ControlsDisconnect(t *testing.T) {
	address, stop := startLDAPGoV2ControlServer(t)
	t.Cleanup(stop)
	assertLDAPv2ControlObservations(t, observeLDAPv2Controls(t, address))
}

func TestOpenLDAPReferenceLDAPv2ControlsDisconnect(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"allow bind_v2",
		"",
		"",
	)
	t.Cleanup(stopReference)
	localAddress, stopLocal := startLDAPGoV2ControlServer(t)
	t.Cleanup(stopLocal)

	reference := observeLDAPv2Controls(t, trimLDAPURI(referenceURI))
	local := observeLDAPv2Controls(t, localAddress)
	assertLDAPv2ControlObservations(t, reference)
	if !reflect.DeepEqual(reference, local) {
		t.Fatalf("LDAPv2 controls mismatch\nOpenLDAP: %#v\nldap-go:  %#v", reference, local)
	}
}

type ldapV2ControlObservations struct {
	bindControl         unknownOperationObservation
	searchControl       unknownOperationObservation
	criticalSearch      unknownOperationObservation
	modifyControl       unknownOperationObservation
	emptyWrapper        unknownOperationObservation
	malformedControl    unknownOperationObservation
	malformedBind       unknownOperationObservation
	failedBindCode      int64
	failedBindSearch    unknownOperationObservation
	abandonClosed       bool
	unbindClosed        bool
	abandonWithoutCtlOK bool
	v3RebindCodes       [3]int64
}

func observeLDAPv2Controls(t *testing.T, address string) ldapV2ControlObservations {
	t.Helper()
	observation := ldapV2ControlObservations{
		bindControl: observeLDAPv2ControlledOperation(
			t,
			address,
			true,
			false,
			rawSimpleBindRequestVersion(2, "", ""),
		),
		searchControl: observeLDAPv2ControlledOperation(
			t,
			address,
			false,
			false,
			rawSyncSearchRequestFor(
				t,
				"dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
		),
		criticalSearch: observeLDAPv2ControlledOperation(
			t,
			address,
			false,
			true,
			rawSyncSearchRequestFor(
				t,
				"dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
		),
		modifyControl: observeLDAPv2ControlledOperation(
			t,
			address,
			false,
			false,
			rawModifyReplaceRequest(aliceDN, "cn", "must not change"),
		),
		emptyWrapper:        observeLDAPv2ControlEnvelope(t, address, false),
		malformedControl:    observeLDAPv2ControlEnvelope(t, address, true),
		malformedBind:       observeLDAPv2MalformedBindControl(t, address),
		abandonClosed:       observeLDAPv2ControlledAbandon(t, address),
		unbindClosed:        observeLDAPv2ControlledUnbind(t, address),
		abandonWithoutCtlOK: observeLDAPv2AbandonWithoutControls(t, address),
		v3RebindCodes:       observeLDAPv2ToV3RebindWithControl(t, address),
	}
	observation.failedBindCode, observation.failedBindSearch =
		observeFailedLDAPv2BindThenControl(t, address)
	return observation
}

func observeLDAPv2ControlledOperation(
	t *testing.T,
	address string,
	controlOnBind bool,
	critical bool,
	operation *ber.Packet,
) unknownOperationObservation {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	if !controlOnBind {
		response := sendRawLDAPOperation(
			t,
			connection,
			1,
			rawSimpleBindRequestVersion(2, "", ""),
		)
		assertRawLDAPEnvelope(
			t,
			response,
			1,
			ldapwire.ApplicationBindResponse,
			int64(ldapwire.ResultSuccess),
		)
	}
	messageID := int64(1)
	if !controlOnBind {
		messageID = 2
	}
	writeRawLDAPRequest(
		t,
		connection,
		messageID,
		operation,
		rawOIDControl(ldapV2TestControlOID, critical),
	)
	return readLDAPv2ControlDisconnect(t, connection)
}

func observeLDAPv2ControlEnvelope(
	t *testing.T,
	address string,
	malformed bool,
) unknownOperationObservation {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	assertRawLDAPEnvelope(
		t,
		sendRawLDAPOperation(t, connection, 1, rawSimpleBindRequestVersion(2, "", "")),
		1,
		ldapwire.ApplicationBindResponse,
		int64(ldapwire.ResultSuccess),
	)
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(2), "messageID",
	))
	message.AppendChild(rawSyncSearchRequestFor(
		t,
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		"(objectClass=*)",
	))
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	if malformed {
		wrapper.AppendChild(ber.NewSequence("malformed empty Control"))
	}
	message.AppendChild(wrapper)
	if err := ldapwire.Write(connection, message.Bytes()); err != nil {
		t.Fatalf("write LDAPv2 controls envelope: %v", err)
	}
	return readLDAPv2ControlDisconnect(t, connection)
}

func observeLDAPv2MalformedBindControl(
	t *testing.T,
	address string,
) unknownOperationObservation {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "messageID",
	))
	message.AppendChild(rawSimpleBindRequestVersion(2, "", ""))
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	wrapper.AppendChild(ber.NewSequence("malformed empty Control"))
	message.AppendChild(wrapper)
	if err := ldapwire.Write(connection, message.Bytes()); err != nil {
		t.Fatalf("write malformed LDAPv2 Bind control: %v", err)
	}
	return readLDAPv2ControlDisconnect(t, connection)
}

func observeFailedLDAPv2BindThenControl(
	t *testing.T,
	address string,
) (int64, unknownOperationObservation) {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	bind := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(
			2,
			"cn=admin,dc=example,dc=com",
			"wrong-password",
		),
	)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		rawOIDControl(ldapV2TestControlOID, false),
	)
	return rawLDAPResultCode(t, bind.Children[1]),
		readLDAPv2ControlDisconnect(t, connection)
}

func observeLDAPv2ControlledAbandon(t *testing.T, address string) bool {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	assertRawLDAPEnvelope(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			1,
			rawSimpleBindRequestVersion(2, "", ""),
		),
		1,
		ldapwire.ApplicationBindResponse,
		int64(ldapwire.ResultSuccess),
	)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawAbandonRequest(99),
		rawOIDControl(ldapV2TestControlOID, false),
	)
	var buffer [1]byte
	count, err := connection.Read(buffer[:])
	return count == 0 && (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed))
}

func observeLDAPv2ControlledUnbind(t *testing.T, address string) bool {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	assertRawLDAPEnvelope(
		t,
		sendRawLDAPOperation(t, connection, 1, rawSimpleBindRequestVersion(2, "", "")),
		1,
		ldapwire.ApplicationBindResponse,
		int64(ldapwire.ResultSuccess),
	)
	writeRawLDAPRequest(
		t,
		connection,
		2,
		ber.Encode(
			ber.ClassApplication,
			ber.TypePrimitive,
			ldapwire.ApplicationUnbindRequest,
			nil,
			"UnbindRequest",
		),
		rawOIDControl(ldapV2TestControlOID, true),
	)
	var buffer [1]byte
	count, err := connection.Read(buffer[:])
	return count == 0 && (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed))
}

func observeLDAPv2AbandonWithoutControls(t *testing.T, address string) bool {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	assertRawLDAPEnvelope(
		t,
		sendRawLDAPOperation(t, connection, 1, rawSimpleBindRequestVersion(2, "", "")),
		1,
		ldapwire.ApplicationBindResponse,
		int64(ldapwire.ResultSuccess),
	)
	writeRawLDAPRequest(t, connection, 2, rawAbandonRequest(99))
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawSimpleBindRequestVersion(3, "", ""),
	)
	return rawLDAPResultCode(t, response.Children[1]) == int64(ldapwire.ResultSuccess)
}

func observeLDAPv2ToV3RebindWithControl(
	t *testing.T,
	address string,
) [3]int64 {
	t.Helper()
	connection := dialLDAPv2ControlConnection(t, address)
	defer connection.Close()
	bindV2 := sendRawLDAPOperation(
		t,
		connection,
		1,
		rawSimpleBindRequestVersion(2, "", ""),
	)
	bindV3 := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawSimpleBindRequestVersion(3, "", ""),
		rawOIDControl(ldapV2TestControlOID, false),
	)
	whoami := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawExtendedRequest(whoAmIOID, nil, false),
	)
	return [3]int64{
		rawLDAPResultCode(t, bindV2.Children[1]),
		rawLDAPResultCode(t, bindV3.Children[1]),
		rawLDAPResultCode(t, whoami.Children[1]),
	}
}

func readLDAPv2ControlDisconnect(
	t *testing.T,
	connection net.Conn,
) unknownOperationObservation {
	t.Helper()
	packet, err := ber.ReadPacket(connection)
	if err != nil {
		t.Fatalf("ReadPacket(LDAPv2 notice): %v", err)
	}
	observation := unknownOperationObservation{}
	if len(packet.Children) != 2 {
		t.Fatalf("LDAPv2 notice = %#v", packet)
	}
	observation.messageID, err = ber.ParseInt64(packet.Children[0].Data.Bytes())
	if err != nil {
		t.Fatalf("parse LDAPv2 notice ID: %v", err)
	}
	operation := packet.Children[1]
	observation.tag = uint64(operation.Tag)
	observation.resultCode = rawLDAPResultCode(t, operation)
	observation.diagnostic = rawLDAPDiagnostic(packet)
	for _, child := range operation.Children[3:] {
		if child.ClassType == ber.ClassContext && child.Tag == 10 {
			observation.responseOID = string(child.Data.Bytes())
		}
	}
	var trailing [1]byte
	count, readErr := connection.Read(trailing[:])
	observation.closed = count == 0 &&
		(errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed))
	return observation
}

func assertLDAPv2ControlObservations(t *testing.T, got ldapV2ControlObservations) {
	t.Helper()
	want := func(messageID int64, tag uint64) unknownOperationObservation {
		return unknownOperationObservation{
			messageID:  messageID,
			tag:        tag,
			resultCode: int64(ldapwire.ResultProtocolError),
			diagnostic: "controls require LDAPv3",
			closed:     true,
		}
	}
	if got.bindControl != want(1, ldapwire.ApplicationBindResponse) ||
		got.searchControl != want(2, ldapwire.ApplicationSearchResultDone) ||
		got.criticalSearch != want(2, ldapwire.ApplicationSearchResultDone) ||
		got.modifyControl != want(2, ldapwire.ApplicationModifyResponse) ||
		got.emptyWrapper != want(2, ldapwire.ApplicationSearchResultDone) ||
		got.malformedControl != want(2, ldapwire.ApplicationSearchResultDone) ||
		got.malformedBind != want(1, ldapwire.ApplicationBindResponse) ||
		got.failedBindCode != int64(ldapwire.ResultInvalidCredentials) ||
		got.failedBindSearch != want(2, ldapwire.ApplicationSearchResultDone) ||
		!got.abandonClosed || !got.unbindClosed || !got.abandonWithoutCtlOK ||
		got.v3RebindCodes != [3]int64{} {
		t.Fatalf("LDAPv2 control observations = %#v", got)
	}
}

func dialLDAPv2ControlConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial(%s): %v", address, err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = connection.Close()
		t.Fatalf("SetDeadline(): %v", err)
	}
	return connection
}

func startLDAPGoV2ControlServer(t *testing.T) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	replaceGlobalConfigurationValues(t, store, "olcAllows", "bind_v2")
	return startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
}
