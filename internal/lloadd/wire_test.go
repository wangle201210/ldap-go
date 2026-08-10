package lloadd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestReadFrameParsesMetadataAndPreservesRawBER(t *testing.T) {
	password := []byte("wire-test-password-do-not-render")
	bind := testSimpleBind("cn=admin,dc=example,dc=com", password)
	firstControl := testControl("1.2.840.113556.1.4.319", true, true, []byte{0x30, 0x03, 0x02, 0x01, 0x05})
	secondControl := testControl("1.3.6.1.1.12", false, false, nil)
	controls := encodeTLV(0xa0, joinBER(firstControl, secondControl))
	raw := encodeFrame(7, bind, controls)
	nextRaw := encodeFrame(8, encodeTLV(0x42, nil), nil)
	reader := bytes.NewBuffer(joinBER(raw, nextRaw))

	frame, err := ReadFrame(reader, int64(len(raw)))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if !bytes.Equal(frame.Raw, raw) {
		t.Fatal("ReadFrame() did not preserve the complete frame")
	}
	if frame.MessageID != 7 || frame.ProtocolTag != TagBindRequest {
		t.Fatalf("frame envelope = id %d tag %d", frame.MessageID, frame.ProtocolTag)
	}
	if !bytes.Equal(frame.ProtocolOp, bind) || !bytes.Equal(frame.ControlsRaw, controls) {
		t.Fatal("ReadFrame() did not preserve protocolOp or controls")
	}
	if frame.Bind == nil || frame.Bind.Version != 3 ||
		frame.Bind.DN != "cn=admin,dc=example,dc=com" ||
		frame.Bind.Authentication != BindAuthenticationSimple {
		t.Fatalf("Bind metadata = %#v", frame.Bind)
	}
	if len(frame.Controls) != 2 {
		t.Fatalf("controls = %d, want 2", len(frame.Controls))
	}
	if frame.Controls[0].OID != "1.2.840.113556.1.4.319" ||
		!frame.Controls[0].Critical || !frame.Controls[0].HasValue ||
		!bytes.Equal(frame.Controls[0].Raw, firstControl) {
		t.Fatalf("first control = %#v", frame.Controls[0])
	}
	if frame.Controls[1].OID != "1.3.6.1.1.12" ||
		frame.Controls[1].Critical || frame.Controls[1].HasValue ||
		!bytes.Equal(frame.Controls[1].Raw, secondControl) {
		t.Fatalf("second control = %#v", frame.Controls[1])
	}
	if reader.Len() != len(nextRaw) {
		t.Fatalf("ReadFrame() consumed %d bytes from the next frame", len(nextRaw)-reader.Len())
	}

	secret := string(password)
	formatted := []string{
		fmt.Sprintf("%v", frame),
		fmt.Sprintf("%+v", frame),
		fmt.Sprintf("%#v", frame),
		fmt.Sprintf("%s", frame.Raw),
		fmt.Sprintf("%x", frame.ProtocolOp),
		fmt.Sprintf("%#v", frame.Controls[0].Raw),
	}
	for _, rendered := range formatted {
		if strings.Contains(rendered, secret) {
			t.Fatalf("formatted frame exposed Bind password: %q", rendered)
		}
	}
}

func TestReadFrameParsesSASLBindAndExtendedRequestMetadata(t *testing.T) {
	saslSecret := []byte("plain-sasl-credentials")
	sasl := testSASLBind("", "PLAIN", true, saslSecret)
	frame := mustParseFrame(t, encodeFrame(11, sasl, nil))
	if frame.Bind == nil || frame.Bind.Authentication != BindAuthenticationSASL ||
		frame.Bind.SASLMechanism != "PLAIN" || !frame.Bind.HasSASLCredentials {
		t.Fatalf("SASL Bind metadata = %#v", frame.Bind)
	}
	if strings.Contains(fmt.Sprintf("%#v", frame), string(saslSecret)) ||
		strings.Contains(fmt.Sprintf("%s", frame.ProtocolOp), string(saslSecret)) {
		t.Fatal("SASL credentials were rendered")
	}

	withoutCredentials := mustParseFrame(t, encodeFrame(12, testSASLBind("", "GSSAPI", false, nil), nil))
	if withoutCredentials.Bind == nil || withoutCredentials.Bind.HasSASLCredentials {
		t.Fatalf("credential-free SASL metadata = %#v", withoutCredentials.Bind)
	}

	const passwordModifyOID = "1.3.6.1.4.1.4203.1.11.1"
	extendedValue := []byte("opaque-password-modify-value")
	extended := encodeTLV(0x77, joinBER(
		encodeTLV(0x80, []byte(passwordModifyOID)),
		encodeTLV(0x81, extendedValue),
	))
	extendedFrame := mustParseFrame(t, encodeFrame(13, extended, nil))
	if extendedFrame.ExtendedOID != passwordModifyOID || !extendedFrame.HasExtendedValue ||
		!bytes.Equal(extendedFrame.ExtendedValue, extendedValue) {
		t.Fatalf(
			"ExtendedRequest metadata = oid %q, hasValue %t, value bytes %d",
			extendedFrame.ExtendedOID,
			extendedFrame.HasExtendedValue,
			len(extendedFrame.ExtendedValue),
		)
	}
	if !bytes.Equal(extendedFrame.ProtocolOp, extended) {
		t.Fatal("ExtendedRequest was not byte-preserved")
	}
	if strings.Contains(fmt.Sprintf("%#v", extendedFrame), string(extendedValue)) ||
		strings.Contains(fmt.Sprintf("%s", extendedFrame.ExtendedValue), string(extendedValue)) {
		t.Fatal("ExtendedRequest value was rendered")
	}
	withoutValue := mustParseFrame(t, encodeFrame(
		14,
		encodeTLV(0x77, encodeTLV(0x80, []byte(passwordModifyOID))),
		nil,
	))
	if withoutValue.HasExtendedValue || withoutValue.ExtendedValue != nil {
		t.Fatalf("value-free ExtendedRequest metadata = %#v", withoutValue)
	}
}

func TestReadFrameLongLengthAndSizeLimit(t *testing.T) {
	operation := encodeTLV(0x63, bytes.Repeat([]byte{0x00}, 128))
	raw := encodeFrame(1, operation, nil)
	if raw[1]&0x80 == 0 || operation[1]&0x80 == 0 {
		t.Fatal("test frame did not exercise long-form BER lengths")
	}
	frame, err := ReadFrame(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("ReadFrame(long form) error = %v", err)
	}
	if !bytes.Equal(frame.Raw, raw) || !bytes.Equal(frame.ProtocolOp, operation) {
		t.Fatal("long-form frame was not preserved")
	}

	if _, err := ParseFrame(raw, int64(len(raw)-1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ParseFrame(over limit) error = %v", err)
	}

	payload := bytes.Repeat([]byte{0xaa}, 32)
	oversizedReader := bytes.NewReader(joinBER([]byte{0x30, 0x82, 0x10, 0x00}, payload))
	if _, err := ReadFrame(oversizedReader, 1024); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame(oversized) error = %v", err)
	}
	if oversizedReader.Len() != len(payload) {
		t.Fatalf("oversized ReadFrame consumed payload: %d bytes remain", oversizedReader.Len())
	}

	if _, err := ReadFrame(bytes.NewReader([]byte{0x30, 0x03, 0x02}), 64); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFrame(truncated body) error = %v", err)
	}
	overwideLength := joinBER(
		[]byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x05},
		[]byte{0x02, 0x01, 0x01, 0x42, 0x00},
	)
	if _, err := ReadFrame(bytes.NewReader(overwideLength), 64); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("ReadFrame(five-octet outer length) error = %v", err)
	}
}

func TestParseFrameRejectsMalformedBER(t *testing.T) {
	validContent := []byte{0x02, 0x01, 0x01, 0x42, 0x00}
	invalidOIDControl := encodeTLV(0xa0, testControl("01.2", false, false, nil))
	badCriticality := encodeTLV(0xa0, encodeTLV(0x30, joinBER(
		encodeTLV(0x04, []byte("1.2.3")),
		encodeTLV(0x01, []byte{0xff, 0x00}),
	)))

	tests := map[string][]byte{
		"wrong outer tag":         append([]byte{0x31, 0x05}, validContent...),
		"indefinite outer length": {0x30, 0x80},
		"outer length over four octets": append(
			[]byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x05},
			validContent...,
		),
		"truncated 128-byte value":  {0x30, 0x82, 0x00, 0x80},
		"truncated long length":     {0x30, 0x82, 0x01},
		"trailing frame byte":       append(append([]byte{0x30, 0x05}, validContent...), 0x00),
		"missing message ID":        {0x30, 0x02, 0x42, 0x00},
		"negative message ID":       encodeTLV(0x30, joinBER([]byte{0x02, 0x01, 0xff}, encodeTLV(0x42, nil))),
		"non-minimal message ID":    encodeTLV(0x30, joinBER([]byte{0x02, 0x02, 0x00, 0x01}, encodeTLV(0x42, nil))),
		"message ID above maximum":  encodeTLV(0x30, joinBER([]byte{0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00}, encodeTLV(0x42, nil))),
		"protocolOp wrong class":    encodeTLV(0x30, joinBER(encodeTLV(0x02, []byte{1}), encodeTLV(0x04, nil))),
		"SearchRequest primitive":   encodeFrame(1, encodeTLV(0x43, nil), nil),
		"UnbindRequest constructed": encodeFrame(1, encodeTLV(0x62, nil), nil),
		"unexpected third element": encodeTLV(0x30, joinBER(
			encodeTLV(0x02, []byte{1}),
			encodeTLV(0x42, nil),
			encodeTLV(0x04, nil),
		)),
		"empty controls":              encodeFrame(1, encodeTLV(0x42, nil), encodeTLV(0xa0, nil)),
		"invalid control OID":         encodeFrame(1, encodeTLV(0x42, nil), invalidOIDControl),
		"invalid control criticality": encodeFrame(1, encodeTLV(0x42, nil), badCriticality),
		"zero Bind version": encodeFrame(1, encodeTLV(0x60, joinBER(
			encodeTLV(0x02, []byte{0}),
			encodeTLV(0x04, nil),
			encodeTLV(0x80, nil),
		)), nil),
		"missing Bind authentication": encodeFrame(1, encodeTLV(0x60, joinBER(
			encodeTLV(0x02, []byte{3}),
			encodeTLV(0x04, nil),
		)), nil),
		"missing ExtendedRequest OID": encodeFrame(1, encodeTLV(0x77, nil), nil),
		"invalid ExtendedRequest OID": encodeFrame(1, encodeTLV(0x77,
			encodeTLV(0x80, []byte("1.bad"))), nil),
		"zero Abandon target": encodeFrame(1, encodeTLV(0x50, []byte{0}), nil),
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFrame(raw, 4096); !errors.Is(err, ErrMalformedFrame) {
				t.Fatalf("ParseFrame() error = %v, want ErrMalformedFrame", err)
			}
		})
	}
}

func TestOpenLDAPLongFormBERLengths(t *testing.T) {
	bindContent := joinBER(
		encodeTLV(0x02, []byte{3}),
		encodeTLV(0x04, []byte("cn=Manager,dc=example,dc=com")),
		encodeTLV(0x80, []byte("secret")),
	)
	bind := joinBER(
		[]byte{0x60, 0x84, 0x00, 0x00, 0x00, byte(len(bindContent))},
		bindContent,
	)
	messageContent := joinBER(encodeTLV(0x02, []byte{1}), bind)
	raw := joinBER(
		[]byte{0x30, 0x84, 0x00, 0x00, 0x00, byte(len(messageContent))},
		messageContent,
	)

	frame, err := ReadFrame(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("ReadFrame(OpenLDAP long-form lengths) error = %v", err)
	}
	if frame.MessageID != 1 || frame.Bind == nil || frame.Bind.Version != 3 ||
		frame.Bind.DN != "cn=Manager,dc=example,dc=com" {
		t.Fatalf("OpenLDAP Bind frame = %#v", frame)
	}
	if !bytes.Equal(frame.Raw, raw) || !bytes.Equal(frame.ProtocolOp, bind) {
		t.Fatal("OpenLDAP long-form BER was not byte-preserved")
	}
	rewritten, err := RewriteMessageID(frame, 257)
	if err != nil {
		t.Fatalf("RewriteMessageID(OpenLDAP frame) error = %v", err)
	}
	rewrittenFrame := mustParseFrame(t, rewritten)
	if rewrittenFrame.MessageID != 257 || !bytes.Equal(rewrittenFrame.ProtocolOp, bind) {
		t.Fatalf("rewritten OpenLDAP frame = %#v", rewrittenFrame)
	}
}

func TestRewriteMessageIDPreservesOpaqueBytesAcrossIntegerBoundaries(t *testing.T) {
	operation := encodeTLV(0x63, bytes.Repeat([]byte{0x5a}, 122))
	control := testControl("1.2.3.4", false, true, []byte{0x00, 0xff, 0x80})
	controls := encodeTLV(0xa0, control)
	originalRaw := encodeFrame(127, operation, controls)
	original := mustParseFrame(t, originalRaw)

	tests := []struct {
		messageID int64
		integer   []byte
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{1, []byte{0x02, 0x01, 0x01}},
		{127, []byte{0x02, 0x01, 0x7f}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}},
		{255, []byte{0x02, 0x02, 0x00, 0xff}},
		{256, []byte{0x02, 0x02, 0x01, 0x00}},
		{32767, []byte{0x02, 0x02, 0x7f, 0xff}},
		{32768, []byte{0x02, 0x03, 0x00, 0x80, 0x00}},
		{MaxMessageID, []byte{0x02, 0x04, 0x7f, 0xff, 0xff, 0xff}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprint(test.messageID), func(t *testing.T) {
			rewritten, err := RewriteMessageID(original, test.messageID)
			if err != nil {
				t.Fatalf("RewriteMessageID() error = %v", err)
			}
			parsed := mustParseFrame(t, rewritten)
			if parsed.MessageID != test.messageID {
				t.Fatalf("MessageID = %d", parsed.MessageID)
			}
			if !bytes.Equal(parsed.ProtocolOp, operation) || !bytes.Equal(parsed.ControlsRaw, controls) {
				t.Fatal("RewriteMessageID changed opaque BER elements")
			}
			if !bytes.Equal(testMessageIDElement(t, rewritten), test.integer) {
				t.Fatalf("messageID BER = %x, want %x", testMessageIDElement(t, rewritten), test.integer)
			}
		})
	}
	if !bytes.Equal(original.Raw, originalRaw) {
		t.Fatal("RewriteMessageID mutated the source frame")
	}

	withoutControls := mustParseFrame(t, encodeFrame(127, operation, nil))
	rewritten, err := RewriteMessageID(withoutControls, 128)
	if err != nil {
		t.Fatalf("RewriteMessageID(boundary) error = %v", err)
	}
	if len(rewritten) < 3 || !bytes.Equal(rewritten[:3], []byte{0x30, 0x81, 0x80}) {
		t.Fatalf("outer BER length boundary = %x", rewritten[:min(4, len(rewritten))])
	}

	for _, invalid := range []int64{-1, MaxMessageID + 1} {
		if _, err := RewriteMessageID(original, invalid); !errors.Is(err, ErrInvalidMessageID) {
			t.Fatalf("RewriteMessageID(%d) error = %v", invalid, err)
		}
	}
}

func TestRewriteAbandonTargetAndOuterMessageID(t *testing.T) {
	control := testControl("1.2.3", false, false, nil)
	controls := encodeTLV(0xa0, control)
	frame := mustParseFrame(t, encodeFrame(127, encodeTLV(0x50, []byte{0x7f}), controls))
	if !frame.HasAbandonTarget || frame.AbandonTarget != 127 {
		t.Fatalf("Abandon target = %d, present %t", frame.AbandonTarget, frame.HasAbandonTarget)
	}

	outerOnly, err := RewriteMessageID(frame, 128)
	if err != nil {
		t.Fatalf("RewriteMessageID(Abandon) error = %v", err)
	}
	outerFrame := mustParseFrame(t, outerOnly)
	if outerFrame.MessageID != 128 || outerFrame.AbandonTarget != 127 ||
		!bytes.Equal(outerFrame.ProtocolOp, frame.ProtocolOp) {
		t.Fatalf("outer-only rewrite = %#v", outerFrame)
	}

	targetOnly, err := RewriteAbandonTarget(frame, 128)
	if err != nil {
		t.Fatalf("RewriteAbandonTarget() error = %v", err)
	}
	targetFrame := mustParseFrame(t, targetOnly)
	if targetFrame.MessageID != 127 || targetFrame.AbandonTarget != 128 ||
		!bytes.Equal(targetFrame.ControlsRaw, controls) {
		t.Fatalf("target-only rewrite = %#v", targetFrame)
	}

	both, err := RewriteAbandonMessageIDs(frame, 32768, 65536)
	if err != nil {
		t.Fatalf("RewriteAbandonMessageIDs() error = %v", err)
	}
	bothFrame := mustParseFrame(t, both)
	if bothFrame.MessageID != 32768 || bothFrame.AbandonTarget != 65536 ||
		!bytes.Equal(bothFrame.ControlsRaw, controls) {
		t.Fatalf("combined rewrite = %#v", bothFrame)
	}

	notAbandon := mustParseFrame(t, encodeFrame(1, encodeTLV(0x42, nil), nil))
	if _, err := RewriteAbandonTarget(notAbandon, 2); !errors.Is(err, ErrNotAbandonRequest) {
		t.Fatalf("RewriteAbandonTarget(non-Abandon) error = %v", err)
	}
	if _, err := RewriteAbandonTarget(frame, 0); !errors.Is(err, ErrInvalidMessageID) {
		t.Fatalf("RewriteAbandonTarget(0) error = %v", err)
	}
}

func TestEncodeAbandonRequest(t *testing.T) {
	encoded, err := EncodeAbandonRequest(17, 23)
	if err != nil {
		t.Fatalf("EncodeAbandonRequest(): %v", err)
	}
	frame, err := ParseFrame(encoded, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("ParseFrame(): %v", err)
	}
	if frame.MessageID != 17 || frame.AbandonTarget != 23 || len(frame.Controls) != 0 {
		t.Fatalf("encoded Abandon = %s", frame)
	}
	for _, ids := range [][2]int64{{0, 1}, {1, 0}, {-1, 1}} {
		if _, err := EncodeAbandonRequest(ids[0], ids[1]); err == nil {
			t.Fatalf("EncodeAbandonRequest(%d, %d) succeeded", ids[0], ids[1])
		}
	}
}

func TestPrependProxyAuthzPreservesAndOrdersControls(t *testing.T) {
	operation := encodeTLV(0x63, []byte{0xde, 0xad, 0xbe, 0xef})
	existing := testControl("1.2.3.4", false, true, []byte{0x00, 0x80, 0xff})
	controls := encodeTLV(0xa0, existing)
	frame := mustParseFrame(t, encodeFrame(9, operation, controls))
	authzID := []byte("dn:uid=alice,dc=example,dc=com")

	proxied, err := PrependProxyAuthz(frame, authzID)
	if err != nil {
		t.Fatalf("PrependProxyAuthz() error = %v", err)
	}
	parsed := mustParseFrame(t, proxied)
	if parsed.MessageID != frame.MessageID || !bytes.Equal(parsed.ProtocolOp, operation) {
		t.Fatal("PrependProxyAuthz changed messageID or protocolOp")
	}
	if len(parsed.Controls) != 2 {
		t.Fatalf("controls = %d, want 2", len(parsed.Controls))
	}
	if parsed.Controls[0].OID != ProxyAuthzControlOID ||
		!parsed.Controls[0].Critical || !parsed.Controls[0].HasValue {
		t.Fatalf("ProxyAuthz control = %#v", parsed.Controls[0])
	}
	if value := testControlValue(t, parsed.Controls[0].Raw); !bytes.Equal(value, authzID) {
		t.Fatalf("ProxyAuthz value = %q", value)
	}
	if !bytes.Equal(parsed.Controls[1].Raw, existing) {
		t.Fatal("existing control bytes changed or were not appended after ProxyAuthz")
	}

	withoutControls := mustParseFrame(t, encodeFrame(10, operation, nil))
	proxied, err = PrependProxyAuthz(withoutControls, nil)
	if err != nil {
		t.Fatalf("PrependProxyAuthz(no controls) error = %v", err)
	}
	parsed = mustParseFrame(t, proxied)
	if len(parsed.Controls) != 1 || parsed.Controls[0].OID != ProxyAuthzControlOID ||
		!parsed.Controls[0].HasValue || len(testControlValue(t, parsed.Controls[0].Raw)) != 0 {
		t.Fatalf("anonymous ProxyAuthz control = %#v", parsed.Controls)
	}

	existingProxy := testControl(ProxyAuthzControlOID, true, true, []byte("dn:uid=bob"))
	duplicateFrame := mustParseFrame(t, encodeFrame(11, operation, encodeTLV(0xa0, existingProxy)))
	proxied, err = PrependProxyAuthz(duplicateFrame, authzID)
	if err != nil {
		t.Fatalf("PrependProxyAuthz(duplicate) error = %v", err)
	}
	parsed = mustParseFrame(t, proxied)
	if len(parsed.Controls) != 2 || parsed.Controls[0].OID != ProxyAuthzControlOID ||
		parsed.Controls[1].OID != ProxyAuthzControlOID || !bytes.Equal(parsed.Controls[1].Raw, existingProxy) {
		t.Fatalf("duplicate ProxyAuthz controls = %#v", parsed.Controls)
	}

	if _, err := PrependProxyAuthz(frame, []byte{0xff}); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("PrependProxyAuthz(invalid UTF-8) error = %v", err)
	}
}

func TestIsFinalResponseAndResultCode(t *testing.T) {
	tests := []struct {
		name      string
		operation []byte
		final     bool
		code      *ResultCode
	}{
		{"search entry", encodeTLV(0x64, nil), false, nil},
		{"search reference", encodeTLV(0x73, nil), false, nil},
		{"intermediate response", encodeTLV(0x79, nil), false, nil},
		{"SASL Bind in progress", testLDAPResultOperation(TagBindResponse, ResultSASLBindInProgress, "continue"), false, resultCodePointer(ResultSASLBindInProgress)},
		{"successful Bind", testLDAPResultOperation(TagBindResponse, ResultSuccess, ""), true, resultCodePointer(ResultSuccess)},
		{"search done", testLDAPResultOperation(TagSearchResultDone, ResultSuccess, ""), true, resultCodePointer(ResultSuccess)},
		{"extended response", testLDAPResultOperation(TagExtendedResponse, ResultUnavailable, "offline"), true, resultCodePointer(ResultUnavailable)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame := mustParseFrame(t, encodeFrame(4, test.operation, nil))
			if got := IsFinalResponse(frame); got != test.final || frame.IsFinalResponse() != test.final {
				t.Fatalf("IsFinalResponse() = %t, want %t", got, test.final)
			}
			if test.code == nil {
				if frame.ResultCode != nil {
					t.Fatalf("ResultCode = %d, want absent", *frame.ResultCode)
				}
			} else if frame.ResultCode == nil || *frame.ResultCode != *test.code {
				t.Fatalf("ResultCode = %v, want %d", frame.ResultCode, *test.code)
			}
		})
	}
}

func TestEncodeErrorResponseMapsRequestTags(t *testing.T) {
	tests := []struct {
		request  uint64
		response uint64
		code     ResultCode
	}{
		{TagBindRequest, TagBindResponse, ResultProtocolError},
		{TagSearchRequest, TagSearchResultDone, ResultBusy},
		{TagModifyRequest, TagModifyResponse, ResultUnavailable},
		{TagAddRequest, TagAddResponse, ResultOther},
		{TagDeleteRequest, TagDeleteResponse, ResultBusy},
		{TagModifyDNRequest, TagModifyDNResponse, ResultUnavailable},
		{TagCompareRequest, TagCompareResponse, ResultProtocolError},
		{TagExtendedRequest, TagExtendedResponse, ResultOther},
		{0x63, TagSearchResultDone, ResultBusy},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d", test.request), func(t *testing.T) {
			encoded, err := EncodeErrorResponse(128, test.request, test.code, "lloadd rejected request")
			if err != nil {
				t.Fatalf("EncodeErrorResponse() error = %v", err)
			}
			frame := mustParseFrame(t, encoded)
			if frame.MessageID != 128 || frame.ProtocolTag != test.response ||
				frame.ResultCode == nil || *frame.ResultCode != test.code {
				t.Fatalf("encoded response = %#v", frame)
			}
			if diagnostic := testLDAPResultDiagnostic(t, frame.ProtocolOp); diagnostic != "lloadd rejected request" {
				t.Fatalf("diagnostic = %q", diagnostic)
			}
		})
	}

	for _, request := range []uint64{TagUnbindRequest, TagAbandonRequest, 30} {
		if _, err := EncodeErrorResponse(1, request, ResultBusy, "busy"); !errors.Is(err, ErrUnsupportedRequest) {
			t.Fatalf("EncodeErrorResponse(tag %d) error = %v", request, err)
		}
	}
	for _, messageID := range []int64{-1, MaxMessageID + 1} {
		if _, err := EncodeErrorResponse(messageID, TagSearchRequest, ResultBusy, "busy"); !errors.Is(err, ErrInvalidMessageID) {
			t.Fatalf("EncodeErrorResponse(messageID %d) error = %v", messageID, err)
		}
	}
	if _, err := EncodeErrorResponse(1, TagSearchRequest, -1, "busy"); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("EncodeErrorResponse(negative code) error = %v", err)
	}
	if _, err := EncodeErrorResponse(1, TagSearchRequest, ResultBusy, string([]byte{0xff})); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("EncodeErrorResponse(invalid diagnostic) error = %v", err)
	}
}

func TestControlOptionalFieldsAndBERLengths(t *testing.T) {
	explicitFalseWithEmptyValue := encodeTLV(0x30, joinBER(
		encodeTLV(0x04, []byte("1.2.3")),
		encodeTLV(0x01, []byte{0x00}),
		encodeTLV(0x04, nil),
	))
	frame := mustParseFrame(t, encodeFrame(1, encodeTLV(0x42, nil), encodeTLV(0xa0, explicitFalseWithEmptyValue)))
	if len(frame.Controls) != 1 || frame.Controls[0].Critical || !frame.Controls[0].HasValue {
		t.Fatalf("control optional fields = %#v", frame.Controls)
	}

	nonMinimalOIDLength := []byte{0x30, 0x06, 0x04, 0x81, 0x03, '1', '.', '2'}
	raw := encodeFrame(1, encodeTLV(0x42, nil), encodeTLV(0xa0, nonMinimalOIDLength))
	parsed, err := ParseFrame(raw, 1024)
	if err != nil {
		t.Fatalf("ParseFrame(BER long-form nested length) error = %v", err)
	}
	if len(parsed.Controls) != 1 || parsed.Controls[0].OID != "1.2" {
		t.Fatalf("long-form control = %#v", parsed.Controls)
	}
}

func TestBERFrameCodecAdapter(t *testing.T) {
	control := testControl("1.2.3", true, true, []byte{0x01})
	raw := encodeFrame(
		17,
		testSASLBind("uid=alice,dc=example", "PLAIN", true, []byte("secret")),
		encodeTLV(0xa0, control),
	)
	codec := berFrameCodec{}
	projected, err := codec.Read(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("berFrameCodec.Read() error = %v", err)
	}
	if projected.MessageID != 17 || projected.ProtocolTag != TagBindRequest ||
		projected.BindVersion != 3 || projected.BindDN != "uid=alice,dc=example" ||
		!projected.BindSASL || projected.BindMechanism != "PLAIN" ||
		len(projected.Controls) != 1 || projected.Controls[0] != "1.2.3" {
		t.Fatalf("projected frame = %s", projected)
	}
	if strings.Contains(projected.String(), "secret") {
		t.Fatal("proxy frame String exposed credentials")
	}

	proxied, err := codec.PrependProxyAuthz(projected, 128, []byte("dn:uid=alice,dc=example"))
	if err != nil {
		t.Fatalf("berFrameCodec.PrependProxyAuthz() error = %v", err)
	}
	proxiedFrame := mustParseFrame(t, proxied)
	if proxiedFrame.MessageID != 128 || len(proxiedFrame.Controls) != 2 ||
		proxiedFrame.Controls[0].OID != ProxyAuthzControlOID ||
		proxiedFrame.Controls[1].OID != "1.2.3" {
		t.Fatalf("codec ProxyAuthz frame = %#v", proxiedFrame)
	}

	abandonRaw := encodeFrame(18, encodeTLV(0x50, []byte{0x11}), nil)
	abandon, err := codec.Read(bytes.NewReader(abandonRaw), int64(len(abandonRaw)))
	if err != nil {
		t.Fatalf("berFrameCodec.Read(Abandon) error = %v", err)
	}
	rewritten, err := codec.RewriteAbandon(abandon, 129, 130)
	if err != nil {
		t.Fatalf("berFrameCodec.RewriteAbandon() error = %v", err)
	}
	rewrittenFrame := mustParseFrame(t, rewritten)
	if rewrittenFrame.MessageID != 129 || rewrittenFrame.AbandonTarget != 130 {
		t.Fatalf("codec Abandon rewrite = %#v", rewrittenFrame)
	}

	cancelRaw, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: 19,
		Request: ldapwire.ExtendedRequest{
			Name:     clientCancelOID,
			Value:    ldapwire.EncodeCancelRequestValue(17),
			HasValue: true,
		},
		Controls: []ldapwire.Control{{OID: "1.2.3"}},
	})
	if err != nil {
		t.Fatalf("encode Cancel: %v", err)
	}
	cancel, err := codec.Read(bytes.NewReader(cancelRaw), int64(len(cancelRaw)))
	if err != nil {
		t.Fatalf("berFrameCodec.Read(Cancel) error = %v", err)
	}
	rewritten, err = codec.RewriteExtendedRequestValue(
		cancel,
		131,
		ldapwire.EncodeCancelRequestValue(130),
	)
	if err != nil {
		t.Fatalf("berFrameCodec.RewriteExtendedRequestValue() error = %v", err)
	}
	rewrittenFrame = mustParseFrame(t, rewritten)
	rewrittenTarget, err := ldapwire.DecodeCancelRequestValue([]byte(rewrittenFrame.ExtendedValue))
	if err != nil {
		t.Fatalf("decode rewritten Cancel target: %v", err)
	}
	if rewrittenFrame.MessageID != 131 || rewrittenFrame.ExtendedOID != clientCancelOID ||
		!rewrittenFrame.HasExtendedValue || rewrittenTarget != 130 ||
		len(rewrittenFrame.Controls) != 1 || rewrittenFrame.Controls[0].OID != "1.2.3" {
		t.Fatalf("codec Cancel rewrite = %#v", rewrittenFrame)
	}

	encoded, err := codec.EncodeResult(19, TagSearchRequest, ldapwire.ResultBusy, "busy")
	if err != nil {
		t.Fatalf("berFrameCodec.EncodeResult() error = %v", err)
	}
	result := mustParseFrame(t, encoded)
	if result.ProtocolTag != TagSearchResultDone || result.ResultCode == nil ||
		*result.ResultCode != ResultBusy {
		t.Fatalf("codec result = %#v", result)
	}

	bindResponse := encodeFrame(20, testLDAPResultOperation(
		TagBindResponse,
		ResultSASLBindInProgress,
		"continue",
	), nil)
	projected, err = codec.Read(bytes.NewReader(bindResponse), int64(len(bindResponse)))
	if err != nil {
		t.Fatalf("berFrameCodec.Read(BindResponse) error = %v", err)
	}
	if !projected.HasResultCode || projected.ResultCode != ldapwire.ResultSASLBindInProgress ||
		projected.FinalResponse {
		t.Fatalf("projected BindResponse = %s", projected)
	}
}

func TestParseFrameOwnsInput(t *testing.T) {
	raw := encodeFrame(5, encodeTLV(0x42, nil), nil)
	frame, err := ParseFrame(raw, int64(len(raw)))
	if err != nil {
		t.Fatalf("ParseFrame() error = %v", err)
	}
	raw[0] = 0xff
	if frame.Raw[0] != 0x30 || frame.ProtocolOp[0] != 0x42 {
		t.Fatal("ParseFrame retained caller-owned storage")
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(encodeFrame(1, encodeTLV(0x42, nil), nil))
	f.Add(encodeFrame(1, testSimpleBind("", []byte("secret")), nil))
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseFrame(raw, 4096)
	})
}

func testSimpleBind(dn string, password []byte) []byte {
	return encodeTLV(0x60, joinBER(
		encodeTLV(0x02, []byte{3}),
		encodeTLV(0x04, []byte(dn)),
		encodeTLV(0x80, password),
	))
}

func testSASLBind(dn, mechanism string, withCredentials bool, credentials []byte) []byte {
	authentication := encodeTLV(0x04, []byte(mechanism))
	if withCredentials {
		authentication = joinBER(authentication, encodeTLV(0x04, credentials))
	}
	return encodeTLV(0x60, joinBER(
		encodeTLV(0x02, []byte{3}),
		encodeTLV(0x04, []byte(dn)),
		encodeTLV(0xa3, authentication),
	))
}

func testControl(oid string, critical bool, hasValue bool, value []byte) []byte {
	fields := encodeTLV(0x04, []byte(oid))
	if critical {
		fields = joinBER(fields, encodeTLV(0x01, []byte{0xff}))
	}
	if hasValue {
		fields = joinBER(fields, encodeTLV(0x04, value))
	}
	return encodeTLV(0x30, fields)
}

func testLDAPResultOperation(tag uint64, code ResultCode, diagnostic string) []byte {
	return encodeTLV(byte(0x60|tag), joinBER(
		encodeTLV(0x0a, encodeNonnegativeInteger(int64(code))),
		encodeTLV(0x04, nil),
		encodeTLV(0x04, []byte(diagnostic)),
	))
}

func testMessageIDElement(t *testing.T, raw []byte) []byte {
	t.Helper()
	outer, _, err := parseElement(raw, 0)
	if err != nil {
		t.Fatalf("parse outer frame: %v", err)
	}
	messageID, _, err := parseElement(raw, outer.contentStart)
	if err != nil {
		t.Fatalf("parse messageID: %v", err)
	}
	return raw[messageID.start:messageID.end]
}

func testControlValue(t *testing.T, raw []byte) []byte {
	t.Helper()
	sequence, _, err := parseElement(raw, 0)
	if err != nil {
		t.Fatalf("parse control: %v", err)
	}
	_, next, err := parseElement(raw, sequence.contentStart)
	if err != nil {
		t.Fatalf("parse control OID: %v", err)
	}
	field, next, err := parseElement(raw, next)
	if err != nil {
		t.Fatalf("parse control field: %v", err)
	}
	if elementIs(field, berClassUniversal, false, berTagBoolean) {
		field, next, err = parseElement(raw, next)
		if err != nil {
			t.Fatalf("parse control value: %v", err)
		}
	}
	if next != sequence.end || !elementIs(field, berClassUniversal, false, berTagOctetString) {
		t.Fatal("control has no final OCTET STRING value")
	}
	return raw[field.contentStart:field.end]
}

func testLDAPResultDiagnostic(t *testing.T, raw []byte) string {
	t.Helper()
	protocol, _, err := parseElement(raw, 0)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	_, next, err := parseElement(raw, protocol.contentStart)
	if err != nil {
		t.Fatalf("parse result code: %v", err)
	}
	_, next, err = parseElement(raw, next)
	if err != nil {
		t.Fatalf("parse matched DN: %v", err)
	}
	diagnostic, _, err := parseElement(raw, next)
	if err != nil {
		t.Fatalf("parse diagnostic: %v", err)
	}
	return string(raw[diagnostic.contentStart:diagnostic.end])
}

func resultCodePointer(code ResultCode) *ResultCode {
	return &code
}

func mustParseFrame(t *testing.T, raw []byte) Frame {
	t.Helper()
	frame, err := ParseFrame(raw, int64(len(raw)))
	if err != nil {
		t.Fatalf("ParseFrame() error = %v", err)
	}
	return frame
}
