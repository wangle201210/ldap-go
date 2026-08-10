package lloadd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	DefaultMaxFrameSize  int64 = (1 << 24) - 1
	MaxMessageID         int64 = (1 << 31) - 1
	maxOuterLengthOctets       = 4

	ProxyAuthzControlOID = "2.16.840.1.113730.3.4.18"
)

const (
	TagBindRequest           uint64 = 0
	TagBindResponse          uint64 = 1
	TagUnbindRequest         uint64 = 2
	TagSearchRequest         uint64 = 3
	TagSearchResultEntry     uint64 = 4
	TagSearchResultDone      uint64 = 5
	TagModifyRequest         uint64 = 6
	TagModifyResponse        uint64 = 7
	TagAddRequest            uint64 = 8
	TagAddResponse           uint64 = 9
	TagDeleteRequest         uint64 = 10
	TagDeleteResponse        uint64 = 11
	TagModifyDNRequest       uint64 = 12
	TagModifyDNResponse      uint64 = 13
	TagCompareRequest        uint64 = 14
	TagCompareResponse       uint64 = 15
	TagAbandonRequest        uint64 = 16
	TagSearchResultReference uint64 = 19
	TagExtendedRequest       uint64 = 23
	TagExtendedResponse      uint64 = 24
	TagIntermediateResponse  uint64 = 25
)

type ResultCode int64

const (
	ResultSuccess            ResultCode = 0
	ResultProtocolError      ResultCode = 2
	ResultSASLBindInProgress ResultCode = 14
	ResultBusy               ResultCode = 51
	ResultUnavailable        ResultCode = 52
	ResultOther              ResultCode = 80
)

var (
	ErrMalformedFrame     = errors.New("malformed LDAP BER frame")
	ErrFrameTooLarge      = errors.New("LDAP BER frame exceeds size limit")
	ErrInvalidMessageID   = errors.New("invalid LDAP message ID")
	ErrNotAbandonRequest  = errors.New("LDAP frame is not an AbandonRequest")
	ErrUnsupportedRequest = errors.New("LDAP request has no LDAPResult response")
)

// RawBER prevents accidental plaintext rendering of opaque protocol data. The
// bytes remain directly writable so the proxy can forward them unchanged.
type RawBER []byte

func (raw RawBER) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprintf(state, "<BER %d bytes>", len(raw))
}

type Control struct {
	OID      string
	Critical bool
	HasValue bool
	Raw      RawBER
}

type BindAuthentication uint8

const (
	BindAuthenticationSimple BindAuthentication = iota
	BindAuthenticationSASL
)

func (authentication BindAuthentication) String() string {
	if authentication == BindAuthenticationSASL {
		return "sasl"
	}
	return "simple"
}

// BindMetadata intentionally excludes simple passwords and SASL credential
// bytes. HasSASLCredentials records only whether the optional element exists.
type BindMetadata struct {
	Version            int64
	DN                 string
	Authentication     BindAuthentication
	SASLMechanism      string
	HasSASLCredentials bool
}

type Frame struct {
	Raw              RawBER
	MessageID        int64
	ProtocolTag      uint64
	ProtocolOp       RawBER
	ControlsRaw      RawBER
	Controls         []Control
	ExtendedOID      string
	ExtendedValue    RawBER
	HasExtendedValue bool
	Bind             *BindMetadata
	ResultCode       *ResultCode
	AbandonTarget    int64
	HasAbandonTarget bool
}

func (frame Frame) String() string {
	return fmt.Sprintf(
		"LDAPFrame{messageID:%d protocolTag:%d controls:%d extendedOID:%q bind:%t result:%t rawBytes:%d}",
		frame.MessageID,
		frame.ProtocolTag,
		len(frame.Controls),
		frame.ExtendedOID,
		frame.Bind != nil,
		frame.ResultCode != nil,
		len(frame.Raw),
	)
}

func (frame Frame) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, frame.String())
}

func ReadFrame(reader io.Reader, max int64) (Frame, error) {
	if reader == nil {
		return Frame{}, malformed("nil reader")
	}
	max = normalizedMaximum(max)

	header := make([]byte, 2, 10)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Frame{}, err
	}
	if header[0] != 0x30 {
		return Frame{}, malformed("LDAPMessage is not a sequence")
	}

	if header[1]&0x80 != 0 {
		lengthOctets := int(header[1] & 0x7f)
		if lengthOctets == 0 {
			return Frame{}, malformed("indefinite BER length")
		}
		if lengthOctets > maxOuterLengthOctets {
			return Frame{}, malformed("BER length uses too many octets")
		}
		header = append(header, make([]byte, lengthOctets)...)
		if _, err := io.ReadFull(reader, header[2:]); err != nil {
			return Frame{}, err
		}
	}

	contentLength, next, err := parseBERLength(header, 1)
	if err != nil {
		return Frame{}, err
	}
	if next != len(header) {
		return Frame{}, malformed("invalid LDAPMessage header")
	}
	if contentLength > uint64(max) || uint64(len(header)) > uint64(max)-contentLength {
		return Frame{}, ErrFrameTooLarge
	}
	if contentLength > uint64(maximumInt()-len(header)) {
		return Frame{}, ErrFrameTooLarge
	}

	raw := make([]byte, len(header)+int(contentLength))
	copy(raw, header)
	if _, err := io.ReadFull(reader, raw[len(header):]); err != nil {
		return Frame{}, err
	}
	return parseOwnedFrame(raw, max)
}

func ParseFrame(raw []byte, max int64) (Frame, error) {
	max = normalizedMaximum(max)
	if int64(len(raw)) > max {
		return Frame{}, ErrFrameTooLarge
	}
	return parseOwnedFrame(bytes.Clone(raw), max)
}

func RewriteMessageID(frame Frame, messageID int64) ([]byte, error) {
	if err := validateMessageID(messageID, true); err != nil {
		return nil, err
	}
	if err := validateFrameParts(frame); err != nil {
		return nil, err
	}
	return encodeFrame(messageID, frame.ProtocolOp, frame.ControlsRaw), nil
}

func RewriteAbandonTarget(frame Frame, targetMessageID int64) ([]byte, error) {
	return rewriteAbandon(frame, frame.MessageID, targetMessageID)
}

func RewriteAbandonMessageIDs(
	frame Frame,
	messageID int64,
	targetMessageID int64,
) ([]byte, error) {
	return rewriteAbandon(frame, messageID, targetMessageID)
}

func RewriteExtendedRequestValue(
	frame Frame,
	messageID int64,
	requestValue []byte,
) ([]byte, error) {
	if err := validateMessageID(messageID, false); err != nil {
		return nil, err
	}
	if err := validateFrameParts(frame); err != nil {
		return nil, err
	}
	if frame.ProtocolTag != TagExtendedRequest {
		return nil, malformed("frame is not an ExtendedRequest")
	}
	protocol, next, err := parseElement(frame.ProtocolOp, 0)
	if err != nil || next != len(frame.ProtocolOp) ||
		!elementIs(protocol, berClassApplication, true, TagExtendedRequest) {
		return nil, malformed("invalid ExtendedRequest protocol op")
	}
	if _, _, _, err := parseExtendedRequestMetadata(frame.ProtocolOp, protocol); err != nil {
		return nil, err
	}
	requestName, _, err := parseElement(frame.ProtocolOp, protocol.contentStart)
	if err != nil || !elementIs(requestName, berClassContext, false, 0) {
		return nil, malformed("invalid ExtendedRequest OID")
	}
	operation := encodeTLV(
		0x77,
		joinBER(
			frame.ProtocolOp[requestName.start:requestName.end],
			encodeTLV(0x81, requestValue),
		),
	)
	return encodeFrame(messageID, operation, frame.ControlsRaw), nil
}

func EncodeAbandonRequest(messageID, targetMessageID int64) ([]byte, error) {
	if err := validateMessageID(messageID, false); err != nil {
		return nil, err
	}
	if err := validateMessageID(targetMessageID, false); err != nil {
		return nil, err
	}
	abandon := encodeTLV(0x50, encodeNonnegativeInteger(targetMessageID))
	return encodeFrame(messageID, abandon, nil), nil
}

func PrependProxyAuthz(frame Frame, authzID []byte) ([]byte, error) {
	return prependProxyAuthz(frame, frame.MessageID, authzID)
}

func prependProxyAuthz(frame Frame, messageID int64, authzID []byte) ([]byte, error) {
	if err := validateMessageID(messageID, true); err != nil {
		return nil, err
	}
	if !utf8.Valid(authzID) {
		return nil, malformed("ProxyAuthz identity is not valid UTF-8")
	}
	if int64(len(authzID)) > DefaultMaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	if err := validateFrameParts(frame); err != nil {
		return nil, err
	}

	controlContent := joinBER(
		encodeTLV(0x04, []byte(ProxyAuthzControlOID)),
		encodeTLV(0x01, []byte{0xff}),
		encodeTLV(0x04, authzID),
	)
	proxyControl := encodeTLV(0x30, controlContent)

	controlsContent := proxyControl
	if len(frame.ControlsRaw) != 0 {
		wrapper, next, err := parseElement(frame.ControlsRaw, 0)
		if err != nil || next != len(frame.ControlsRaw) ||
			wrapper.class != berClassContext || !wrapper.constructed || wrapper.tag != 0 {
			return nil, malformed("invalid controls wrapper")
		}
		controlsContent = joinBER(proxyControl, frame.ControlsRaw[wrapper.contentStart:wrapper.end])
	}
	controls := encodeTLV(0xa0, controlsContent)
	return encodeFrame(messageID, frame.ProtocolOp, controls), nil
}

func PrependProxyAuthzString(frame Frame, authzID string) ([]byte, error) {
	return PrependProxyAuthz(frame, []byte(authzID))
}

func IsFinalResponse(frame Frame) bool {
	switch frame.ProtocolTag {
	case TagSearchResultEntry, TagSearchResultReference, TagIntermediateResponse:
		return false
	case TagBindResponse:
		return frame.ResultCode == nil || *frame.ResultCode != ResultSASLBindInProgress
	default:
		return true
	}
}

func (frame Frame) IsFinalResponse() bool {
	return IsFinalResponse(frame)
}

func EncodeErrorResponse(
	messageID int64,
	requestTag uint64,
	code ResultCode,
	diagnosticMessage string,
) ([]byte, error) {
	if err := validateMessageID(messageID, true); err != nil {
		return nil, err
	}
	if code < 0 || int64(code) > MaxMessageID {
		return nil, malformed("invalid LDAP result code")
	}
	if !utf8.ValidString(diagnosticMessage) {
		return nil, malformed("diagnostic message is not valid UTF-8")
	}

	responseTag, ok := responseTagForRequest(requestTag)
	if !ok {
		return nil, fmt.Errorf("%w: application tag %d", ErrUnsupportedRequest, requestTag)
	}
	result := joinBER(
		encodeTLV(0x0a, encodeNonnegativeInteger(int64(code))),
		encodeTLV(0x04, nil),
		encodeTLV(0x04, []byte(diagnosticMessage)),
	)
	operation := encodeTLV(byte(0x60|responseTag), result)
	return encodeFrame(messageID, operation, nil), nil
}

type berFrameCodec struct{}

func (berFrameCodec) Read(reader io.Reader, max int64) (proxyFrame, error) {
	frame, err := ReadFrame(reader, max)
	if err != nil {
		return proxyFrame{}, err
	}
	return projectProxyFrame(frame), nil
}

func (berFrameCodec) RewriteMessageID(frame proxyFrame, messageID int64) ([]byte, error) {
	parsed, err := parseProxyFrame(frame)
	if err != nil {
		return nil, err
	}
	return RewriteMessageID(parsed, messageID)
}

func (berFrameCodec) RewriteAbandon(
	frame proxyFrame,
	messageID int64,
	targetMessageID int64,
) ([]byte, error) {
	parsed, err := parseProxyFrame(frame)
	if err != nil {
		return nil, err
	}
	return RewriteAbandonMessageIDs(parsed, messageID, targetMessageID)
}

func (berFrameCodec) RewriteExtendedRequestValue(
	frame proxyFrame,
	messageID int64,
	requestValue []byte,
) ([]byte, error) {
	parsed, err := parseProxyFrame(frame)
	if err != nil {
		return nil, err
	}
	return RewriteExtendedRequestValue(parsed, messageID, requestValue)
}

func (berFrameCodec) EncodeAbandon(messageID, targetMessageID int64) ([]byte, error) {
	return EncodeAbandonRequest(messageID, targetMessageID)
}

func (berFrameCodec) PrependProxyAuthz(
	frame proxyFrame,
	messageID int64,
	authzID []byte,
) ([]byte, error) {
	parsed, err := parseProxyFrame(frame)
	if err != nil {
		return nil, err
	}
	return prependProxyAuthz(parsed, messageID, authzID)
}

func (berFrameCodec) EncodeResult(
	messageID int64,
	requestTag uint64,
	code ldapwire.ResultCode,
	diagnosticMessage string,
) ([]byte, error) {
	return EncodeErrorResponse(messageID, requestTag, ResultCode(code), diagnosticMessage)
}

func projectProxyFrame(frame Frame) proxyFrame {
	projected := proxyFrame{
		Raw:              []byte(frame.Raw),
		MessageID:        frame.MessageID,
		ProtocolTag:      frame.ProtocolTag,
		ExtendedOID:      frame.ExtendedOID,
		ExtendedValue:    append(RawBER(nil), frame.ExtendedValue...),
		HasExtendedValue: frame.HasExtendedValue,
		AbandonID:        frame.AbandonTarget,
		FinalResponse:    IsFinalResponse(frame),
	}
	if len(frame.Controls) != 0 {
		projected.Controls = make([]string, len(frame.Controls))
		for index, control := range frame.Controls {
			projected.Controls[index] = control.OID
		}
	}
	if frame.Bind != nil {
		projected.BindVersion = int(frame.Bind.Version)
		projected.BindDN = frame.Bind.DN
		projected.BindSASL = frame.Bind.Authentication == BindAuthenticationSASL
		projected.BindMechanism = frame.Bind.SASLMechanism
	}
	if frame.ResultCode != nil {
		projected.ResultCode = ldapwire.ResultCode(*frame.ResultCode)
		projected.HasResultCode = true
	}
	return projected
}

func parseProxyFrame(frame proxyFrame) (Frame, error) {
	maximum := int64(len(frame.Raw))
	if maximum == 0 {
		maximum = 1
	}
	return ParseFrame(frame.Raw, maximum)
}

func parseOwnedFrame(raw []byte, max int64) (Frame, error) {
	if int64(len(raw)) > max {
		return Frame{}, ErrFrameTooLarge
	}
	outer, next, err := parseElement(raw, 0)
	if err != nil {
		return Frame{}, err
	}
	if next != len(raw) {
		return Frame{}, malformed("trailing bytes after LDAPMessage")
	}
	if outer.class != berClassUniversal || !outer.constructed || outer.tag != berTagSequence ||
		outer.identifierEnd-outer.start != 1 || raw[outer.start] != 0x30 {
		return Frame{}, malformed("LDAPMessage is not a sequence")
	}
	if raw[outer.identifierEnd]&0x80 != 0 &&
		int(raw[outer.identifierEnd]&0x7f) > maxOuterLengthOctets {
		return Frame{}, malformed("BER length uses too many octets")
	}

	cursor := outer.contentStart
	messageIDElement, next, err := parseElement(raw, cursor)
	if err != nil {
		return Frame{}, malformedWrap("messageID", err)
	}
	if !elementIs(messageIDElement, berClassUniversal, false, berTagInteger) {
		return Frame{}, malformed("invalid messageID element")
	}
	messageID, err := decodeNonnegativeInteger(
		raw[messageIDElement.contentStart:messageIDElement.end],
		MaxMessageID,
	)
	if err != nil {
		return Frame{}, malformedWrap("messageID", err)
	}
	cursor = next

	protocol, next, err := parseElement(raw, cursor)
	if err != nil {
		return Frame{}, malformedWrap("protocolOp", err)
	}
	if protocol.class != berClassApplication {
		return Frame{}, malformed("protocolOp is not application class")
	}
	if err := validateProtocolElement(protocol); err != nil {
		return Frame{}, err
	}
	cursor = next

	frame := Frame{
		Raw:         RawBER(raw),
		MessageID:   messageID,
		ProtocolTag: protocol.tag,
		ProtocolOp:  RawBER(raw[protocol.start:protocol.end]),
	}
	if cursor < outer.end {
		controlsElement, controlsEnd, controlsErr := parseElement(raw, cursor)
		if controlsErr != nil {
			return Frame{}, malformedWrap("controls", controlsErr)
		}
		if controlsEnd != outer.end {
			return Frame{}, malformed("unexpected LDAPMessage element")
		}
		controls, controlsErr := parseControls(raw, controlsElement)
		if controlsErr != nil {
			return Frame{}, controlsErr
		}
		frame.ControlsRaw = RawBER(raw[controlsElement.start:controlsElement.end])
		frame.Controls = controls
		cursor = controlsEnd
	}
	if cursor != outer.end {
		return Frame{}, malformed("incomplete LDAPMessage")
	}

	switch protocol.tag {
	case TagBindRequest:
		bind, bindErr := parseBindMetadata(raw, protocol)
		if bindErr != nil {
			return Frame{}, bindErr
		}
		frame.Bind = &bind
	case TagExtendedRequest:
		oid, value, hasValue, extendedErr := parseExtendedRequestMetadata(raw, protocol)
		if extendedErr != nil {
			return Frame{}, extendedErr
		}
		frame.ExtendedOID = oid
		frame.ExtendedValue = value
		frame.HasExtendedValue = hasValue
	case TagAbandonRequest:
		if protocol.constructed {
			return Frame{}, malformed("AbandonRequest must be primitive")
		}
		target, targetErr := decodeNonnegativeInteger(
			raw[protocol.contentStart:protocol.end],
			MaxMessageID,
		)
		if targetErr != nil || target == 0 {
			return Frame{}, malformed("invalid Abandon target messageID")
		}
		frame.AbandonTarget = target
		frame.HasAbandonTarget = true
	}

	if isLDAPResultResponse(protocol.tag) {
		code, resultErr := parseLDAPResultCode(raw, protocol)
		if resultErr != nil {
			return Frame{}, resultErr
		}
		frame.ResultCode = &code
	}
	return frame, nil
}

func parseControls(raw []byte, wrapper berElement) ([]Control, error) {
	if !elementIs(wrapper, berClassContext, true, 0) {
		return nil, malformed("invalid controls wrapper")
	}
	if wrapper.contentStart == wrapper.end {
		return nil, malformed("controls wrapper is empty")
	}

	controls := make([]Control, 0, 1)
	for cursor := wrapper.contentStart; cursor < wrapper.end; {
		sequence, next, err := parseElement(raw, cursor)
		if err != nil {
			return nil, malformedWrap("control", err)
		}
		if !elementIs(sequence, berClassUniversal, true, berTagSequence) {
			return nil, malformed("control is not a sequence")
		}

		fieldCursor := sequence.contentStart
		oidElement, fieldEnd, err := parseElement(raw, fieldCursor)
		if err != nil || !elementIs(oidElement, berClassUniversal, false, berTagOctetString) {
			return nil, malformed("invalid control OID")
		}
		oid, err := parseNumericOID(raw[oidElement.contentStart:oidElement.end])
		if err != nil {
			return nil, malformed("invalid control OID")
		}
		fieldCursor = fieldEnd

		control := Control{OID: oid, Raw: RawBER(raw[sequence.start:sequence.end])}
		if fieldCursor < sequence.end {
			field, nextField, fieldErr := parseElement(raw, fieldCursor)
			if fieldErr != nil {
				return nil, malformedWrap("control field", fieldErr)
			}
			if elementIs(field, berClassUniversal, false, berTagBoolean) {
				if field.end-field.contentStart != 1 {
					return nil, malformed("invalid control criticality")
				}
				control.Critical = raw[field.contentStart] != 0
				fieldCursor = nextField
			}
		}
		if fieldCursor < sequence.end {
			value, nextField, valueErr := parseElement(raw, fieldCursor)
			if valueErr != nil || !elementIs(value, berClassUniversal, false, berTagOctetString) {
				return nil, malformed("invalid control value")
			}
			control.HasValue = true
			fieldCursor = nextField
		}
		if fieldCursor != sequence.end {
			return nil, malformed("unexpected control field")
		}

		controls = append(controls, control)
		cursor = next
	}
	return controls, nil
}

func parseBindMetadata(raw []byte, protocol berElement) (BindMetadata, error) {
	if !protocol.constructed {
		return BindMetadata{}, malformed("BindRequest must be constructed")
	}
	cursor := protocol.contentStart
	versionElement, next, err := parseElement(raw, cursor)
	if err != nil || !elementIs(versionElement, berClassUniversal, false, berTagInteger) {
		return BindMetadata{}, malformed("invalid Bind version")
	}
	version, err := decodeNonnegativeInteger(raw[versionElement.contentStart:versionElement.end], 127)
	if err != nil || version == 0 {
		return BindMetadata{}, malformed("invalid Bind version")
	}
	cursor = next

	dnElement, next, err := parseElement(raw, cursor)
	if err != nil || !elementIs(dnElement, berClassUniversal, false, berTagOctetString) {
		return BindMetadata{}, malformed("invalid Bind DN")
	}
	dnBytes := raw[dnElement.contentStart:dnElement.end]
	if !utf8.Valid(dnBytes) {
		return BindMetadata{}, malformed("Bind DN is not valid UTF-8")
	}
	cursor = next

	authentication, next, err := parseElement(raw, cursor)
	if err != nil || next != protocol.end || authentication.class != berClassContext {
		return BindMetadata{}, malformed("invalid Bind authentication")
	}
	metadata := BindMetadata{Version: version, DN: string(dnBytes)}
	switch authentication.tag {
	case 0:
		if authentication.constructed {
			return BindMetadata{}, malformed("simple Bind authentication must be primitive")
		}
		metadata.Authentication = BindAuthenticationSimple
	case 3:
		if !authentication.constructed {
			return BindMetadata{}, malformed("SASL Bind authentication must be constructed")
		}
		metadata.Authentication = BindAuthenticationSASL
		mechanism, mechanismEnd, mechanismErr := parseElement(raw, authentication.contentStart)
		if mechanismErr != nil || !elementIs(mechanism, berClassUniversal, false, berTagOctetString) {
			return BindMetadata{}, malformed("invalid SASL mechanism")
		}
		mechanismBytes := raw[mechanism.contentStart:mechanism.end]
		if len(mechanismBytes) == 0 || !utf8.Valid(mechanismBytes) {
			return BindMetadata{}, malformed("invalid SASL mechanism")
		}
		metadata.SASLMechanism = string(mechanismBytes)
		if mechanismEnd < authentication.end {
			credentials, credentialsEnd, credentialsErr := parseElement(raw, mechanismEnd)
			if credentialsErr != nil || credentialsEnd != authentication.end ||
				!elementIs(credentials, berClassUniversal, false, berTagOctetString) {
				return BindMetadata{}, malformed("invalid SASL credentials element")
			}
			metadata.HasSASLCredentials = true
		} else if mechanismEnd != authentication.end {
			return BindMetadata{}, malformed("invalid SASL authentication")
		}
	default:
		return BindMetadata{}, malformed("unsupported Bind authentication choice")
	}
	return metadata, nil
}

func parseExtendedRequestMetadata(
	raw []byte,
	protocol berElement,
) (string, RawBER, bool, error) {
	if !protocol.constructed {
		return "", nil, false, malformed("ExtendedRequest must be constructed")
	}
	requestName, next, err := parseElement(raw, protocol.contentStart)
	if err != nil || !elementIs(requestName, berClassContext, false, 0) {
		return "", nil, false, malformed("invalid ExtendedRequest OID")
	}
	oid, err := parseNumericOID(raw[requestName.contentStart:requestName.end])
	if err != nil {
		return "", nil, false, malformed("invalid ExtendedRequest OID")
	}
	var value RawBER
	hasValue := false
	if next < protocol.end {
		requestValue, valueEnd, valueErr := parseElement(raw, next)
		if valueErr != nil || valueEnd != protocol.end ||
			!elementIs(requestValue, berClassContext, false, 1) {
			return "", nil, false, malformed("invalid ExtendedRequest value")
		}
		value = RawBER(raw[requestValue.contentStart:requestValue.end])
		hasValue = true
		next = valueEnd
	}
	if next != protocol.end {
		return "", nil, false, malformed("unexpected ExtendedRequest field")
	}
	return oid, value, hasValue, nil
}

func parseLDAPResultCode(raw []byte, protocol berElement) (ResultCode, error) {
	if !protocol.constructed {
		return 0, malformed("LDAPResult response must be constructed")
	}
	codeElement, next, err := parseElement(raw, protocol.contentStart)
	if err != nil || !elementIs(codeElement, berClassUniversal, false, berTagEnumerated) {
		return 0, malformed("invalid LDAPResult code")
	}
	code, err := decodeNonnegativeInteger(raw[codeElement.contentStart:codeElement.end], MaxMessageID)
	if err != nil {
		return 0, malformed("invalid LDAPResult code")
	}

	matchedDN, next, err := parseElement(raw, next)
	if err != nil || !elementIs(matchedDN, berClassUniversal, false, berTagOctetString) {
		return 0, malformed("invalid LDAPResult matched DN")
	}
	diagnostic, next, err := parseElement(raw, next)
	if err != nil || !elementIs(diagnostic, berClassUniversal, false, berTagOctetString) {
		return 0, malformed("invalid LDAPResult diagnostic message")
	}
	for next < protocol.end {
		_, fieldEnd, fieldErr := parseElement(raw, next)
		if fieldErr != nil {
			return 0, malformedWrap("LDAPResult field", fieldErr)
		}
		next = fieldEnd
	}
	if next != protocol.end {
		return 0, malformed("invalid LDAPResult")
	}
	return ResultCode(code), nil
}

func rewriteAbandon(frame Frame, messageID int64, targetMessageID int64) ([]byte, error) {
	if frame.ProtocolTag != TagAbandonRequest || !frame.HasAbandonTarget {
		return nil, ErrNotAbandonRequest
	}
	if err := validateMessageID(messageID, true); err != nil {
		return nil, err
	}
	if err := validateMessageID(targetMessageID, false); err != nil {
		return nil, err
	}
	if err := validateFrameParts(frame); err != nil {
		return nil, err
	}
	abandon := encodeTLV(0x50, encodeNonnegativeInteger(targetMessageID))
	return encodeFrame(messageID, abandon, frame.ControlsRaw), nil
}

func validateFrameParts(frame Frame) error {
	protocol, next, err := parseElement(frame.ProtocolOp, 0)
	if err != nil || next != len(frame.ProtocolOp) || protocol.class != berClassApplication ||
		protocol.tag != frame.ProtocolTag {
		return malformed("invalid preserved protocolOp")
	}
	if err := validateProtocolElement(protocol); err != nil {
		return err
	}
	if len(frame.ControlsRaw) != 0 {
		controls, controlsEnd, controlsErr := parseElement(frame.ControlsRaw, 0)
		if controlsErr != nil || controlsEnd != len(frame.ControlsRaw) ||
			!elementIs(controls, berClassContext, true, 0) {
			return malformed("invalid preserved controls")
		}
	}
	return nil
}

func validateProtocolElement(protocol berElement) error {
	expectedConstructed, known := protocolConstructedForm(protocol.tag)
	if known && protocol.constructed != expectedConstructed {
		return malformed("protocolOp has invalid primitive/constructed form")
	}
	return nil
}

func protocolConstructedForm(tag uint64) (bool, bool) {
	switch tag {
	case TagUnbindRequest, TagDeleteRequest, TagAbandonRequest:
		return false, true
	case TagBindRequest,
		TagBindResponse,
		TagSearchRequest,
		TagSearchResultEntry,
		TagSearchResultDone,
		TagModifyRequest,
		TagModifyResponse,
		TagAddRequest,
		TagAddResponse,
		TagDeleteResponse,
		TagModifyDNRequest,
		TagModifyDNResponse,
		TagCompareRequest,
		TagCompareResponse,
		TagSearchResultReference,
		TagExtendedRequest,
		TagExtendedResponse,
		TagIntermediateResponse:
		return true, true
	default:
		return false, false
	}
}

func validateMessageID(messageID int64, allowZero bool) error {
	if messageID < 0 || messageID > MaxMessageID || (!allowZero && messageID == 0) {
		return ErrInvalidMessageID
	}
	return nil
}

func responseTagForRequest(tag uint64) (byte, bool) {
	if tag > 30 && tag <= 0xff {
		identifier := byte(tag)
		if identifier&0xc0 == 0x40 && identifier&0x1f != 0x1f {
			tag = uint64(identifier & 0x1f)
		}
	}
	switch tag {
	case TagBindRequest:
		return byte(TagBindResponse), true
	case TagSearchRequest:
		return byte(TagSearchResultDone), true
	case TagModifyRequest:
		return byte(TagModifyResponse), true
	case TagAddRequest:
		return byte(TagAddResponse), true
	case TagDeleteRequest:
		return byte(TagDeleteResponse), true
	case TagModifyDNRequest:
		return byte(TagModifyDNResponse), true
	case TagCompareRequest:
		return byte(TagCompareResponse), true
	case TagExtendedRequest:
		return byte(TagExtendedResponse), true
	default:
		return 0, false
	}
}

func isLDAPResultResponse(tag uint64) bool {
	switch tag {
	case TagBindResponse,
		TagSearchResultDone,
		TagModifyResponse,
		TagAddResponse,
		TagDeleteResponse,
		TagModifyDNResponse,
		TagCompareResponse,
		TagExtendedResponse:
		return true
	default:
		return false
	}
}

func encodeFrame(messageID int64, protocolOp, controls []byte) []byte {
	content := joinBER(
		encodeTLV(0x02, encodeNonnegativeInteger(messageID)),
		protocolOp,
		controls,
	)
	return encodeTLV(0x30, content)
}

func encodeTLV(identifier byte, content []byte) []byte {
	length := encodeBERLength(len(content))
	encoded := make([]byte, 1+len(length)+len(content))
	encoded[0] = identifier
	copy(encoded[1:], length)
	copy(encoded[1+len(length):], content)
	return encoded
}

func encodeBERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var scratch [8]byte
	cursor := len(scratch)
	for value := uint64(length); value != 0; value >>= 8 {
		cursor--
		scratch[cursor] = byte(value)
	}
	encoded := make([]byte, 1+len(scratch)-cursor)
	encoded[0] = 0x80 | byte(len(scratch)-cursor)
	copy(encoded[1:], scratch[cursor:])
	return encoded
}

func encodeNonnegativeInteger(value int64) []byte {
	if value == 0 {
		return []byte{0}
	}
	var scratch [9]byte
	cursor := len(scratch)
	for value != 0 {
		cursor--
		scratch[cursor] = byte(value)
		value >>= 8
	}
	if scratch[cursor]&0x80 != 0 {
		cursor--
		scratch[cursor] = 0
	}
	return bytes.Clone(scratch[cursor:])
}

func joinBER(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		if len(part) > maximumInt()-total {
			panic("BER frame length overflow")
		}
		total += len(part)
	}
	joined := make([]byte, 0, total)
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

type berElement struct {
	start         int
	identifierEnd int
	contentStart  int
	end           int
	class         byte
	constructed   bool
	tag           uint64
}

const (
	berClassUniversal   byte = 0
	berClassApplication byte = 1
	berClassContext     byte = 2

	berTagBoolean     uint64 = 1
	berTagInteger     uint64 = 2
	berTagOctetString uint64 = 4
	berTagEnumerated  uint64 = 10
	berTagSequence    uint64 = 16
)

func parseElement(raw []byte, offset int) (berElement, int, error) {
	if offset < 0 || offset >= len(raw) {
		return berElement{}, offset, malformed("truncated BER identifier")
	}
	start := offset
	identifier := raw[offset]
	offset++
	element := berElement{
		start:       start,
		class:       identifier >> 6,
		constructed: identifier&0x20 != 0,
		tag:         uint64(identifier & 0x1f),
	}
	if element.tag == 0x1f {
		element.tag = 0
		first := true
		for {
			if offset >= len(raw) {
				return berElement{}, offset, malformed("truncated high-tag identifier")
			}
			octet := raw[offset]
			offset++
			value := uint64(octet & 0x7f)
			if first && value == 0 {
				return berElement{}, offset, malformed("non-minimal high-tag identifier")
			}
			if element.tag > (^uint64(0)-value)/128 {
				return berElement{}, offset, malformed("BER tag overflows")
			}
			element.tag = element.tag*128 + value
			first = false
			if octet&0x80 == 0 {
				break
			}
		}
		if element.tag < 31 {
			return berElement{}, offset, malformed("non-minimal high-tag identifier")
		}
	}
	element.identifierEnd = offset

	length, contentStart, err := parseBERLength(raw, offset)
	if err != nil {
		return berElement{}, offset, err
	}
	if length > uint64(len(raw)-contentStart) {
		return berElement{}, contentStart, malformed("truncated BER value")
	}
	if length > uint64(maximumInt()) {
		return berElement{}, contentStart, ErrFrameTooLarge
	}
	element.contentStart = contentStart
	element.end = contentStart + int(length)
	return element, element.end, nil
}

func parseBERLength(raw []byte, offset int) (uint64, int, error) {
	if offset < 0 || offset >= len(raw) {
		return 0, offset, malformed("truncated BER length")
	}
	first := raw[offset]
	offset++
	if first&0x80 == 0 {
		return uint64(first), offset, nil
	}
	octets := int(first & 0x7f)
	if octets == 0 {
		return 0, offset, malformed("indefinite BER length")
	}
	if octets > 8 {
		return 0, offset, malformed("BER length uses too many octets")
	}
	if octets > len(raw)-offset {
		return 0, offset, malformed("truncated BER length")
	}
	// LDAP uses BER rather than DER. OpenLDAP's liblber reserves multiple
	// length octets for constructed values, including leading zero octets.
	var length uint64
	for _, octet := range raw[offset : offset+octets] {
		length = length<<8 | uint64(octet)
	}
	return length, offset + octets, nil
}

func decodeNonnegativeInteger(content []byte, maximum int64) (int64, error) {
	if len(content) == 0 {
		return 0, malformed("empty BER integer")
	}
	if content[0]&0x80 != 0 {
		return 0, malformed("negative BER integer")
	}
	if len(content) > 1 && content[0] == 0 && content[1]&0x80 == 0 {
		return 0, malformed("non-minimal BER integer")
	}
	var value uint64
	for _, octet := range content {
		if value > (^uint64(0)-uint64(octet))/256 {
			return 0, malformed("BER integer overflows")
		}
		value = value*256 + uint64(octet)
	}
	if value > uint64(maximum) {
		return 0, malformed("BER integer exceeds allowed range")
	}
	return int64(value), nil
}

func parseNumericOID(raw []byte) (string, error) {
	if len(raw) < 3 || raw[0] == '.' || raw[len(raw)-1] == '.' {
		return "", malformed("invalid numeric OID")
	}
	segmentStart := 0
	dots := 0
	for index, value := range raw {
		switch {
		case value == '.':
			if index == segmentStart || index-segmentStart > 1 && raw[segmentStart] == '0' {
				return "", malformed("invalid numeric OID")
			}
			dots++
			segmentStart = index + 1
		case value < '0' || value > '9':
			return "", malformed("invalid numeric OID")
		}
	}
	if dots == 0 || len(raw)-segmentStart > 1 && raw[segmentStart] == '0' {
		return "", malformed("invalid numeric OID")
	}
	return string(raw), nil
}

func elementIs(element berElement, class byte, constructed bool, tag uint64) bool {
	return element.class == class && element.constructed == constructed && element.tag == tag
}

func normalizedMaximum(max int64) int64 {
	if max <= 0 {
		return DefaultMaxFrameSize
	}
	return max
}

func maximumInt() int {
	return int(^uint(0) >> 1)
}

func malformed(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedFrame, fmt.Sprintf(format, arguments...))
}

func malformedWrap(context string, err error) error {
	if errors.Is(err, ErrFrameTooLarge) {
		return err
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformedFrame, context, err)
}
