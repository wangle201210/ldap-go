package ldapwire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

var ErrMalformedMessage = errors.New("malformed LDAP message")

func ReadMessage(reader io.Reader, maxSize int64) (Message, error) {
	frame, err := readFrame(reader, maxSize)
	if err != nil {
		return Message{}, err
	}
	packet, err := ber.DecodePacketErr(frame)
	if err != nil {
		return Message{}, malformed("decode BER: %v", err)
	}
	return decodeMessage(packet)
}

func readFrame(reader io.Reader, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, malformed("LDAPMessage must be a BER sequence")
	}

	var contentLength uint64
	if header[1]&0x80 == 0 {
		contentLength = uint64(header[1])
	} else {
		lengthBytes := int(header[1] & 0x7f)
		if lengthBytes == 0 {
			return nil, malformed("indefinite BER length is not allowed")
		}
		if lengthBytes > 8 {
			return nil, malformed("BER length uses %d octets", lengthBytes)
		}
		encodedLength := make([]byte, lengthBytes)
		if _, err := io.ReadFull(reader, encodedLength); err != nil {
			return nil, err
		}
		if encodedLength[0] == 0 {
			return nil, malformed("BER length is not minimally encoded")
		}
		header = append(header, encodedLength...)
		for _, value := range encodedLength {
			if contentLength > (math.MaxUint64-uint64(value))/256 {
				return nil, malformed("BER length overflows")
			}
			contentLength = contentLength*256 + uint64(value)
		}
		if contentLength < 128 {
			return nil, malformed("BER long-form length is not minimal")
		}
	}

	if contentLength > uint64(maxSize) || uint64(len(header)) > uint64(maxSize)-contentLength {
		return nil, malformed("message exceeds %d-byte limit", maxSize)
	}
	frame := make([]byte, len(header)+int(contentLength))
	copy(frame, header)
	if _, err := io.ReadFull(reader, frame[len(header):]); err != nil {
		return nil, err
	}
	return frame, nil
}

func decodeMessage(packet *ber.Packet) (Message, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return Message{}, malformed("LDAPMessage is not a sequence")
	}
	if len(packet.Children) < 2 || len(packet.Children) > 3 {
		return Message{}, malformed("LDAPMessage has %d elements", len(packet.Children))
	}

	id, err := packetInteger(packet.Children[0])
	if err != nil || id <= 0 || id > math.MaxInt32 {
		return Message{}, malformed("invalid message ID")
	}

	opPacket := packet.Children[1]
	if opPacket.ClassType != ber.ClassApplication {
		return Message{}, malformed("protocol operation is not application class")
	}

	var request Request
	switch uint64(opPacket.Tag) {
	case ApplicationBindRequest:
		request, err = decodeBindRequest(opPacket)
	case ApplicationSearchRequest:
		request, err = decodeSearchRequest(opPacket)
	case ApplicationUnbindRequest:
		if opPacket.TagType != ber.TypePrimitive || opPacket.Data.Len() != 0 {
			err = malformed("invalid UnbindRequest")
		} else {
			request = UnbindRequest{}
		}
	case ApplicationModifyRequest:
		request, err = decodeModifyRequest(opPacket)
	case ApplicationAddRequest:
		request, err = decodeAddRequest(opPacket)
	case ApplicationDeleteRequest:
		request, err = decodeDeleteRequest(opPacket)
	case ApplicationModifyDNRequest:
		request, err = decodeModifyDNRequest(opPacket)
	case ApplicationCompareRequest:
		request, err = decodeCompareRequest(opPacket)
	case ApplicationAbandonRequest:
		request, err = decodeAbandonRequest(opPacket)
	case ApplicationExtendedRequest:
		request, err = decodeExtendedRequest(opPacket)
	default:
		request = UnsupportedRequest{Tag: uint64(opPacket.Tag)}
	}
	if err != nil {
		return Message{}, err
	}

	message := Message{ID: id, Request: request}
	if len(packet.Children) == 3 {
		message.ControlsPresent = true
		message.Controls, err = decodeControls(packet.Children[2])
		if err != nil {
			if _, unbind := request.(UnbindRequest); unbind {
				return message, nil
			}
			return message, err
		}
	}
	return message, nil
}

func decodeBindRequest(packet *ber.Packet) (BindRequest, error) {
	if packet.TagType != ber.TypeConstructed || len(packet.Children) != 3 {
		return BindRequest{}, malformed("invalid BindRequest")
	}
	version, err := packetInteger(packet.Children[0])
	if err != nil || version < 0 || version > math.MaxInt32 {
		return BindRequest{}, malformed("invalid BindRequest version")
	}
	name, err := packetString(packet.Children[1])
	if err != nil {
		return BindRequest{}, malformed("invalid BindRequest name")
	}

	authPacket := packet.Children[2]
	if authPacket.ClassType != ber.ClassContext {
		return BindRequest{}, malformed("invalid BindRequest authentication")
	}
	request := BindRequest{Version: int(version), Name: name}
	switch authPacket.Tag {
	case 0:
		if authPacket.TagType != ber.TypePrimitive {
			return BindRequest{}, malformed("simple authentication must be primitive")
		}
		request.Authentication.Simple = bytes.Clone(authPacket.Data.Bytes())
	case 3:
		if authPacket.TagType != ber.TypeConstructed ||
			len(authPacket.Children) < 1 || len(authPacket.Children) > 2 {
			return BindRequest{}, malformed("invalid SASL credentials")
		}
		mechanism, err := packetString(authPacket.Children[0])
		if err != nil || mechanism == "" {
			return BindRequest{}, malformed("invalid SASL mechanism")
		}
		request.Authentication.IsSASL = true
		request.Authentication.SASLMechanism = mechanism
		if len(authPacket.Children) == 2 {
			credentials, err := packetBytes(authPacket.Children[1])
			if err != nil {
				return BindRequest{}, malformed("invalid SASL credentials")
			}
			request.Authentication.SASLCredentials = credentials
			request.Authentication.HasSASLCredentials = true
		}
	default:
		return BindRequest{}, malformed("unknown authentication choice %d", authPacket.Tag)
	}
	return request, nil
}

func decodeAddRequest(packet *ber.Packet) (AddRequest, error) {
	if packet.TagType != ber.TypeConstructed || len(packet.Children) != 2 {
		return AddRequest{}, malformed("invalid AddRequest")
	}
	dn, err := packetString(packet.Children[0])
	if err != nil || dn == "" {
		return AddRequest{}, malformed("invalid AddRequest DN")
	}
	attributes, err := decodeAttributeList(packet.Children[1], false)
	if err != nil {
		return AddRequest{}, err
	}
	return AddRequest{Entry: directory.Entry{DN: dn, Attributes: attributes}}, nil
}

func decodeModifyRequest(packet *ber.Packet) (ModifyRequest, error) {
	if packet.TagType != ber.TypeConstructed || len(packet.Children) != 2 {
		return ModifyRequest{}, malformed("invalid ModifyRequest")
	}
	dn, err := packetString(packet.Children[0])
	if err != nil || dn == "" {
		return ModifyRequest{}, malformed("invalid ModifyRequest DN")
	}
	changesPacket := packet.Children[1]
	if !isPacket(changesPacket, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return ModifyRequest{}, malformed("invalid modify changes")
	}

	request := ModifyRequest{DN: dn, Changes: make([]Modification, 0, len(changesPacket.Children))}
	for _, changePacket := range changesPacket.Children {
		if !isPacket(changePacket, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
			len(changePacket.Children) != 2 {
			return ModifyRequest{}, malformed("invalid modify change")
		}
		operation, err := packetInteger(changePacket.Children[0])
		if err != nil || operation < 0 || operation > 3 {
			return ModifyRequest{}, malformed("invalid modify operation")
		}
		attributes, err := decodeAttributeListElement(changePacket.Children[1], true)
		if err != nil {
			return ModifyRequest{}, err
		}
		request.Changes = append(request.Changes, Modification{
			Operation: ModificationOperation(operation),
			Attribute: attributes,
		})
	}
	return request, nil
}

func decodeDeleteRequest(packet *ber.Packet) (DeleteRequest, error) {
	if packet.TagType != ber.TypePrimitive || len(packet.Children) != 0 || packet.Data.Len() == 0 {
		return DeleteRequest{}, malformed("invalid DeleteRequest")
	}
	return DeleteRequest{DN: string(packet.Data.Bytes())}, nil
}

func decodeModifyDNRequest(packet *ber.Packet) (ModifyDNRequest, error) {
	if packet.TagType != ber.TypeConstructed ||
		(len(packet.Children) != 3 && len(packet.Children) != 4) {
		return ModifyDNRequest{}, malformed("invalid ModifyDNRequest")
	}
	dn, err := packetString(packet.Children[0])
	if err != nil || dn == "" {
		return ModifyDNRequest{}, malformed("invalid ModifyDNRequest DN")
	}
	newRDN, err := packetString(packet.Children[1])
	if err != nil || newRDN == "" {
		return ModifyDNRequest{}, malformed("invalid new RDN")
	}
	deleteOldRDN, err := packetBoolean(packet.Children[2])
	if err != nil {
		return ModifyDNRequest{}, malformed("invalid deleteOldRDN")
	}
	request := ModifyDNRequest{DN: dn, NewRDN: newRDN, DeleteOldRDN: deleteOldRDN}
	if len(packet.Children) == 4 {
		superior := packet.Children[3]
		if !isPacket(superior, ber.ClassContext, ber.TypePrimitive, 0) ||
			superior.Data.Len() == 0 {
			return ModifyDNRequest{}, malformed("invalid newSuperior")
		}
		request.NewSuperior = string(superior.Data.Bytes())
		request.HasNewSuperior = true
	}
	return request, nil
}

func decodeCompareRequest(packet *ber.Packet) (CompareRequest, error) {
	if packet.TagType != ber.TypeConstructed || len(packet.Children) != 2 {
		return CompareRequest{}, malformed("invalid CompareRequest")
	}
	dn, err := packetString(packet.Children[0])
	if err != nil || dn == "" {
		return CompareRequest{}, malformed("invalid CompareRequest DN")
	}
	assertionPacket := packet.Children[1]
	if !isPacket(assertionPacket, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(assertionPacket.Children) != 2 {
		return CompareRequest{}, malformed("invalid compare assertion")
	}
	attribute, err := packetString(assertionPacket.Children[0])
	if err != nil || attribute == "" {
		return CompareRequest{}, malformed("invalid compare attribute")
	}
	assertion, err := packetBytes(assertionPacket.Children[1])
	if err != nil {
		return CompareRequest{}, malformed("invalid compare value")
	}
	return CompareRequest{DN: dn, Attribute: attribute, Assertion: assertion}, nil
}

func decodeAbandonRequest(packet *ber.Packet) (AbandonRequest, error) {
	if packet.TagType != ber.TypePrimitive || len(packet.Children) != 0 || packet.Data.Len() == 0 {
		return AbandonRequest{}, malformed("invalid AbandonRequest")
	}
	messageID, err := ber.ParseInt64(packet.Data.Bytes())
	if err != nil || messageID <= 0 || messageID > math.MaxInt32 {
		return AbandonRequest{}, malformed("invalid abandoned message ID")
	}
	return AbandonRequest{MessageID: messageID}, nil
}

func decodeExtendedRequest(packet *ber.Packet) (ExtendedRequest, error) {
	if packet.TagType != ber.TypeConstructed ||
		len(packet.Children) < 1 ||
		len(packet.Children) > 2 {
		return ExtendedRequest{}, malformed("invalid ExtendedRequest")
	}
	name := packet.Children[0]
	if !isPacket(name, ber.ClassContext, ber.TypePrimitive, 0) ||
		name.Data.Len() == 0 {
		return ExtendedRequest{}, malformed("invalid ExtendedRequest name")
	}
	request := ExtendedRequest{Name: string(name.Data.Bytes())}
	if len(packet.Children) == 2 {
		value := packet.Children[1]
		if !isPacket(value, ber.ClassContext, ber.TypePrimitive, 1) {
			return ExtendedRequest{}, malformed("invalid ExtendedRequest value")
		}
		request.Value = bytes.Clone(value.Data.Bytes())
		request.HasValue = true
	}
	return request, nil
}

func decodeAttributeList(packet *ber.Packet, allowEmptyValues bool) ([]directory.Attribute, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return nil, malformed("invalid attribute list")
	}
	attributes := make([]directory.Attribute, 0, len(packet.Children))
	for _, child := range packet.Children {
		attribute, err := decodeAttributeListElement(child, allowEmptyValues)
		if err != nil {
			return nil, err
		}
		attributes = append(attributes, attribute)
	}
	return attributes, nil
}

func decodeAttributeListElement(packet *ber.Packet, allowEmptyValues bool) (directory.Attribute, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 2 {
		return directory.Attribute{}, malformed("invalid attribute")
	}
	description, err := packetString(packet.Children[0])
	if err != nil || description == "" {
		return directory.Attribute{}, malformed("invalid attribute description")
	}
	valuesPacket := packet.Children[1]
	if !isPacket(valuesPacket, ber.ClassUniversal, ber.TypeConstructed, ber.TagSet) ||
		(!allowEmptyValues && len(valuesPacket.Children) == 0) {
		return directory.Attribute{}, malformed("invalid attribute values")
	}
	attribute := directory.Attribute{
		Description: description,
		Values:      make([][]byte, 0, len(valuesPacket.Children)),
	}
	for _, valuePacket := range valuesPacket.Children {
		value, err := packetBytes(valuePacket)
		if err != nil {
			return directory.Attribute{}, malformed("invalid attribute value")
		}
		attribute.Values = append(attribute.Values, value)
	}
	return attribute, nil
}

func decodeSearchRequest(packet *ber.Packet) (SearchRequest, error) {
	if packet.TagType != ber.TypeConstructed || len(packet.Children) != 8 {
		return SearchRequest{}, malformed("invalid SearchRequest")
	}

	baseDN, err := packetString(packet.Children[0])
	if err != nil {
		return SearchRequest{}, malformed("invalid search base")
	}
	scope, err := packetInteger(packet.Children[1])
	if err != nil || scope < math.MinInt32 || scope > math.MaxInt32 {
		return SearchRequest{}, malformed("invalid search scope")
	}
	derefAliases, err := packetInteger(packet.Children[2])
	if err != nil || derefAliases < math.MinInt32 || derefAliases > math.MaxInt32 {
		return SearchRequest{}, malformed("invalid alias dereference mode")
	}
	sizeLimit, sizeLimitErr := packetInteger(packet.Children[3])
	if sizeLimitErr != nil || sizeLimit < math.MinInt32 || sizeLimit > math.MaxInt32 {
		return SearchRequest{}, malformed("invalid size limit")
	}
	timeLimit, timeLimitErr := packetInteger(packet.Children[4])
	if timeLimitErr != nil || timeLimit < math.MinInt32 || timeLimit > math.MaxInt32 {
		return SearchRequest{}, malformed("invalid time limit")
	}
	typesOnly, err := packetBoolean(packet.Children[5])
	if err != nil {
		return SearchRequest{}, malformed("invalid typesOnly value")
	}
	filter, err := decodeFilter(packet.Children[6], 0)
	if err != nil {
		return SearchRequest{}, err
	}

	attributesPacket := packet.Children[7]
	if !isPacket(attributesPacket, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return SearchRequest{}, malformed("invalid requested attributes")
	}
	attributes := make([]string, 0, len(attributesPacket.Children))
	for _, attributePacket := range attributesPacket.Children {
		attribute, err := packetString(attributePacket)
		if err != nil {
			return SearchRequest{}, malformed("invalid requested attribute")
		}
		attributes = append(attributes, attribute)
	}

	return SearchRequest{
		BaseDN:       baseDN,
		Scope:        directory.Scope(scope),
		DerefAliases: int(derefAliases),
		SizeLimit:    int(sizeLimit),
		TimeLimit:    int(timeLimit),
		TypesOnly:    typesOnly,
		Filter:       filter,
		Attributes:   attributes,
	}, nil
}

func decodeControls(packet *ber.Packet) ([]Control, error) {
	if !isPacket(packet, ber.ClassContext, ber.TypeConstructed, 0) {
		return nil, malformed("invalid controls wrapper")
	}
	controls := make([]Control, 0, len(packet.Children))
	for _, controlPacket := range packet.Children {
		if !isPacket(controlPacket, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
			len(controlPacket.Children) < 1 || len(controlPacket.Children) > 3 {
			return nil, malformed("invalid control")
		}
		oid, err := packetString(controlPacket.Children[0])
		if err != nil || oid == "" {
			return nil, malformed("invalid control OID")
		}
		control := Control{OID: oid}
		position := 1
		if position < len(controlPacket.Children) &&
			controlPacket.Children[position].Tag == ber.TagBoolean {
			control.Critical, err = packetBoolean(controlPacket.Children[position])
			if err != nil {
				return nil, malformed("invalid control criticality")
			}
			position++
		}
		if position < len(controlPacket.Children) {
			control.Value, err = packetBytes(controlPacket.Children[position])
			if err != nil {
				return nil, malformed("invalid control value")
			}
			control.HasValue = true
			position++
		}
		if position != len(controlPacket.Children) {
			return nil, malformed("invalid control element order")
		}
		controls = append(controls, control)
	}
	return controls, nil
}

func nonNegativeInt(packet *ber.Packet, name string) (int, error) {
	value, err := packetInteger(packet)
	if err != nil || value < 0 || value > math.MaxInt32 {
		return 0, malformed("invalid %s", name)
	}
	return int(value), nil
}

func packetInteger(packet *ber.Packet) (int64, error) {
	if packet.ClassType != ber.ClassUniversal ||
		(packet.Tag != ber.TagInteger && packet.Tag != ber.TagEnumerated) ||
		packet.TagType != ber.TypePrimitive ||
		packet.Data.Len() == 0 {
		return 0, errors.New("not an integer")
	}
	return ber.ParseInt64(packet.Data.Bytes())
}

func packetBoolean(packet *ber.Packet) (bool, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean) ||
		packet.Data.Len() != 1 {
		return false, errors.New("not a boolean")
	}
	return packet.Data.Bytes()[0] != 0, nil
}

func packetString(packet *ber.Packet) (string, error) {
	value, err := packetBytes(packet)
	return string(value), err
}

func packetBytes(packet *ber.Packet) ([]byte, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) {
		return nil, errors.New("not an octet string")
	}
	return bytes.Clone(packet.Data.Bytes()), nil
}

func isPacket(packet *ber.Packet, class ber.Class, tagType ber.Type, tag ber.Tag) bool {
	return packet != nil && packet.ClassType == class && packet.TagType == tagType && packet.Tag == tag
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedMessage, fmt.Sprintf(format, args...))
}
