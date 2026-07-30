package ldapwire

import (
	"bytes"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type PasswordModifyRequestValue struct {
	UserIdentity    []byte
	OldPassword     []byte
	NewPassword     []byte
	HasUserIdentity bool
	HasOldPassword  bool
	HasNewPassword  bool
}

func DecodePasswordModifyRequestValue(
	value []byte,
	present bool,
) (PasswordModifyRequestValue, error) {
	if !present {
		return PasswordModifyRequestValue{}, nil
	}
	if len(value) == 0 {
		return PasswordModifyRequestValue{}, malformed("empty password modify request value")
	}

	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return PasswordModifyRequestValue{}, malformed(
			"decode password modify request value: %v",
			err,
		)
	}
	if reader.Len() != 0 {
		return PasswordModifyRequestValue{}, malformed(
			"password modify request value has trailing data",
		)
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return PasswordModifyRequestValue{}, malformed(
			"password modify request value is not a sequence",
		)
	}

	var request PasswordModifyRequestValue
	lastTag := -1
	for _, child := range packet.Children {
		if child.ClassType != ber.ClassContext ||
			child.TagType != ber.TypePrimitive ||
			child.Tag > 2 {
			return PasswordModifyRequestValue{}, malformed(
				"invalid password modify request element",
			)
		}
		tag := int(child.Tag)
		if tag <= lastTag {
			return PasswordModifyRequestValue{}, malformed(
				"password modify request elements are duplicated or out of order",
			)
		}
		lastTag = tag
		switch tag {
		case 0:
			request.UserIdentity = bytes.Clone(child.Data.Bytes())
			request.HasUserIdentity = true
		case 1:
			request.OldPassword = bytes.Clone(child.Data.Bytes())
			request.HasOldPassword = true
		case 2:
			request.NewPassword = bytes.Clone(child.Data.Bytes())
			request.HasNewPassword = true
		default:
			return PasswordModifyRequestValue{}, malformed(
				"unknown password modify request element",
			)
		}
	}
	return request, nil
}

func EncodePasswordModifyResponseValue(generatedPassword []byte) []byte {
	if len(generatedPassword) == 0 {
		return nil
	}
	response := ber.NewSequence("PasswordModifyResponseValue")
	response.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		string(generatedPassword),
		"genPasswd",
	))
	return response.Bytes()
}
