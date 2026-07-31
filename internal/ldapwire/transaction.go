package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type TransactionEndRequestValue struct {
	Commit     bool
	Identifier []byte
}

type TransactionUpdateControls struct {
	MessageID int64
	Controls  []Control
}

type TransactionEndResponseValue struct {
	FailedMessageID    int64
	HasFailedMessageID bool
	UpdateControls     []TransactionUpdateControls
}

func EncodeTransactionEndRequestValue(request TransactionEndRequestValue) []byte {
	value := ber.NewSequence("txnEndReq")
	if !request.Commit {
		value.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			false,
			"commit",
		))
	}
	value.AppendChild(octetString(request.Identifier))
	return value.Bytes()
}

func DecodeTransactionEndRequestValue(
	value []byte,
) (TransactionEndRequestValue, error) {
	packet, err := decodeTransactionBERValue(value, "txnEndReq")
	if err != nil {
		return TransactionEndRequestValue{}, err
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 1 ||
		len(packet.Children) > 2 {
		return TransactionEndRequestValue{}, malformed(
			"txnEndReq is not a one-or-two-element sequence",
		)
	}

	request := TransactionEndRequestValue{Commit: true}
	position := 0
	if isPacket(
		packet.Children[position],
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
	) {
		request.Commit, err = packetBoolean(packet.Children[position])
		if err != nil {
			return TransactionEndRequestValue{}, malformed(
				"txnEndReq commit value is invalid",
			)
		}
		position++
	}
	if position >= len(packet.Children) {
		return TransactionEndRequestValue{}, malformed(
			"txnEndReq transaction identifier is absent",
		)
	}
	request.Identifier, err = packetBytes(packet.Children[position])
	if err != nil {
		return TransactionEndRequestValue{}, malformed(
			"txnEndReq transaction identifier is invalid",
		)
	}
	position++
	if position != len(packet.Children) {
		return TransactionEndRequestValue{}, malformed(
			"txnEndReq elements are invalid",
		)
	}
	return request, nil
}

func EncodeTransactionEndResponseValue(
	response TransactionEndResponseValue,
) []byte {
	if !response.HasFailedMessageID && len(response.UpdateControls) == 0 {
		return nil
	}
	value := ber.NewSequence("txnEndRes")
	if response.HasFailedMessageID {
		value.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			response.FailedMessageID,
			"messageID",
		))
	}
	if len(response.UpdateControls) > 0 {
		updates := ber.NewSequence("updatesControls")
		for _, update := range response.UpdateControls {
			item := ber.NewSequence("updateControls")
			item.AppendChild(ber.NewInteger(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagInteger,
				update.MessageID,
				"messageID",
			))
			item.AppendChild(encodeControls(update.Controls))
			updates.AppendChild(item)
		}
		value.AppendChild(updates)
	}
	return value.Bytes()
}

func DecodeTransactionEndResponseValue(
	value []byte,
) (TransactionEndResponseValue, error) {
	if value == nil {
		return TransactionEndResponseValue{}, nil
	}
	packet, err := decodeTransactionBERValue(value, "txnEndRes")
	if err != nil {
		return TransactionEndResponseValue{}, err
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 1 ||
		len(packet.Children) > 2 {
		return TransactionEndResponseValue{}, malformed(
			"txnEndRes is not a one-or-two-element sequence",
		)
	}

	var response TransactionEndResponseValue
	position := 0
	if position < len(packet.Children) &&
		isPacket(
			packet.Children[position],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
		) {
		response.FailedMessageID, err = packetInteger(packet.Children[position])
		if err != nil ||
			response.FailedMessageID <= 0 ||
			response.FailedMessageID > math.MaxInt32 {
			return TransactionEndResponseValue{}, malformed(
				"txnEndRes messageID is invalid",
			)
		}
		response.HasFailedMessageID = true
		position++
	}
	if position < len(packet.Children) {
		updates := packet.Children[position]
		if !isPacket(
			updates,
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSequence,
		) || len(updates.Children) == 0 {
			return TransactionEndResponseValue{}, malformed(
				"txnEndRes updatesControls is invalid",
			)
		}
		for _, child := range updates.Children {
			if !isPacket(
				child,
				ber.ClassUniversal,
				ber.TypeConstructed,
				ber.TagSequence,
			) || len(child.Children) != 2 {
				return TransactionEndResponseValue{}, malformed(
					"txnEndRes updateControls element is invalid",
				)
			}
			if !isPacket(
				child.Children[0],
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagInteger,
			) {
				return TransactionEndResponseValue{}, malformed(
					"txnEndRes updateControls messageID is invalid",
				)
			}
			messageID, err := packetInteger(child.Children[0])
			if err != nil || messageID <= 0 || messageID > math.MaxInt32 {
				return TransactionEndResponseValue{}, malformed(
					"txnEndRes updateControls messageID is invalid",
				)
			}
			controls, err := decodeControls(child.Children[1])
			if err != nil || len(controls) == 0 {
				return TransactionEndResponseValue{}, malformed(
					"txnEndRes updateControls controls are invalid",
				)
			}
			response.UpdateControls = append(
				response.UpdateControls,
				TransactionUpdateControls{
					MessageID: messageID,
					Controls:  controls,
				},
			)
		}
		position++
	}
	if position != len(packet.Children) {
		return TransactionEndResponseValue{}, malformed(
			"txnEndRes elements are invalid",
		)
	}
	return response, nil
}

func decodeTransactionBERValue(value []byte, name string) (*ber.Packet, error) {
	if len(value) == 0 {
		return nil, malformed("%s is empty", name)
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return nil, malformed("decode %s: %v", name, err)
	}
	if reader.Len() != 0 {
		return nil, malformed("%s has trailing data", name)
	}
	return packet, nil
}
