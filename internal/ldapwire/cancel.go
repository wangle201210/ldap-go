package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func EncodeCancelRequestValue(messageID int64) []byte {
	value := ber.NewSequence("cancelRequestValue")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"cancelID",
	))
	return value.Bytes()
}

func DecodeCancelRequestValue(value []byte) (int64, error) {
	reader := bytes.NewReader(value)
	frame, err := readFrame(reader, int64(len(value)))
	if err != nil {
		return 0, malformed("decode cancelRequestValue: %v", err)
	}
	if reader.Len() != 0 {
		return 0, malformed("cancelRequestValue has trailing data")
	}
	packet, err := ber.DecodePacketErr(frame)
	if err != nil {
		return 0, malformed("decode cancelRequestValue: %v", err)
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 1 {
		return 0, malformed("invalid cancelRequestValue")
	}
	messageID, err := packetInteger(packet.Children[0])
	if err != nil || messageID <= 0 || messageID > math.MaxInt32 {
		return 0, malformed("invalid cancelID")
	}
	return messageID, nil
}
