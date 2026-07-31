package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type DynamicRefreshRequestValue struct {
	EntryName  string
	RequestTTL int64
}

func DecodeDynamicRefreshRequestValue(
	value []byte,
	present bool,
) (DynamicRefreshRequestValue, error) {
	if !present {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh request value is absent",
		)
	}
	if len(value) == 0 {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh request value is empty",
		)
	}

	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return DynamicRefreshRequestValue{}, malformed(
			"decode dynamic refresh request value: %v",
			err,
		)
	}
	if reader.Len() != 0 {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh request value has trailing data",
		)
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 2 {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh request value is not a two-element sequence",
		)
	}

	entryName := packet.Children[0]
	if !isPacket(entryName, ber.ClassContext, ber.TypePrimitive, 0) {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh entryName is invalid",
		)
	}
	requestTTL := packet.Children[1]
	if !isPacket(requestTTL, ber.ClassContext, ber.TypePrimitive, 1) ||
		requestTTL.Data.Len() == 0 {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh requestTtl is invalid",
		)
	}
	ttl, err := ber.ParseInt64(requestTTL.Data.Bytes())
	if err != nil || ttl < math.MinInt32 || ttl > math.MaxInt32 {
		return DynamicRefreshRequestValue{}, malformed(
			"dynamic refresh requestTtl is invalid",
		)
	}
	return DynamicRefreshRequestValue{
		EntryName:  string(entryName.Data.Bytes()),
		RequestTTL: ttl,
	}, nil
}

func EncodeDynamicRefreshRequestValue(entryName string, requestTTL int64) []byte {
	request := ber.NewSequence("RefreshRequestValue")
	request.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		entryName,
		"entryName",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		requestTTL,
		"requestTtl",
	))
	return request.Bytes()
}

func DecodeDynamicRefreshResponseValue(value []byte) (int64, error) {
	if len(value) == 0 {
		return 0, malformed("dynamic refresh response value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return 0, malformed("decode dynamic refresh response value: %v", err)
	}
	if reader.Len() != 0 {
		return 0, malformed("dynamic refresh response value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 1 {
		return 0, malformed(
			"dynamic refresh response value is not a one-element sequence",
		)
	}
	responseTTL := packet.Children[0]
	if !isPacket(responseTTL, ber.ClassContext, ber.TypePrimitive, 1) ||
		responseTTL.Data.Len() == 0 {
		return 0, malformed("dynamic refresh responseTtl is invalid")
	}
	ttl, err := ber.ParseInt64(responseTTL.Data.Bytes())
	if err != nil || ttl < 0 || ttl > math.MaxInt32 {
		return 0, malformed("dynamic refresh responseTtl is invalid")
	}
	return ttl, nil
}

func EncodeDynamicRefreshResponseValue(responseTTL int64) []byte {
	response := ber.NewSequence("RefreshResponseValue")
	response.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		responseTTL,
		"responseTtl",
	))
	return response.Bytes()
}
