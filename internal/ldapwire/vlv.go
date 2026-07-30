package ldapwire

import (
	"bytes"
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type VirtualListViewRequest struct {
	BeforeCount    int64
	AfterCount     int64
	ByOffset       bool
	Offset         int64
	ContentCount   int64
	AssertionValue []byte
	ContextID      []byte
	HasContextID   bool
}

type VirtualListViewResponse struct {
	TargetPosition int64
	ContentCount   int64
	Result         ResultCode
	ContextID      []byte
	HasContextID   bool
}

func DecodeVirtualListViewRequestValue(
	value []byte,
) (VirtualListViewRequest, error) {
	if len(value) == 0 {
		return VirtualListViewRequest{}, malformed("VLV request value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return VirtualListViewRequest{}, malformed("decode VLV request value: %v", err)
	}
	if reader.Len() != 0 {
		return VirtualListViewRequest{}, malformed("VLV request value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 3 ||
		len(packet.Children) > 4 {
		return VirtualListViewRequest{}, malformed(
			"VLV request value is not a three-or-four-element sequence",
		)
	}

	beforeCount, err := virtualListViewInteger(packet.Children[0])
	if err != nil {
		return VirtualListViewRequest{}, malformed("VLV beforeCount: %v", err)
	}
	afterCount, err := virtualListViewInteger(packet.Children[1])
	if err != nil {
		return VirtualListViewRequest{}, malformed("VLV afterCount: %v", err)
	}
	request := VirtualListViewRequest{
		BeforeCount: beforeCount,
		AfterCount:  afterCount,
	}
	target := packet.Children[2]
	switch {
	case isPacket(target, ber.ClassContext, ber.TypeConstructed, 0):
		if len(target.Children) != 2 {
			return VirtualListViewRequest{}, malformed(
				"VLV byOffset target is not a two-element sequence",
			)
		}
		request.Offset, err = virtualListViewInteger(target.Children[0])
		if err != nil {
			return VirtualListViewRequest{}, malformed("VLV offset: %v", err)
		}
		request.ContentCount, err = virtualListViewInteger(target.Children[1])
		if err != nil {
			return VirtualListViewRequest{}, malformed("VLV contentCount: %v", err)
		}
		request.ByOffset = true
	case isPacket(target, ber.ClassContext, ber.TypePrimitive, 1):
		request.AssertionValue = bytes.Clone(target.Data.Bytes())
	default:
		return VirtualListViewRequest{}, malformed("VLV target choice is invalid")
	}

	if len(packet.Children) == 4 {
		request.ContextID, err = packetBytes(packet.Children[3])
		if err != nil {
			return VirtualListViewRequest{}, malformed("VLV contextID is invalid")
		}
		request.HasContextID = true
	}
	return request, nil
}

func EncodeVirtualListViewRequestValue(
	request VirtualListViewRequest,
) []byte {
	value := ber.NewSequence("virtualListViewRequest")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		request.BeforeCount,
		"beforeCount",
	))
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		request.AfterCount,
		"afterCount",
	))
	if request.ByOffset {
		target := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			0,
			nil,
			"byOffset",
		)
		target.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			request.Offset,
			"offset",
		))
		target.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			request.ContentCount,
			"contentCount",
		))
		value.AppendChild(target)
	} else {
		target := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			1,
			nil,
			"greaterThanOrEqual",
		)
		_, _ = target.Data.Write(bytes.Clone(request.AssertionValue))
		value.AppendChild(target)
	}
	if request.HasContextID {
		value.AppendChild(octetString(request.ContextID))
	}
	return value.Bytes()
}

func DecodeVirtualListViewResponseValue(
	value []byte,
) (VirtualListViewResponse, error) {
	if len(value) == 0 {
		return VirtualListViewResponse{}, malformed("VLV response value is empty")
	}
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil {
		return VirtualListViewResponse{}, malformed("decode VLV response value: %v", err)
	}
	if reader.Len() != 0 {
		return VirtualListViewResponse{}, malformed("VLV response value has trailing data")
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) < 3 ||
		len(packet.Children) > 4 {
		return VirtualListViewResponse{}, malformed(
			"VLV response value is not a three-or-four-element sequence",
		)
	}

	targetPosition, err := virtualListViewNonnegativeInteger(packet.Children[0])
	if err != nil {
		return VirtualListViewResponse{}, malformed("VLV targetPosition: %v", err)
	}
	contentCount, err := virtualListViewNonnegativeInteger(packet.Children[1])
	if err != nil {
		return VirtualListViewResponse{}, malformed("VLV contentCount: %v", err)
	}
	resultPacket := packet.Children[2]
	if !isPacket(
		resultPacket,
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
	) || resultPacket.Data.Len() == 0 {
		return VirtualListViewResponse{}, malformed(
			"VLV result is not an enumerated value",
		)
	}
	rawResult, err := ber.ParseInt64(resultPacket.Data.Bytes())
	if err != nil || rawResult < 0 || rawResult > math.MaxInt32 {
		return VirtualListViewResponse{}, malformed("VLV result is invalid")
	}
	response := VirtualListViewResponse{
		TargetPosition: targetPosition,
		ContentCount:   contentCount,
		Result:         ResultCode(rawResult),
	}
	if len(packet.Children) == 4 {
		response.ContextID, err = packetBytes(packet.Children[3])
		if err != nil {
			return VirtualListViewResponse{}, malformed("VLV contextID is invalid")
		}
		response.HasContextID = true
	}
	return response, nil
}

func EncodeVirtualListViewResponseValue(
	response VirtualListViewResponse,
) []byte {
	value := ber.NewSequence("virtualListViewResponse")
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		response.TargetPosition,
		"targetPosition",
	))
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		response.ContentCount,
		"contentCount",
	))
	value.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(response.Result),
		"virtualListViewResult",
	))
	if response.HasContextID {
		value.AppendChild(octetString(response.ContextID))
	}
	return value.Bytes()
}

func virtualListViewInteger(packet *ber.Packet) (int64, error) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger) ||
		packet.Data.Len() == 0 {
		return 0, malformed("value is not an integer")
	}
	value, err := ber.ParseInt64(packet.Data.Bytes())
	if err != nil {
		return 0, malformed("integer value is invalid")
	}
	return value, nil
}

func virtualListViewNonnegativeInteger(packet *ber.Packet) (int64, error) {
	value, err := virtualListViewInteger(packet)
	if err != nil {
		return 0, err
	}
	if value < 0 || value > math.MaxInt32 {
		return 0, malformed("integer value is outside maxInt")
	}
	return value, nil
}
