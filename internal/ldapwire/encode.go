package ldapwire

import (
	"bytes"
	"fmt"
	"io"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func EncodeBindResponse(messageID int64, result Result, controls []Control) []byte {
	return encodeResultMessage(messageID, ApplicationBindResponse, result, controls)
}

func EncodeSASLBindResponse(
	messageID int64,
	result Result,
	serverCredentials []byte,
	hasServerCredentials bool,
	controls []Control,
) []byte {
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationBindResponse,
		nil,
		"BindResponse",
	)
	appendLDAPResult(response, result)
	if hasServerCredentials {
		credentials := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			7,
			nil,
			"serverSaslCreds",
		)
		_, _ = credentials.Data.Write(bytes.Clone(serverCredentials))
		response.AppendChild(credentials)
	}
	return encodeMessage(messageID, response, controls)
}

func EncodeSearchResultDone(messageID int64, result Result, controls []Control) []byte {
	return encodeResultMessage(messageID, ApplicationSearchResultDone, result, controls)
}

func EncodeExtendedResponse(
	messageID int64,
	result Result,
	responseName string,
	responseValue []byte,
	controls []Control,
) []byte {
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationExtendedResponse,
		nil,
		"ExtendedResponse",
	)
	appendLDAPResult(response, result)
	if responseName != "" {
		response.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			10,
			responseName,
			"responseName",
		))
	}
	if responseValue != nil {
		response.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			11,
			string(responseValue),
			"responseValue",
		))
	}
	return encodeMessage(messageID, response, controls)
}

func EncodeIntermediateResponse(
	messageID int64,
	responseName string,
	responseValue []byte,
	controls []Control,
) []byte {
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationIntermediateResponse,
		nil,
		"IntermediateResponse",
	)
	if responseName != "" {
		response.AppendChild(ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			0,
			responseName,
			"responseName",
		))
	}
	if responseValue != nil {
		value := ber.Encode(
			ber.ClassContext,
			ber.TypePrimitive,
			1,
			nil,
			"responseValue",
		)
		_, _ = value.Data.Write(bytes.Clone(responseValue))
		response.AppendChild(value)
	}
	return encodeMessage(messageID, response, controls)
}

func EncodeResultResponse(messageID int64, applicationTag uint64, result Result, controls []Control) []byte {
	return encodeResultMessage(messageID, applicationTag, result, controls)
}

func EncodeSearchResultEntry(messageID int64, entry directory.Entry, controls []Control) []byte {
	return encodeMessage(messageID, encodeSearchResultEntry(entry), controls)
}

func EncodeSearchResultReference(
	messageID int64,
	referrals []string,
	controls []Control,
) []byte {
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationSearchResultReference,
		nil,
		"SearchResultReference",
	)
	for _, referral := range referrals {
		response.AppendChild(octetString([]byte(referral)))
	}
	return encodeMessage(messageID, response, controls)
}

func EncodeReadControlValue(entry directory.Entry) []byte {
	return encodeSearchResultEntry(entry).Bytes()
}

func encodeSearchResultEntry(entry directory.Entry) *ber.Packet {
	response := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ApplicationSearchResultEntry,
		nil,
		"SearchResultEntry",
	)
	response.AppendChild(octetString([]byte(entry.DN)))

	attributes := ber.NewSequence("PartialAttributeList")
	for _, attribute := range entry.Attributes {
		partial := ber.NewSequence("PartialAttribute")
		partial.AppendChild(octetString([]byte(attribute.Description)))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "SET OF values")
		for _, value := range attribute.Values {
			values.AppendChild(octetString(value))
		}
		partial.AppendChild(values)
		attributes.AppendChild(partial)
	}
	response.AppendChild(attributes)
	return response
}

func EncodeNoticeOfDisconnection(result Result) []byte {
	return EncodeExtendedResponse(
		0,
		result,
		"1.3.6.1.4.1.1466.20036",
		nil,
		nil,
	)
}

func Write(writer io.Writer, encoded []byte) error {
	for len(encoded) > 0 {
		written, err := writer.Write(encoded)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

func encodeResultMessage(messageID int64, tag uint64, result Result, controls []Control) []byte {
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, "LDAPResult")
	appendLDAPResult(response, result)
	return encodeMessage(messageID, response, controls)
}

func appendLDAPResult(packet *ber.Packet, result Result) {
	packet.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(result.Code),
		"resultCode",
	))
	packet.AppendChild(octetString([]byte(result.MatchedDN)))
	packet.AppendChild(octetString([]byte(result.DiagnosticMessage)))
	if len(result.Referrals) > 0 {
		referral := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "referral")
		for _, uri := range result.Referrals {
			referral.AppendChild(octetString([]byte(uri)))
		}
		packet.AppendChild(referral)
	}
}

func encodeMessage(messageID int64, operation *ber.Packet, controls []Control) []byte {
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	message.AppendChild(operation)
	if len(controls) > 0 {
		message.AppendChild(encodeControls(controls))
	}
	return message.Bytes()
}

func encodeControls(controls []Control) *ber.Packet {
	wrapper := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	for _, control := range controls {
		packet := ber.NewSequence("Control")
		packet.AppendChild(octetString([]byte(control.OID)))
		if control.Critical {
			packet.AppendChild(ber.NewLDAPBoolean(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagBoolean,
				true,
				"criticality",
			))
		}
		if control.HasValue || control.Value != nil {
			packet.AppendChild(octetString(control.Value))
		}
		wrapper.AppendChild(packet)
	}
	return wrapper
}

func octetString(value []byte) *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"LDAPString",
	)
	_, _ = packet.Data.Write(bytes.Clone(value))
	return packet
}

func ResultError(code ResultCode, diagnostic string) Result {
	return Result{Code: code, DiagnosticMessage: diagnostic}
}

func (code ResultCode) String() string {
	return fmt.Sprintf("LDAP result %d", code)
}
