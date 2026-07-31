package ldapwire

import (
	"bytes"
	"errors"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestTransactionEndRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	for _, request := range []TransactionEndRequestValue{
		{Commit: true, Identifier: []byte{}},
		{Commit: false, Identifier: []byte("transaction-id")},
	} {
		encoded := EncodeTransactionEndRequestValue(request)
		decoded, err := DecodeTransactionEndRequestValue(encoded)
		if err != nil {
			t.Fatalf("DecodeTransactionEndRequestValue(): %v", err)
		}
		if decoded.Commit != request.Commit ||
			!bytes.Equal(decoded.Identifier, request.Identifier) {
			t.Fatalf("decoded request = %#v, want %#v", decoded, request)
		}
	}
}

func TestDecodeTransactionEndRequestValueDefaultsCommit(t *testing.T) {
	t.Parallel()

	value := ber.NewSequence("txnEndReq")
	value.AppendChild(octetString(nil))
	decoded, err := DecodeTransactionEndRequestValue(value.Bytes())
	if err != nil {
		t.Fatalf("DecodeTransactionEndRequestValue(): %v", err)
	}
	if !decoded.Commit || len(decoded.Identifier) != 0 {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestDecodeTransactionEndRequestValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	wrongOrder := ber.NewSequence("txnEndReq")
	wrongOrder.AppendChild(octetString(nil))
	wrongOrder.AppendChild(ber.NewLDAPBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		false,
		"commit",
	))

	for name, value := range map[string][]byte{
		"empty":              nil,
		"not sequence":       octetString(nil).Bytes(),
		"missing identifier": ber.NewSequence("txnEndReq").Bytes(),
		"wrong order":        wrongOrder.Bytes(),
		"trailing data":      append(EncodeTransactionEndRequestValue(TransactionEndRequestValue{Commit: true}), 0),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeTransactionEndRequestValue(value)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}

func TestTransactionEndResponseValueRoundTrip(t *testing.T) {
	t.Parallel()

	response := TransactionEndResponseValue{
		FailedMessageID:    7,
		HasFailedMessageID: true,
		UpdateControls: []TransactionUpdateControls{{
			MessageID: 5,
			Controls: []Control{{
				OID:      "1.3.6.1.1.13.2",
				Critical: true,
				Value:    []byte{0, 1, 2},
				HasValue: true,
			}},
		}},
	}
	encoded := EncodeTransactionEndResponseValue(response)
	decoded, err := DecodeTransactionEndResponseValue(encoded)
	if err != nil {
		t.Fatalf("DecodeTransactionEndResponseValue(): %v", err)
	}
	if !decoded.HasFailedMessageID ||
		decoded.FailedMessageID != response.FailedMessageID ||
		len(decoded.UpdateControls) != 1 ||
		decoded.UpdateControls[0].MessageID != 5 ||
		len(decoded.UpdateControls[0].Controls) != 1 ||
		decoded.UpdateControls[0].Controls[0].OID != "1.3.6.1.1.13.2" ||
		!decoded.UpdateControls[0].Controls[0].Critical ||
		!bytes.Equal(decoded.UpdateControls[0].Controls[0].Value, []byte{0, 1, 2}) {
		t.Fatalf("decoded response = %#v", decoded)
	}
}

func TestTransactionEndResponseValueCanBeAbsent(t *testing.T) {
	t.Parallel()

	if encoded := EncodeTransactionEndResponseValue(
		TransactionEndResponseValue{},
	); encoded != nil {
		t.Fatalf("encoded empty response = %x, want nil", encoded)
	}
	decoded, err := DecodeTransactionEndResponseValue(nil)
	if err != nil || decoded.HasFailedMessageID || len(decoded.UpdateControls) != 0 {
		t.Fatalf("decoded response = %#v, %v", decoded, err)
	}
}

func TestDecodeTransactionEndResponseValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	invalidID := ber.NewSequence("txnEndRes")
	invalidID.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		0,
		"messageID",
	))
	invalidUpdates := ber.NewSequence("txnEndRes")
	invalidUpdates.AppendChild(octetString(nil))
	emptyUpdates := ber.NewSequence("txnEndRes")
	emptyUpdates.AppendChild(ber.NewSequence("updatesControls"))
	enumeratedUpdateID := ber.NewSequence("txnEndRes")
	enumeratedUpdates := ber.NewSequence("updatesControls")
	enumeratedUpdate := ber.NewSequence("updateControls")
	enumeratedUpdate.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		1,
		"messageID",
	))
	enumeratedUpdate.AppendChild(encodeControls([]Control{{OID: "1.2.3"}}))
	enumeratedUpdates.AppendChild(enumeratedUpdate)
	enumeratedUpdateID.AppendChild(enumeratedUpdates)
	emptyControls := ber.NewSequence("txnEndRes")
	emptyControlUpdates := ber.NewSequence("updatesControls")
	emptyControlUpdate := ber.NewSequence("updateControls")
	emptyControlUpdate.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		1,
		"messageID",
	))
	emptyControlUpdate.AppendChild(encodeControls(nil))
	emptyControlUpdates.AppendChild(emptyControlUpdate)
	emptyControls.AppendChild(emptyControlUpdates)

	for name, value := range map[string][]byte{
		"empty sequence":        ber.NewSequence("txnEndRes").Bytes(),
		"invalid message ID":    invalidID.Bytes(),
		"invalid updates":       invalidUpdates.Bytes(),
		"empty updates":         emptyUpdates.Bytes(),
		"enumerated update ID":  enumeratedUpdateID.Bytes(),
		"empty update controls": emptyControls.Bytes(),
		"trailing data": append(
			EncodeTransactionEndResponseValue(TransactionEndResponseValue{
				FailedMessageID:    1,
				HasFailedMessageID: true,
			}),
			0,
		),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeTransactionEndResponseValue(value)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}
