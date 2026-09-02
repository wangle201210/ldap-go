package ldapwire

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestDerefControlOIDAndWireFixtures(t *testing.T) {
	t.Parallel()

	if DerefControlOID != "1.3.6.1.4.1.4203.666.5.16" {
		t.Fatalf("DerefControlOID = %q", DerefControlOID)
	}

	requestFixture := []byte{
		0x30, 0x11,
		0x30, 0x0f,
		0x04, 0x06, 'm', 'e', 'm', 'b', 'e', 'r',
		0x30, 0x05,
		0x04, 0x03, 'u', 'i', 'd',
	}
	specs, err := DecodeDerefRequestValue(requestFixture)
	if err != nil {
		t.Fatalf("DecodeDerefRequestValue(fixture): %v", err)
	}
	if !reflect.DeepEqual(specs, []DerefSpec{{
		DerefAttr:  "member",
		Attributes: []string{"uid"},
	}}) {
		t.Fatalf("decoded fixture = %#v", specs)
	}

	response, err := EncodeDerefResponseValue([]DerefResult{{
		DerefAttr: "member",
		Attributes: []DerefAttribute{{
			Type:   "uid",
			Values: [][]byte{{0x00, 0xff}},
		}},
	}})
	if err != nil {
		t.Fatalf("EncodeDerefResponseValue(fixture): %v", err)
	}
	responseFixture := []byte{
		0x30, 0x1b,
		0x30, 0x19,
		0x04, 0x06, 'm', 'e', 'm', 'b', 'e', 'r',
		0x04, 0x00,
		0xa0, 0x0d,
		0x30, 0x0b,
		0x04, 0x03, 'u', 'i', 'd',
		0x31, 0x04,
		0x04, 0x02, 0x00, 0xff,
	}
	if !bytes.Equal(response, responseFixture) {
		t.Fatalf("encoded fixture = %x, want %x", response, responseFixture)
	}
}

func TestEncodeDerefRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	want := []DerefSpec{
		{DerefAttr: "seeAlso", Attributes: []string{"uid", "cn"}},
		{DerefAttr: "manager", Attributes: []string{"mail"}},
	}
	encoded, err := EncodeDerefRequestValue(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDerefRequestValue(encoded)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("deref round trip = %#v, %v; want %#v", got, err, want)
	}
	for _, invalid := range [][]DerefSpec{
		nil,
		{{DerefAttr: "seeAlso"}},
		{{DerefAttr: "bad attr", Attributes: []string{"uid"}}},
		{{DerefAttr: "seeAlso", Attributes: []string{"uid", "UID"}}},
	} {
		if _, err := EncodeDerefRequestValue(invalid); err == nil {
			t.Fatalf("EncodeDerefRequestValue(%#v) succeeded", invalid)
		}
	}
}

func TestDecodeDerefRequestValue(t *testing.T) {
	t.Parallel()

	want := []DerefSpec{
		{
			DerefAttr:  "member",
			Attributes: []string{"uid", "jpegPhoto;binary"},
		},
		{
			DerefAttr:  "manager",
			Attributes: []string{"cn", "1.2.840.113556.1.4.221"},
		},
	}
	got, err := DecodeDerefRequestValue(encodeDerefRequestForTest(want))
	if err != nil {
		t.Fatalf("DecodeDerefRequestValue(): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded deref request = %#v, want %#v", got, want)
	}
}

func TestDecodeDerefRequestValueAcceptsEncodedEmptySequence(t *testing.T) {
	t.Parallel()

	specs, err := DecodeDerefRequestValue([]byte{0x30, 0x00})
	if err != nil {
		t.Fatalf("DecodeDerefRequestValue(): %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("decoded deref request = %#v, want no specifications", specs)
	}
}

func TestDecodeDerefRequestValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	valid := encodeDerefRequestForTest([]DerefSpec{{
		DerefAttr:  "member",
		Attributes: []string{"uid"},
	}})
	wrongSpec := ber.NewSequence("request")
	wrongSpec.AppendChild(octetString([]byte("not-a-spec")))
	missingAttributeList := ber.NewSequence("request")
	missingAttributeList.AppendChild(derefSpecPacketForTest("member", nil, false))
	extraSpecElement := ber.NewSequence("request")
	extraSpec := derefSpecPacketForTest("member", []string{"uid"}, true)
	extraSpec.AppendChild(octetString([]byte("extra")))
	extraSpecElement.AppendChild(extraSpec)
	wrongDerefAttrTag := ber.NewSequence("request")
	wrongDerefSpec := ber.NewSequence("spec")
	wrongDerefSpec.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"derefAttr",
	))
	wrongDerefSpec.AppendChild(derefAttributeListPacketForTest("uid"))
	wrongDerefAttrTag.AppendChild(wrongDerefSpec)
	wrongAttributeListTag := ber.NewSequence("request")
	wrongListSpec := ber.NewSequence("spec")
	wrongListSpec.AppendChild(octetString([]byte("member")))
	wrongListSpec.AppendChild(octetString([]byte("uid")))
	wrongAttributeListTag.AppendChild(wrongListSpec)
	emptyAttributeList := ber.NewSequence("request")
	emptyListSpec := ber.NewSequence("spec")
	emptyListSpec.AppendChild(octetString([]byte("member")))
	emptyListSpec.AppendChild(ber.NewSequence("attributes"))
	emptyAttributeList.AppendChild(emptyListSpec)
	wrongAttributeTag := ber.NewSequence("request")
	wrongAttributeSpec := ber.NewSequence("spec")
	wrongAttributeSpec.AppendChild(octetString([]byte("member")))
	wrongAttributes := ber.NewSequence("attributes")
	wrongAttributes.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(1),
		"attribute",
	))
	wrongAttributeSpec.AppendChild(wrongAttributes)
	wrongAttributeTag.AppendChild(wrongAttributeSpec)
	duplicate := encodeDerefRequestForTest([]DerefSpec{
		{DerefAttr: "member;binary;lang-en", Attributes: []string{"uid"}},
		{DerefAttr: "MEMBER;LANG-EN;BINARY", Attributes: []string{"cn"}},
	})

	tests := map[string][]byte{
		"absent":                   nil,
		"wrong outer tag":          append([]byte{0x31}, valid[1:]...),
		"trailing data":            append(bytes.Clone(valid), 0x00),
		"truncated":                bytes.Clone(valid[:len(valid)-1]),
		"indefinite length":        {0x30, 0x80, 0x00, 0x00},
		"wrong spec tag":           wrongSpec.Bytes(),
		"missing attribute list":   missingAttributeList.Bytes(),
		"extra spec element":       extraSpecElement.Bytes(),
		"wrong derefAttr tag":      wrongDerefAttrTag.Bytes(),
		"empty derefAttr":          encodeDerefRequestForTest([]DerefSpec{{DerefAttr: "", Attributes: []string{"uid"}}}),
		"invalid derefAttr":        encodeDerefRequestForTest([]DerefSpec{{DerefAttr: "member name", Attributes: []string{"uid"}}}),
		"wrong attribute list tag": wrongAttributeListTag.Bytes(),
		"empty attribute list":     emptyAttributeList.Bytes(),
		"wrong attribute tag":      wrongAttributeTag.Bytes(),
		"empty attribute":          encodeDerefRequestForTest([]DerefSpec{{DerefAttr: "member", Attributes: []string{""}}}),
		"duplicate derefAttr":      duplicate,
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeDerefRequestValue(value); !errors.Is(
				err,
				ErrMalformedMessage,
			) {
				t.Fatalf("DecodeDerefRequestValue(%x) error = %v", value, err)
			}
		})
	}
}

func TestDecodeDerefRequestValueResourceLimits(t *testing.T) {
	t.Parallel()

	tooManySpecs := make([]DerefSpec, maxDerefSpecs+1)
	for index := range tooManySpecs {
		tooManySpecs[index] = DerefSpec{
			DerefAttr:  "member" + string(rune('a'+index%26)) + string(rune('a'+index/26)),
			Attributes: []string{"uid"},
		}
	}
	tooManyAttributes := make([]string, maxDerefAttributesPerSpec+1)
	for index := range tooManyAttributes {
		tooManyAttributes[index] = "attr" + string(rune('a'+index%26)) + string(rune('a'+index/26))
	}
	tooManyTotalAttributes := make([]DerefSpec, maxDerefRequestAttributes/maxDerefAttributesPerSpec+1)
	for specIndex := range tooManyTotalAttributes {
		attributes := make([]string, maxDerefAttributesPerSpec)
		for attributeIndex := range attributes {
			attributes[attributeIndex] = fmt.Sprintf(
				"attr%d%c",
				specIndex,
				'a'+rune(attributeIndex%26),
			)
		}
		tooManyTotalAttributes[specIndex] = DerefSpec{
			DerefAttr:  fmt.Sprintf("member%d", specIndex),
			Attributes: attributes,
		}
	}
	tooLongDescription := "a" + strings.Repeat("b", maxDerefAttributeDescriptionBytes)

	tests := map[string][]byte{
		"control bytes":  make([]byte, DefaultMaxMessageSize+1),
		"specifications": encodeDerefRequestForTest(tooManySpecs),
		"attributes per spec": encodeDerefRequestForTest([]DerefSpec{{
			DerefAttr:  "member",
			Attributes: tooManyAttributes,
		}}),
		"total attributes": encodeDerefRequestForTest(tooManyTotalAttributes),
		"attribute description bytes": encodeDerefRequestForTest([]DerefSpec{{
			DerefAttr:  tooLongDescription,
			Attributes: []string{"uid"},
		}}),
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeDerefRequestValue(value); !errors.Is(
				err,
				ErrMalformedMessage,
			) {
				t.Fatalf("DecodeDerefRequestValue() error = %v", err)
			}
		})
	}
}

func TestEncodeDerefResponseValue(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeDerefResponseValue([]DerefResult{
		{
			DerefAttr:  "member",
			DerefValue: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []DerefAttribute{
				{Type: "uid", Values: [][]byte{[]byte("alice"), []byte("a.smith")}},
				{Type: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
				{Type: "description", Values: [][]byte{{}}},
				{Type: "sn"},
			},
		},
		{
			DerefAttr:  "manager",
			DerefValue: "",
		},
	})
	if err != nil {
		t.Fatalf("EncodeDerefResponseValue(): %v", err)
	}

	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("DecodePacketErr(): %v", err)
	}
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 2 {
		t.Fatalf("deref response packet = %#v", packet)
	}
	first := packet.Children[0]
	if !isPacket(first, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(first.Children) != 3 ||
		first.Children[0].Data.String() != "member" ||
		first.Children[1].Data.String() != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("first deref result = %#v", first)
	}
	attributes := first.Children[2]
	if !isPacket(attributes, ber.ClassContext, ber.TypeConstructed, 0) ||
		len(attributes.Children) != 3 {
		t.Fatalf("deref attrVals = %#v", attributes)
	}
	assertDerefPartialAttributeForTest(
		t,
		attributes.Children[0],
		"uid",
		[][]byte{[]byte("alice"), []byte("a.smith")},
	)
	assertDerefPartialAttributeForTest(
		t,
		attributes.Children[1],
		"jpegPhoto",
		[][]byte{{0x00, 0xff, 0x10}},
	)
	assertDerefPartialAttributeForTest(
		t,
		attributes.Children[2],
		"description",
		[][]byte{{}},
	)

	second := packet.Children[1]
	if !isPacket(second, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(second.Children) != 2 ||
		second.Children[0].Data.String() != "manager" ||
		len(second.Children[1].Data.Bytes()) != 0 {
		t.Fatalf("second deref result = %#v", second)
	}
}

func TestDecodeDerefResponseValueRoundTrip(t *testing.T) {
	t.Parallel()

	want := []DerefResult{
		{
			DerefAttr:  "member",
			DerefValue: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []DerefAttribute{
				{Type: "uid", Values: [][]byte{[]byte("alice"), []byte("a.smith")}},
				{Type: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}}},
				{Type: "description", Values: [][]byte{{}}},
			},
		},
		{DerefAttr: "manager", DerefValue: ""},
	}
	encoded, err := EncodeDerefResponseValue(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeDerefResponseValue(encoded)
	if err != nil {
		t.Fatalf("DecodeDerefResponseValue(): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded deref response = %#v, want %#v", got, want)
	}

	got[0].Attributes[0].Values[0][0] = 'X'
	again, err := DecodeDerefResponseValue(encoded)
	if err != nil || string(again[0].Attributes[0].Values[0]) != "alice" {
		t.Fatalf("decoded deref values alias input or prior output: %#v, %v", again, err)
	}
}

func TestDecodeDerefResponseValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"empty":                nil,
		"wrong outer tag":      {0x31, 0x00},
		"trailing data":        {0x30, 0x00, 0x00},
		"wrong result tag":     {0x30, 0x02, 0x31, 0x00},
		"missing deref value":  {0x30, 0x05, 0x30, 0x03, 0x04, 0x01, 'a'},
		"invalid deref value":  {0x30, 0x08, 0x30, 0x06, 0x04, 0x01, 'a', 0x04, 0x01, 0xff},
		"wrong attributes tag": {0x30, 0x0b, 0x30, 0x09, 0x04, 0x01, 'a', 0x04, 0x00, 0x30, 0x02, 0x04, 0x00},
		"empty attributes":     {0x30, 0x09, 0x30, 0x07, 0x04, 0x01, 'a', 0x04, 0x00, 0xa0, 0x00},
		"empty value set":      {0x30, 0x10, 0x30, 0x0e, 0x04, 0x01, 'a', 0x04, 0x00, 0xa0, 0x07, 0x30, 0x05, 0x04, 0x01, 'b', 0x31, 0x00},
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if decoded, err := DecodeDerefResponseValue(value); !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("DecodeDerefResponseValue(%x) = %#v, %v", value, decoded, err)
			}
		})
	}
}

func TestEncodeDerefResponseValueEmpty(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeDerefResponseValue(nil)
	if err != nil {
		t.Fatalf("EncodeDerefResponseValue(): %v", err)
	}
	if !bytes.Equal(encoded, []byte{0x30, 0x00}) {
		t.Fatalf("empty deref response = %x, want 3000", encoded)
	}
}

func TestEncodeDerefResponseValueRejectsInvalidOrOversizedData(t *testing.T) {
	t.Parallel()

	tooManyResults := make([]DerefResult, maxDerefResults+1)
	tooManyAttributes := make([]DerefAttribute, maxDerefAttributesPerResult+1)
	maxAttributes := make([]DerefAttribute, maxDerefAttributesPerResult)
	for index := range maxAttributes {
		maxAttributes[index] = DerefAttribute{Type: "uid"}
	}
	tooManyTotalAttributes := make([]DerefResult, maxDerefResponseAttributes/maxDerefAttributesPerResult+1)
	for index := range tooManyTotalAttributes {
		tooManyTotalAttributes[index] = DerefResult{
			DerefAttr:  "member",
			Attributes: maxAttributes,
		}
	}
	tooManyValues := make([][]byte, maxDerefValuesPerAttribute+1)
	maxValues := make([][]byte, maxDerefValuesPerAttribute)
	tooManyTotalValueAttributes := make(
		[]DerefAttribute,
		maxDerefResponseValues/maxDerefValuesPerAttribute+1,
	)
	for index := range tooManyTotalValueAttributes {
		tooManyTotalValueAttributes[index] = DerefAttribute{
			Type:   "uid",
			Values: maxValues,
		}
	}
	tests := map[string][]DerefResult{
		"too many results":           tooManyResults,
		"too many result attributes": {{DerefAttr: "member", Attributes: tooManyAttributes}},
		"too many total attributes":  tooManyTotalAttributes,
		"too many total values": {{
			DerefAttr:  "member",
			Attributes: tooManyTotalValueAttributes,
		}},
		"invalid derefAttr": {{DerefAttr: "member name"}},
		"invalid derefValue UTF-8": {{
			DerefAttr:  "member",
			DerefValue: string([]byte{0xff}),
		}},
		"invalid result attribute": {{
			DerefAttr:  "member",
			Attributes: []DerefAttribute{{Type: "bad attribute", Values: [][]byte{{1}}}},
		}},
		"too many values": {{
			DerefAttr:  "member",
			Attributes: []DerefAttribute{{Type: "uid", Values: tooManyValues}},
		}},
		"payload bytes": {{
			DerefAttr: "member",
			Attributes: []DerefAttribute{{
				Type:   "jpegPhoto",
				Values: [][]byte{make([]byte, DefaultMaxMessageSize)},
			}},
		}},
	}
	for name, results := range tests {
		name, results := name, results
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if encoded, err := EncodeDerefResponseValue(results); err == nil {
				t.Fatalf("EncodeDerefResponseValue() = %x, want error", encoded)
			}
		})
	}
}

func FuzzDecodeDerefRequestValue(f *testing.F) {
	valid := encodeDerefRequestForTest([]DerefSpec{{
		DerefAttr:  "member",
		Attributes: []string{"uid", "jpegPhoto"},
	}})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add(valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, value []byte) {
		specs, err := DecodeDerefRequestValue(value)
		if err != nil {
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("DecodeDerefRequestValue() error = %v", err)
			}
			return
		}
		if len(specs) > maxDerefSpecs {
			t.Fatalf("decoded deref specs = %#v", specs)
		}
		for _, spec := range specs {
			if spec.DerefAttr == "" || len(spec.Attributes) == 0 ||
				len(spec.Attributes) > maxDerefAttributesPerSpec {
				t.Fatalf("decoded deref spec = %#v", spec)
			}
		}
	})
}

func FuzzDecodeDerefResponseValue(f *testing.F) {
	valid, err := EncodeDerefResponseValue([]DerefResult{{
		DerefAttr:  "member",
		DerefValue: "uid=alice,dc=example,dc=com",
		Attributes: []DerefAttribute{{
			Type: "uid", Values: [][]byte{[]byte("alice"), {0x00, 0xff}},
		}},
	}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add(valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, value []byte) {
		results, err := DecodeDerefResponseValue(value)
		if err != nil {
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("DecodeDerefResponseValue() error = %v", err)
			}
			return
		}
		if len(results) > maxDerefResults {
			t.Fatalf("decoded deref results = %d", len(results))
		}
		for _, result := range results {
			if result.DerefAttr == "" || len(result.Attributes) > maxDerefAttributesPerResult {
				t.Fatalf("decoded deref result = %#v", result)
			}
			for _, attribute := range result.Attributes {
				if attribute.Type == "" || len(attribute.Values) == 0 ||
					len(attribute.Values) > maxDerefValuesPerAttribute {
					t.Fatalf("decoded deref attribute = %#v", attribute)
				}
			}
		}
	})
}

func encodeDerefRequestForTest(specs []DerefSpec) []byte {
	request := ber.NewSequence("derefRequestValue")
	for _, spec := range specs {
		request.AppendChild(derefSpecPacketForTest(
			spec.DerefAttr,
			spec.Attributes,
			true,
		))
	}
	return request.Bytes()
}

func derefSpecPacketForTest(
	derefAttr string,
	attributes []string,
	includeAttributeList bool,
) *ber.Packet {
	spec := ber.NewSequence("derefSpec")
	spec.AppendChild(octetString([]byte(derefAttr)))
	if includeAttributeList {
		spec.AppendChild(derefAttributeListPacketForTest(attributes...))
	}
	return spec
}

func derefAttributeListPacketForTest(attributes ...string) *ber.Packet {
	list := ber.NewSequence("AttributeList")
	for _, attribute := range attributes {
		list.AppendChild(octetString([]byte(attribute)))
	}
	return list
}

func assertDerefPartialAttributeForTest(
	t *testing.T,
	packet *ber.Packet,
	wantType string,
	wantValues [][]byte,
) {
	t.Helper()
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) ||
		len(packet.Children) != 2 ||
		packet.Children[0].Data.String() != wantType {
		t.Fatalf("partial attribute = %#v, want type %q", packet, wantType)
	}
	values := packet.Children[1]
	if !isPacket(values, ber.ClassUniversal, ber.TypeConstructed, ber.TagSet) ||
		len(values.Children) != len(wantValues) {
		t.Fatalf("partial attribute values = %#v, want %#v", values, wantValues)
	}
	for index, want := range wantValues {
		if !isPacket(
			values.Children[index],
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
		) || !bytes.Equal(values.Children[index].Data.Bytes(), want) {
			t.Fatalf(
				"partial attribute value %d = %x, want %x",
				index,
				values.Children[index].Data.Bytes(),
				want,
			)
		}
	}
}
