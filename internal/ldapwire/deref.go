package ldapwire

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const DerefControlOID = "1.3.6.1.4.1.4203.666.5.16"

const (
	maxDerefSpecs                     = 256
	maxDerefAttributesPerSpec         = 256
	maxDerefRequestAttributes         = 4096
	maxDerefResults                   = 4096
	maxDerefAttributesPerResult       = 256
	maxDerefResponseAttributes        = 16384
	maxDerefValuesPerAttribute        = 1024
	maxDerefResponseValues            = 65536
	maxDerefAttributeDescriptionBytes = 1024
)

// DerefSpec identifies a DN-valued attribute and the attributes to read from
// each referenced entry.
type DerefSpec struct {
	DerefAttr  string
	Attributes []string
}

// DerefAttribute is one partial attribute in a dereference result.
type DerefAttribute struct {
	Type   string
	Values [][]byte
}

// DerefResult contains one dereferenced DN value and its readable attributes.
type DerefResult struct {
	DerefAttr  string
	DerefValue string
	Attributes []DerefAttribute
}

// DecodeDerefRequestValue decodes the value of an OpenLDAP dereference
// request control. Attribute existence and DN syntax are schema concerns and
// are intentionally left to the server layer.
func DecodeDerefRequestValue(value []byte) ([]DerefSpec, error) {
	if len(value) == 0 {
		return nil, malformed("deref request value is empty")
	}
	if int64(len(value)) > DefaultMaxMessageSize {
		return nil, malformed(
			"deref request value exceeds %d-byte limit",
			DefaultMaxMessageSize,
		)
	}

	outer, trailing, err := readDerefBERElement(value)
	if err != nil {
		return nil, malformed("decode deref request value: %v", err)
	}
	if len(trailing) != 0 {
		return nil, malformed("deref request value has trailing data")
	}
	if outer.identifier != 0x30 {
		return nil, malformed("deref request value is not a sequence")
	}
	specs := make([]DerefSpec, 0)
	seenDerefAttributes := make(map[string]struct{})
	totalAttributes := 0
	remaining := outer.content
	for len(remaining) != 0 {
		if len(specs) == maxDerefSpecs {
			return nil, malformed(
				"deref request contains more than %d specifications",
				maxDerefSpecs,
			)
		}

		var encodedSpec derefBERElement
		encodedSpec, remaining, err = readDerefBERElement(remaining)
		if err != nil {
			return nil, malformed(
				"decode deref specification %d: %v",
				len(specs),
				err,
			)
		}
		if encodedSpec.identifier != 0x30 {
			return nil, malformed(
				"deref specification %d is not a sequence",
				len(specs),
			)
		}

		spec, canonicalAttribute, err := decodeDerefSpec(
			encodedSpec.content,
			len(specs),
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenDerefAttributes[canonicalAttribute]; duplicate {
			return nil, malformed(
				"derefAttr %q is specified more than once",
				spec.DerefAttr,
			)
		}
		seenDerefAttributes[canonicalAttribute] = struct{}{}

		if len(spec.Attributes) > maxDerefRequestAttributes-totalAttributes {
			return nil, malformed(
				"deref request contains more than %d requested attributes",
				maxDerefRequestAttributes,
			)
		}
		totalAttributes += len(spec.Attributes)
		specs = append(specs, spec)
	}

	return specs, nil
}

func decodeDerefSpec(
	content []byte,
	index int,
) (DerefSpec, string, error) {
	derefAttribute, remaining, err := readDerefBERElement(content)
	if err != nil {
		return DerefSpec{}, "", malformed(
			"decode deref specification %d derefAttr: %v",
			index,
			err,
		)
	}
	if derefAttribute.identifier != 0x04 {
		return DerefSpec{}, "", malformed(
			"deref specification %d derefAttr is not an octet string",
			index,
		)
	}
	canonicalAttribute, err := canonicalDerefAttributeDescription(
		string(derefAttribute.content),
	)
	if err != nil {
		return DerefSpec{}, "", malformed(
			"deref specification %d derefAttr is invalid: %v",
			index,
			err,
		)
	}

	attributeList, trailing, err := readDerefBERElement(remaining)
	if err != nil {
		return DerefSpec{}, "", malformed(
			"decode deref specification %d attribute list: %v",
			index,
			err,
		)
	}
	if len(trailing) != 0 {
		return DerefSpec{}, "", malformed(
			"deref specification %d has extra elements",
			index,
		)
	}
	if attributeList.identifier != 0x30 {
		return DerefSpec{}, "", malformed(
			"deref specification %d attribute list is not a sequence",
			index,
		)
	}
	if len(attributeList.content) == 0 {
		return DerefSpec{}, "", malformed(
			"deref specification %d attribute list is empty",
			index,
		)
	}

	attributes := make([]string, 0)
	remainingAttributes := attributeList.content
	for len(remainingAttributes) != 0 {
		if len(attributes) == maxDerefAttributesPerSpec {
			return DerefSpec{}, "", malformed(
				"deref specification %d contains more than %d attributes",
				index,
				maxDerefAttributesPerSpec,
			)
		}
		var attribute derefBERElement
		attribute, remainingAttributes, err = readDerefBERElement(
			remainingAttributes,
		)
		if err != nil {
			return DerefSpec{}, "", malformed(
				"decode deref specification %d attribute %d: %v",
				index,
				len(attributes),
				err,
			)
		}
		if attribute.identifier != 0x04 {
			return DerefSpec{}, "", malformed(
				"deref specification %d attribute %d is not an octet string",
				index,
				len(attributes),
			)
		}
		attributeDescription := string(attribute.content)
		if _, err := canonicalDerefAttributeDescription(attributeDescription); err != nil {
			return DerefSpec{}, "", malformed(
				"deref specification %d attribute %d is invalid: %v",
				index,
				len(attributes),
				err,
			)
		}
		attributes = append(attributes, attributeDescription)
	}

	return DerefSpec{
		DerefAttr:  string(derefAttribute.content),
		Attributes: attributes,
	}, canonicalAttribute, nil
}

// EncodeDerefResponseValue encodes the value of an OpenLDAP dereference
// response control. Partial attributes with no values are omitted as required
// by the dereference control specification.
func EncodeDerefResponseValue(results []DerefResult) ([]byte, error) {
	if err := validateDerefResponse(results); err != nil {
		return nil, err
	}

	controlValue := ber.NewSequence("derefResponseValue")
	for _, result := range results {
		encodedResult := ber.NewSequence("derefRes")
		encodedResult.AppendChild(octetString([]byte(result.DerefAttr)))
		encodedResult.AppendChild(octetString([]byte(result.DerefValue)))

		var encodedAttributes *ber.Packet
		for _, attribute := range result.Attributes {
			if len(attribute.Values) == 0 {
				continue
			}
			if encodedAttributes == nil {
				encodedAttributes = ber.Encode(
					ber.ClassContext,
					ber.TypeConstructed,
					0,
					nil,
					"attrVals",
				)
			}

			partialAttribute := ber.NewSequence("PartialAttribute")
			partialAttribute.AppendChild(octetString([]byte(attribute.Type)))
			values := ber.Encode(
				ber.ClassUniversal,
				ber.TypeConstructed,
				ber.TagSet,
				nil,
				"SET OF values",
			)
			for _, value := range attribute.Values {
				values.AppendChild(octetString(value))
			}
			partialAttribute.AppendChild(values)
			encodedAttributes.AppendChild(partialAttribute)
		}
		if encodedAttributes != nil {
			encodedResult.AppendChild(encodedAttributes)
		}
		controlValue.AppendChild(encodedResult)
	}

	encoded := controlValue.Bytes()
	if int64(len(encoded)) > DefaultMaxMessageSize {
		return nil, fmt.Errorf(
			"encode deref response: value exceeds %d-byte limit",
			DefaultMaxMessageSize,
		)
	}
	return encoded, nil
}

func validateDerefResponse(results []DerefResult) error {
	if len(results) > maxDerefResults {
		return fmt.Errorf(
			"encode deref response: more than %d results",
			maxDerefResults,
		)
	}

	totalAttributes := 0
	totalValues := 0
	payloadBytes := int64(0)
	for resultIndex, result := range results {
		if _, err := canonicalDerefAttributeDescription(result.DerefAttr); err != nil {
			return fmt.Errorf(
				"encode deref response result %d derefAttr: %w",
				resultIndex,
				err,
			)
		}
		if !utf8.ValidString(result.DerefValue) {
			return fmt.Errorf(
				"encode deref response result %d derefValue is not valid UTF-8",
				resultIndex,
			)
		}
		if len(result.Attributes) > maxDerefAttributesPerResult {
			return fmt.Errorf(
				"encode deref response result %d has more than %d attributes",
				resultIndex,
				maxDerefAttributesPerResult,
			)
		}
		if len(result.Attributes) > maxDerefResponseAttributes-totalAttributes {
			return fmt.Errorf(
				"encode deref response: more than %d attributes",
				maxDerefResponseAttributes,
			)
		}
		totalAttributes += len(result.Attributes)
		if !addDerefPayloadBytes(&payloadBytes, len(result.DerefAttr)) ||
			!addDerefPayloadBytes(&payloadBytes, len(result.DerefValue)) {
			return fmt.Errorf(
				"encode deref response: payload exceeds %d-byte limit",
				DefaultMaxMessageSize,
			)
		}

		for attributeIndex, attribute := range result.Attributes {
			if _, err := canonicalDerefAttributeDescription(attribute.Type); err != nil {
				return fmt.Errorf(
					"encode deref response result %d attribute %d: %w",
					resultIndex,
					attributeIndex,
					err,
				)
			}
			if len(attribute.Values) > maxDerefValuesPerAttribute {
				return fmt.Errorf(
					"encode deref response result %d attribute %d has more than %d values",
					resultIndex,
					attributeIndex,
					maxDerefValuesPerAttribute,
				)
			}
			if len(attribute.Values) > maxDerefResponseValues-totalValues {
				return fmt.Errorf(
					"encode deref response: more than %d attribute values",
					maxDerefResponseValues,
				)
			}
			totalValues += len(attribute.Values)
			if !addDerefPayloadBytes(&payloadBytes, len(attribute.Type)) {
				return fmt.Errorf(
					"encode deref response: payload exceeds %d-byte limit",
					DefaultMaxMessageSize,
				)
			}
			for _, value := range attribute.Values {
				if !addDerefPayloadBytes(&payloadBytes, len(value)) {
					return fmt.Errorf(
						"encode deref response: payload exceeds %d-byte limit",
						DefaultMaxMessageSize,
					)
				}
			}
		}
	}
	return nil
}

func addDerefPayloadBytes(total *int64, size int) bool {
	if int64(size) > DefaultMaxMessageSize-*total {
		return false
	}
	*total += int64(size)
	return true
}

func canonicalDerefAttributeDescription(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("attribute description is empty")
	}
	if len(value) > maxDerefAttributeDescriptionBytes {
		return "", fmt.Errorf(
			"attribute description exceeds %d bytes",
			maxDerefAttributeDescriptionBytes,
		)
	}

	parts := strings.Split(value, ";")
	if !validDerefAttributeType(parts[0]) {
		return "", fmt.Errorf("attribute type %q is invalid", parts[0])
	}

	options := make([]string, 0, len(parts)-1)
	seenOptions := make(map[string]struct{}, len(parts)-1)
	for _, option := range parts[1:] {
		if !validDerefAttributeOption(option) {
			return "", fmt.Errorf("attribute option %q is invalid", option)
		}
		canonicalOption := strings.ToLower(option)
		if _, duplicate := seenOptions[canonicalOption]; duplicate {
			return "", fmt.Errorf(
				"attribute option %q is specified more than once",
				option,
			)
		}
		seenOptions[canonicalOption] = struct{}{}
		options = append(options, canonicalOption)
	}
	sort.Strings(options)

	canonical := strings.ToLower(parts[0])
	if len(options) != 0 {
		canonical += ";" + strings.Join(options, ";")
	}
	return canonical, nil
}

func validDerefAttributeType(value string) bool {
	if value == "" {
		return false
	}
	if isASCIIAlpha(value[0]) {
		for index := 1; index < len(value); index++ {
			if !isDerefKeyCharacter(value[index]) {
				return false
			}
		}
		return true
	}
	return validDerefNumericOID(value)
}

func validDerefNumericOID(value string) bool {
	if value == "" || value[0] < '0' || value[0] > '9' {
		return false
	}
	arcs := strings.Split(value, ".")
	if len(arcs) < 2 {
		return false
	}
	for _, arc := range arcs {
		if arc == "" || (len(arc) > 1 && arc[0] == '0') {
			return false
		}
		for index := range len(arc) {
			if arc[index] < '0' || arc[index] > '9' {
				return false
			}
		}
	}
	return true
}

func validDerefAttributeOption(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if !isDerefKeyCharacter(value[index]) {
			return false
		}
	}
	return true
}

func isDerefKeyCharacter(value byte) bool {
	return isASCIIAlpha(value) ||
		(value >= '0' && value <= '9') ||
		value == '-'
}

func isASCIIAlpha(value byte) bool {
	return (value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z')
}

type derefBERElement struct {
	identifier byte
	content    []byte
}

// readDerefBERElement implements the LDAP BER subset needed by the control.
// LDAP requires definite lengths, primitive OCTET STRINGs, and all tags used
// by this control fit in the short identifier form.
func readDerefBERElement(value []byte) (derefBERElement, []byte, error) {
	if len(value) < 2 {
		return derefBERElement{}, nil, fmt.Errorf("truncated BER header")
	}
	identifier := value[0]
	if identifier&0x1f == 0x1f {
		return derefBERElement{}, nil, fmt.Errorf(
			"high-tag-number BER identifier is not allowed",
		)
	}

	lengthByte := value[1]
	headerLength := 2
	contentLength := uint64(0)
	switch {
	case lengthByte == 0x80:
		return derefBERElement{}, nil, fmt.Errorf(
			"indefinite BER length is not allowed by LDAP",
		)
	case lengthByte == 0xff:
		return derefBERElement{}, nil, fmt.Errorf("invalid BER length")
	case lengthByte&0x80 == 0:
		contentLength = uint64(lengthByte)
	default:
		lengthOctets := int(lengthByte & 0x7f)
		if lengthOctets == 0 || lengthOctets > 8 ||
			len(value) < headerLength+lengthOctets {
			return derefBERElement{}, nil, fmt.Errorf(
				"truncated or overflowing BER length",
			)
		}
		for _, octet := range value[headerLength : headerLength+lengthOctets] {
			if contentLength > (^uint64(0)-uint64(octet))/256 {
				return derefBERElement{}, nil, fmt.Errorf("BER length overflows uint64")
			}
			contentLength = contentLength*256 + uint64(octet)
		}
		headerLength += lengthOctets
	}

	available := len(value) - headerLength
	if contentLength > uint64(available) {
		return derefBERElement{}, nil, fmt.Errorf(
			"truncated BER content: need %d bytes, have %d",
			contentLength,
			available,
		)
	}
	contentEnd := headerLength + int(contentLength)
	return derefBERElement{
		identifier: identifier,
		content:    value[headerLength:contentEnd],
	}, value[contentEnd:], nil
}
