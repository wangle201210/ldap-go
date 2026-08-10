package schema

import (
	"errors"
	"fmt"
	"math"
)

const (
	berTagInteger         uint64 = 0x02
	berTagBitString       uint64 = 0x03
	berTagOctetString     uint64 = 0x04
	berTagOID             uint64 = 0x06
	berTagSequence        uint64 = 0x30
	berTagSet             uint64 = 0x31
	berTagUTCTime         uint64 = 0x17
	berTagGeneralizedTime uint64 = 0x18
	berTagContext0        uint64 = 0xa0
	berTagContext1        uint64 = 0x81
	berTagContext2        uint64 = 0x82
	berTagContext3        uint64 = 0xa3
)

var errBEREnd = errors.New("end of BER value")

type berElement struct {
	tag          uint64
	contentStart int
	length       int
}

type berCursor struct {
	value []byte
	pos   int
}

func (cursor *berCursor) atEnd() bool {
	return cursor.pos == len(cursor.value)
}

func (cursor *berCursor) peek() (berElement, error) {
	return parseBERElement(cursor.value, cursor.pos)
}

func (cursor *berCursor) readHeader() (berElement, error) {
	element, err := cursor.peek()
	if err != nil {
		return berElement{}, err
	}
	cursor.pos = element.contentStart
	return element, nil
}

func (cursor *berCursor) readElement() (berElement, error) {
	element, err := cursor.readHeader()
	if err != nil {
		return berElement{}, err
	}
	cursor.pos += element.length
	return element, nil
}

func (cursor *berCursor) readExpected(tag uint64) (berElement, error) {
	element, err := cursor.readElement()
	if err != nil {
		return berElement{}, err
	}
	if element.tag != tag {
		return berElement{}, fmt.Errorf("expected BER tag 0x%x, got 0x%x", tag, element.tag)
	}
	return element, nil
}

func (cursor *berCursor) readInteger() (int64, error) {
	element, err := cursor.readExpected(berTagInteger)
	if err != nil {
		return 0, err
	}
	if element.length > 8 {
		return 0, errors.New("BER integer is too large")
	}
	if element.length == 0 {
		return 0, nil
	}
	content := cursor.value[element.contentStart : element.contentStart+element.length]
	result := int64(int8(content[0]))
	for _, octet := range content[1:] {
		result = int64(uint64(result)<<8 | uint64(octet))
	}
	return result, nil
}

func parseBERElement(value []byte, offset int) (berElement, error) {
	if offset >= len(value) {
		return berElement{}, errBEREnd
	}
	position := offset
	tag := uint64(value[position])
	position++
	if tag&0x1f == 0x1f {
		for {
			if position >= len(value) || tag > math.MaxUint64>>8 {
				return berElement{}, errors.New("invalid BER tag")
			}
			octet := value[position]
			position++
			tag = tag<<8 | uint64(octet)
			if octet&0x80 == 0 {
				break
			}
		}
	}
	if position >= len(value) {
		return berElement{}, errors.New("missing BER length")
	}
	length := uint64(value[position])
	position++
	if length&0x80 != 0 {
		lengthOctets := int(length & 0x7f)
		if lengthOctets == 0 || lengthOctets > 8 || position+lengthOctets > len(value) {
			return berElement{}, errors.New("invalid BER length")
		}
		length = 0
		for range lengthOctets {
			if length > math.MaxUint64>>8 {
				return berElement{}, errors.New("BER length overflows")
			}
			length = length<<8 | uint64(value[position])
			position++
		}
	}
	if length > uint64(len(value)-position) || length > uint64(math.MaxInt) {
		return berElement{}, errors.New("BER element exceeds input")
	}
	return berElement{
		tag:          tag,
		contentStart: position,
		length:       int(length),
	}, nil
}

func validateBlob([]byte) error {
	return nil
}

func validateCertificatePair(value []byte) error {
	if len(value) < 2 || value[0] != byte(berTagSequence) {
		return errors.New("value is not a Certificate Pair sequence")
	}
	return nil
}

func validateCertificate(value []byte) error {
	if len(value) == 0 {
		return errors.New("value is not a certificate")
	}
	cursor := berCursor{value: value}
	if _, err := cursor.readHeaderExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("certificate", err)
	}
	if _, err := cursor.readHeaderExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("certificate", err)
	}

	version := int64(0)
	if element, err := cursor.peek(); err == nil && element.tag == berTagContext0 {
		if _, err := cursor.readHeader(); err != nil {
			return invalidBinarySyntax("certificate", err)
		}
		version, err = cursor.readInteger()
		if err != nil {
			return invalidBinarySyntax("certificate", err)
		}
	}
	for _, tag := range []uint64{
		berTagInteger,
		berTagSequence,
		berTagSequence,
		berTagSequence,
		berTagSequence,
		berTagSequence,
	} {
		if _, err := cursor.readExpected(tag); err != nil {
			return invalidBinarySyntax("certificate", err)
		}
	}

	next, err := cursor.readHeader()
	if err != nil {
		return invalidBinarySyntax("certificate", err)
	}
	if next.tag == berTagContext1 {
		if version < 1 {
			return errors.New("certificate issuerUniqueID requires version 2 or later")
		}
		cursor.pos += next.length
		next, err = cursor.readHeader()
		if err != nil {
			return invalidBinarySyntax("certificate", err)
		}
	}
	if next.tag == berTagContext2 {
		if version < 1 {
			return errors.New("certificate subjectUniqueID requires version 2 or later")
		}
		cursor.pos += next.length
		next, err = cursor.readHeader()
		if err != nil {
			return invalidBinarySyntax("certificate", err)
		}
	}
	if next.tag == berTagContext3 {
		if version < 2 {
			return errors.New("certificate extensions require version 3 or later")
		}
		if _, err := cursor.readExpected(berTagSequence); err != nil {
			return invalidBinarySyntax("certificate", err)
		}
		next, err = cursor.readHeader()
		if err != nil {
			return invalidBinarySyntax("certificate", err)
		}
	}
	if next.tag != berTagSequence {
		return errors.New("certificate has invalid signature algorithm")
	}
	cursor.pos += next.length
	if _, err := cursor.readExpected(berTagBitString); err != nil {
		return invalidBinarySyntax("certificate", err)
	}
	if !cursor.atEnd() {
		return errors.New("certificate has trailing data")
	}
	return nil
}

func (cursor *berCursor) readHeaderExpected(tag uint64) (berElement, error) {
	element, err := cursor.readHeader()
	if err != nil {
		return berElement{}, err
	}
	if element.tag != tag {
		return berElement{}, fmt.Errorf("expected BER tag 0x%x, got 0x%x", tag, element.tag)
	}
	return element, nil
}

func validateCertificateList(value []byte) error {
	cursor := berCursor{value: value}
	wrapper, err := cursor.readHeaderExpected(berTagSequence)
	if err != nil {
		return invalidBinarySyntax("certificate list", err)
	}
	wrapperEnd := wrapper.contentStart + wrapper.length
	if _, err := cursor.readHeaderExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("certificate list", err)
	}

	version := int64(0)
	if element, err := cursor.peek(); err == nil && element.tag == berTagInteger {
		version, err = cursor.readInteger()
		if err != nil || version != 1 {
			return errors.New("certificate list has invalid version")
		}
	}
	if _, err := cursor.readExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("certificate list", err)
	}
	issuerStart := cursor.pos
	issuer, err := cursor.readExpected(berTagSequence)
	if err != nil {
		return invalidBinarySyntax("certificate list", err)
	}
	issuerEnd := issuer.contentStart + issuer.length
	thisUpdate, err := cursor.readElement()
	if err != nil || (thisUpdate.tag != berTagUTCTime && thisUpdate.tag != berTagGeneralizedTime) {
		return errors.New("certificate list has invalid thisUpdate tag")
	}

	next, err := cursor.readHeader()
	if err != nil {
		return invalidBinarySyntax("certificate list", err)
	}
	if next.tag == berTagUTCTime || next.tag == berTagGeneralizedTime {
		cursor.pos += next.length
		next, err = cursor.readHeader()
		if err != nil {
			return invalidBinarySyntax("certificate list", err)
		}
	}
	if next.tag == berTagSequence {
		inner, innerErr := cursor.peek()
		if next.length == 0 || (innerErr == nil && inner.tag == berTagSequence) {
			cursor.pos += next.length
			next, err = cursor.readHeader()
			if err != nil {
				return invalidBinarySyntax("certificate list", err)
			}
		}
	}
	if next.tag == berTagContext0 {
		if version != 1 {
			return errors.New("certificate list extensions require version 2")
		}
		inner, innerErr := cursor.peek()
		if innerErr != nil || inner.tag != berTagSequence {
			return errors.New("certificate list has invalid extensions")
		}
		cursor.pos += next.length
		next, err = cursor.readHeader()
		if err != nil {
			return invalidBinarySyntax("certificate list", err)
		}
	}
	if next.tag != berTagSequence {
		return errors.New("certificate list has invalid signature algorithm")
	}
	cursor.pos += next.length
	if _, err := cursor.readExpected(berTagBitString); err != nil {
		return invalidBinarySyntax("certificate list", err)
	}
	if cursor.atEnd() {
		return nil
	}
	if cursor.pos != wrapperEnd {
		return errors.New("certificate list wrapper does not end before trailing data")
	}
	if _, err := cursor.peek(); err != nil {
		return errors.New("certificate list has malformed trailing data")
	}
	if !validX509Name(value[issuerStart:issuerEnd]) ||
		!validX509Time(value[thisUpdate.contentStart:thisUpdate.contentStart+thisUpdate.length]) {
		return errors.New("certificate list has invalid issuer or thisUpdate before trailing data")
	}
	return nil
}

func validateAttributeCertificate(value []byte) error {
	cursor := berCursor{value: value}
	if _, err := cursor.readHeaderExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("attribute certificate", err)
	}
	if _, err := cursor.readHeaderExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("attribute certificate", err)
	}
	version, err := cursor.readInteger()
	if err != nil || version != 1 {
		return errors.New("attribute certificate has invalid version")
	}
	for _, tag := range []uint64{
		berTagSequence,
		berTagContext0,
		berTagSequence,
		berTagInteger,
		berTagSequence,
		berTagSequence,
	} {
		if _, err := cursor.readExpected(tag); err != nil {
			return invalidBinarySyntax("attribute certificate", err)
		}
	}
	if element, err := cursor.peek(); err == nil && element.tag == berTagBitString {
		_, _ = cursor.readElement()
	}
	continuations := 0
	for continuations < 2 {
		element, err := cursor.peek()
		if err != nil || element.tag != berTagSequence {
			break
		}
		_, _ = cursor.readElement()
		continuations++
	}
	if element, err := cursor.peek(); err == nil && element.tag == berTagBitString {
		_, _ = cursor.readElement()
		continuations++
	}
	if continuations < 2 || !cursor.atEnd() {
		return errors.New("attribute certificate has invalid signature fields or trailing data")
	}
	return nil
}

func validatePKCS8PrivateKey(value []byte) error {
	cursor := berCursor{value: value}
	if _, err := cursor.readHeaderExpected(berTagSequence); err != nil {
		return invalidBinarySyntax("PKCS#8 private key", err)
	}
	first, err := cursor.peek()
	if err != nil {
		return invalidBinarySyntax("PKCS#8 private key", err)
	}
	if first.tag == berTagInteger {
		if _, err := cursor.readInteger(); err != nil {
			return invalidBinarySyntax("PKCS#8 private key", err)
		}
		if _, err := cursor.readExpected(berTagSequence); err != nil {
			return invalidBinarySyntax("PKCS#8 private key", err)
		}
		if _, err := cursor.readExpected(berTagOctetString); err != nil {
			return invalidBinarySyntax("PKCS#8 private key", err)
		}
		if element, err := cursor.peek(); err == nil && element.tag == berTagSet {
			_, _ = cursor.readElement()
		}
	} else if first.tag == berTagSequence {
		if _, err := cursor.readElement(); err != nil {
			return invalidBinarySyntax("PKCS#8 private key", err)
		}
		if _, err := cursor.readExpected(berTagOctetString); err != nil {
			return invalidBinarySyntax("PKCS#8 private key", err)
		}
	} else {
		return errors.New("PKCS#8 private key has invalid first field")
	}
	if !cursor.atEnd() {
		return errors.New("PKCS#8 private key has trailing data")
	}
	return nil
}

func validX509Time(value []byte) bool {
	if len(value) != 13 && len(value) != 15 {
		return false
	}
	if value[len(value)-1] != 'Z' {
		return false
	}
	for _, octet := range value[:len(value)-1] {
		if octet < '0' || octet > '9' {
			return false
		}
	}
	if len(value) == 15 {
		return validGeneralizedTime(value)
	}
	year := []byte("19")
	if value[0] < '7' {
		year = []byte("20")
	}
	normalized := make([]byte, 0, 15)
	normalized = append(normalized, year...)
	normalized = append(normalized, value...)
	return validGeneralizedTime(normalized)
}

func validX509Name(value []byte) bool {
	outer, err := parseBERElement(value, 0)
	if err != nil || outer.tag != berTagSequence ||
		outer.contentStart+outer.length != len(value) {
		return false
	}
	rdns := berCursor{value: value, pos: outer.contentStart}
	end := outer.contentStart + outer.length
	for rdns.pos < end {
		rdn, err := rdns.readElement()
		if err != nil || rdn.tag != berTagSet || rdn.length == 0 {
			return false
		}
		attributes := berCursor{
			value: value[:rdn.contentStart+rdn.length],
			pos:   rdn.contentStart,
		}
		for !attributes.atEnd() {
			attribute, err := attributes.readElement()
			if err != nil || attribute.tag != berTagSequence || attribute.length == 0 {
				return false
			}
			fields := berCursor{
				value: value[:attribute.contentStart+attribute.length],
				pos:   attribute.contentStart,
			}
			oid, err := fields.readElement()
			if err != nil || oid.tag != berTagOID || oid.length == 0 {
				return false
			}
			if _, err := fields.readElement(); err != nil || !fields.atEnd() {
				return false
			}
		}
	}
	return rdns.pos == end
}

func invalidBinarySyntax(name string, err error) error {
	return fmt.Errorf("value is not a valid %s: %w", name, err)
}
