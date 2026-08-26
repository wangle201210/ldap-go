package ldapwire

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSessionTrackingValueRoundTrip(t *testing.T) {
	t.Parallel()

	want := SessionTrackingValue{
		SessionSourceIP:           []byte("192.0.2.10"),
		SessionSourceName:         []byte("edge.example.com"),
		FormatOID:                 []byte("1.3.6.1.4.1.21008.108.63.1"),
		SessionTrackingIdentifier: []byte("request-42"),
	}
	encoded := EncodeSessionTrackingValue(want)
	got, formatOIDValid, err := DecodeSessionTrackingValue(encoded)
	if err != nil {
		t.Fatalf("DecodeSessionTrackingValue(): %v", err)
	}
	if !formatOIDValid {
		t.Fatal("FormatOIDValid = false, want true")
	}
	assertSessionTrackingValue(t, got, want)

	encodedBefore := bytes.Clone(encoded)
	want.SessionSourceIP[0] = 'X'
	if !bytes.Equal(encoded, encodedBefore) {
		t.Fatal("encoded value aliases an input field")
	}

	decodedBefore := SessionTrackingValue{
		SessionSourceIP:           bytes.Clone(got.SessionSourceIP),
		SessionSourceName:         bytes.Clone(got.SessionSourceName),
		FormatOID:                 bytes.Clone(got.FormatOID),
		SessionTrackingIdentifier: bytes.Clone(got.SessionTrackingIdentifier),
	}
	got.SessionSourceIP[0] = 'X'
	got.SessionSourceName[0] = 'X'
	got.FormatOID[0] = '9'
	got.SessionTrackingIdentifier[0] = 'X'
	if !bytes.Equal(encoded, encodedBefore) {
		t.Fatal("decoded fields alias the encoded input")
	}

	got, _, err = DecodeSessionTrackingValue(encoded)
	if err != nil {
		t.Fatalf("DecodeSessionTrackingValue() second call: %v", err)
	}
	for index := range encoded {
		encoded[index] ^= 0xff
	}
	assertSessionTrackingValue(t, got, decodedBefore)
}

func TestDecodeSessionTrackingValueAcceptsOpenLDAPBER(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value []byte
		want  SessionTrackingValue
	}{
		"arbitrary inner tags": {
			value: sessionTrackingSequenceForTest(
				sessionTrackingTLVForTest([]byte{0x02}, []byte("1")),
				sessionTrackingTLVForTest([]byte{0x80}, []byte("n")),
				sessionTrackingTLVForTest([]byte{0x31}, []byte("1.2")),
				sessionTrackingTLVForTest([]byte{0x9f, 0x20}, []byte("i")),
			),
			want: SessionTrackingValue{
				SessionSourceIP:           []byte("1"),
				SessionSourceName:         []byte("n"),
				FormatOID:                 []byte("1.2"),
				SessionTrackingIdentifier: []byte("i"),
			},
		},
		"empty optional fields": {
			value: sessionTrackingSequenceForTest(
				sessionTrackingTLVForTest([]byte{0x04}, nil),
				sessionTrackingTLVForTest([]byte{0x04}, nil),
				sessionTrackingTLVForTest([]byte{0x04}, []byte("1")),
				sessionTrackingTLVForTest([]byte{0x04}, nil),
			),
			want: SessionTrackingValue{FormatOID: []byte("1")},
		},
		"outer boundary is ignored": {
			value: append(
				[]byte{0x30, 0x00},
				sessionTrackingFieldsForTest("ip", "name", "1.2", "id")...,
			),
			want: SessionTrackingValue{
				SessionSourceIP:           []byte("ip"),
				SessionSourceName:         []byte("name"),
				FormatOID:                 []byte("1.2"),
				SessionTrackingIdentifier: []byte("id"),
			},
		},
		"single trailing tag byte": {
			value: append(
				sessionTrackingSequenceForTest(
					sessionTrackingFieldsForTest("ip", "name", "1.2", "id"),
				),
				0xff,
			),
			want: SessionTrackingValue{
				SessionSourceIP:           []byte("ip"),
				SessionSourceName:         []byte("name"),
				FormatOID:                 []byte("1.2"),
				SessionTrackingIdentifier: []byte("id"),
			},
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, formatOIDValid, err := DecodeSessionTrackingValue(test.value)
			if err != nil {
				t.Fatalf("DecodeSessionTrackingValue(%x): %v", test.value, err)
			}
			if !formatOIDValid {
				t.Fatal("FormatOIDValid = false, want true")
			}
			assertSessionTrackingValue(t, got, test.want)
		})
	}
}

func TestDecodeSessionTrackingValueLengthBoundaries(t *testing.T) {
	t.Parallel()

	validOID1024 := strings.Repeat("1.", 511) + "11"
	tests := map[string]struct {
		value   SessionTrackingValue
		wantErr bool
	}{
		"IP at limit": {
			value: SessionTrackingValue{SessionSourceIP: bytes.Repeat([]byte{'i'}, 128), FormatOID: []byte("1.2")},
		},
		"IP over limit": {
			value:   SessionTrackingValue{SessionSourceIP: bytes.Repeat([]byte{'i'}, 129), FormatOID: []byte("1.2")},
			wantErr: true,
		},
		"name at limit": {
			value: SessionTrackingValue{SessionSourceName: bytes.Repeat([]byte{'n'}, 65536), FormatOID: []byte("1.2")},
		},
		"name over limit": {
			value:   SessionTrackingValue{SessionSourceName: bytes.Repeat([]byte{'n'}, 65537), FormatOID: []byte("1.2")},
			wantErr: true,
		},
		"OID at limit": {
			value: SessionTrackingValue{FormatOID: []byte(validOID1024)},
		},
		"OID over limit": {
			value:   SessionTrackingValue{FormatOID: []byte(validOID1024 + "1")},
			wantErr: true,
		},
		"identifier has no extra limit": {
			value: SessionTrackingValue{FormatOID: []byte("1.2"), SessionTrackingIdentifier: bytes.Repeat([]byte{'x'}, 131072)},
		},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, formatOIDValid, err := DecodeSessionTrackingValue(
				EncodeSessionTrackingValue(test.value),
			)
			if test.wantErr {
				if !errors.Is(err, ErrMalformedMessage) {
					t.Fatalf("error = %v, want ErrMalformedMessage", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeSessionTrackingValue(): %v", err)
			}
			if !formatOIDValid {
				t.Fatal("FormatOIDValid = false, want true")
			}
			assertSessionTrackingValue(t, got, test.value)
		})
	}
}

func TestDecodeSessionTrackingValueReportsInvalidFormatOID(t *testing.T) {
	t.Parallel()

	invalid := []string{"01.2", "1..2", "1.", ".1", "one.two", "1.02", "1 2"}
	for _, formatOID := range invalid {
		formatOID := formatOID
		t.Run(formatOID, func(t *testing.T) {
			t.Parallel()

			want := SessionTrackingValue{FormatOID: []byte(formatOID)}
			got, formatOIDValid, err := DecodeSessionTrackingValue(
				EncodeSessionTrackingValue(want),
			)
			if err != nil {
				t.Fatalf("DecodeSessionTrackingValue(): %v", err)
			}
			if formatOIDValid {
				t.Fatal("FormatOIDValid = true, want false")
			}
			assertSessionTrackingValue(t, got, want)
		})
	}
}

func TestDecodeSessionTrackingValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	validFields := sessionTrackingFieldsForTest("ip", "name", "1.2", "id")
	threeFields := sessionTrackingFieldsForTest("ip", "name", "1.2")
	fiveFields := sessionTrackingFieldsForTest("ip", "name", "1.2", "id", "extra")
	tests := map[string][]byte{
		"empty":                    nil,
		"outer is not sequence":    sessionTrackingTLVForTest([]byte{0x31}, validFields),
		"outer tag only":           {0x30},
		"outer content truncated":  {0x30, 0x20, 0x04, 0x00},
		"outer indefinite length":  append([]byte{0x30, 0x80}, append(validFields, 0x00, 0x00)...),
		"missing fourth field":     sessionTrackingTLVForTest([]byte{0x30}, threeFields),
		"fifth field":              sessionTrackingTLVForTest([]byte{0x30}, fiveFields),
		"two trailing bytes":       append(sessionTrackingTLVForTest([]byte{0x30}, validFields), 0x00, 0x00),
		"inner indefinite length":  {0x30, 0x0d, 0x04, 0x80, 0x00, 0x00, 0x04, 0x01, 'n', 0x04, 0x03, '1', '.', '2', 0x04, 0x00},
		"inner content truncated":  {0x30, 0x04, 0x04, 0x03, 'i'},
		"empty format OID":         sessionTrackingSequenceForTest(sessionTrackingFieldsForTest("ip", "name", "", "id")),
		"truncated inner long tag": append([]byte{0x30, 0x02, 0x1f, 0x80}, nil...),
	}

	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := DecodeSessionTrackingValue(value)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}

func assertSessionTrackingValue(t *testing.T, got, want SessionTrackingValue) {
	t.Helper()

	gotFields := [][]byte{got.SessionSourceIP, got.SessionSourceName, got.FormatOID, got.SessionTrackingIdentifier}
	wantFields := [][]byte{want.SessionSourceIP, want.SessionSourceName, want.FormatOID, want.SessionTrackingIdentifier}
	for index := range gotFields {
		if !slices.Equal(gotFields[index], wantFields[index]) {
			t.Fatalf("field %d = %q, want %q", index, gotFields[index], wantFields[index])
		}
	}
}

func sessionTrackingFieldsForTest(fields ...string) []byte {
	var encoded []byte
	for _, field := range fields {
		encoded = append(encoded, sessionTrackingTLVForTest([]byte{0x04}, []byte(field))...)
	}
	return encoded
}

func sessionTrackingSequenceForTest(fields ...[]byte) []byte {
	var content []byte
	for _, field := range fields {
		content = append(content, field...)
	}
	return sessionTrackingTLVForTest([]byte{0x30}, content)
}

func sessionTrackingTLVForTest(tag, content []byte) []byte {
	encoded := slices.Clone(tag)
	length := len(content)
	if length < 128 {
		encoded = append(encoded, byte(length))
	} else {
		var lengthBytes [8]byte
		first := len(lengthBytes)
		for length != 0 {
			first--
			lengthBytes[first] = byte(length)
			length >>= 8
		}
		encoded = append(encoded, 0x80|byte(len(lengthBytes)-first))
		encoded = append(encoded, lengthBytes[first:]...)
	}
	return append(encoded, content...)
}
