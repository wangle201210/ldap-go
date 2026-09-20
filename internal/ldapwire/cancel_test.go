package ldapwire

import (
	"errors"
	"math"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestCancelRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	encoded := EncodeCancelRequestValue(42)
	messageID, err := DecodeCancelRequestValue(encoded)
	if err != nil {
		t.Fatalf("DecodeCancelRequestValue(): %v", err)
	}
	if messageID != 42 {
		t.Fatalf("cancelID = %d, want 42", messageID)
	}
}

func TestDecodeCancelRequestValueRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	empty := ber.NewSequence("cancelRequestValue")
	tests := map[string][]byte{
		"empty input":        nil,
		"empty sequence":     empty.Bytes(),
		"out of range ID":    EncodeCancelRequestValue(math.MaxInt32 + 1),
		"indefinite length":  {0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		"truncated length":   {0x30, 0x82, 0},
		"truncated integer":  {0x30, 3, 2, 2, 1},
		"truncated sequence": {0x30, 4, 2, 1, 1},
		"overflowing length": {0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"oversized length":   {0x30, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2, 1, 1},
		"truncated tag":      {0x3f, 0x80},
		"oversized tag":      {0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 3, 2, 1, 1},
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeCancelRequestValue(value)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}

func TestDecodeCancelRequestValueOpenLDAPBER(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		value []byte
		want  int64
	}{
		{"outer trailing data", append(EncodeCancelRequestValue(1), 0xff), 1},
		{"inner trailing data", []byte{0x30, 4, 2, 1, 1, 0xff}, 1},
		{"second ID ignored", []byte{0x30, 6, 2, 1, 1, 2, 1, 2}, 1},
		{"nonminimal length", []byte{0x30, 0x81, 3, 2, 1, 1}, 1},
		{"zero", EncodeCancelRequestValue(0), 0},
		{"empty integer", []byte{0x30, 2, 2, 0}, 0},
		{"negative decoded for server validation", EncodeCancelRequestValue(-1), -1},
		{"maximum", EncodeCancelRequestValue(math.MaxInt32), math.MaxInt32},
		{"minimum", EncodeCancelRequestValue(math.MinInt32), math.MinInt32},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, err := DecodeCancelRequestValue(test.value)
			if err != nil || id != test.want {
				t.Fatalf("decoded ID = %d, %v; want %d", id, err, test.want)
			}
		})
	}
}
