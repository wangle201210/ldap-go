package ldapwire

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"testing"
)

func TestSearchOptionsValueRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		flags int32
		want  []byte
	}{
		{flags: 0, want: []byte{0x30, 0x03, 0x02, 0x01, 0x00}},
		{flags: 1, want: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{flags: 2, want: []byte{0x30, 0x03, 0x02, 0x01, 0x02}},
		{flags: 3, want: []byte{0x30, 0x03, 0x02, 0x01, 0x03}},
		{flags: -1, want: []byte{0x30, 0x03, 0x02, 0x01, 0xff}},
		{flags: math.MinInt32},
		{flags: math.MaxInt32},
	}
	for _, test := range tests {
		test := test
		t.Run(strconv.FormatInt(int64(test.flags), 10), func(t *testing.T) {
			t.Parallel()

			encoded := EncodeSearchOptionsValue(test.flags)
			if test.want != nil && !slices.Equal(encoded, test.want) {
				t.Fatalf("EncodeSearchOptionsValue(%d) = %x, want %x", test.flags, encoded, test.want)
			}
			got, err := DecodeSearchOptionsValue(encoded)
			if err != nil {
				t.Fatalf("DecodeSearchOptionsValue(%x): %v", encoded, err)
			}
			if got != test.flags {
				t.Fatalf("flags = %d, want %d", got, test.flags)
			}
		})
	}
}

func TestDecodeSearchOptionsValueOpenLDAPPermissiveBER(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value []byte
		want  int32
	}{
		"zero-length integer": {
			value: []byte{0x30, 0x02, 0x02, 0x00},
		},
		"outer and child tags are ignored": {
			value: []byte{0x04, 0x03, 0x01, 0x01, 0x01},
			want:  1,
		},
		"container has remaining element": {
			value: []byte{0x30, 0x05, 0x02, 0x01, 0x02, 0x05, 0x00},
			want:  2,
		},
		"value has trailing data": {
			value: []byte{0x30, 0x03, 0x02, 0x01, 0x03, 0xff},
			want:  3,
		},
		"child follows empty container": {
			value: []byte{0x30, 0x00, 0x02, 0x01, 0x01},
			want:  1,
		},
		"non-minimal long length": {
			value: []byte{0x30, 0x81, 0x03, 0x02, 0x01, 0x01},
			want:  1,
		},
		"positive two-octet integer": {
			value: []byte{0x30, 0x04, 0x02, 0x02, 0x00, 0x80},
			want:  128,
		},
		"negative two-octet integer": {
			value: []byte{0x30, 0x04, 0x02, 0x02, 0x80, 0x00},
			want:  -32768,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := DecodeSearchOptionsValue(test.value)
			if err != nil {
				t.Fatalf("DecodeSearchOptionsValue(%x): %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("flags = %d, want %d", got, test.want)
			}
		})
	}
}

func TestDecodeSearchOptionsValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"empty value":             nil,
		"outer tag only":          {0x30},
		"outer content truncated": {0x30, 0x03, 0x02, 0x01},
		"missing child":           {0x30, 0x00},
		"child tag only":          {0x30, 0x01, 0x02},
		"child content truncated": {0x30, 0x02, 0x02, 0x02, 0x01},
		"integer exceeds int32":   {0x30, 0x07, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01},
		"indefinite outer length": {0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		"indefinite child length": {0x30, 0x04, 0x02, 0x80, 0x00, 0x00},
		"truncated long length":   {0x30, 0x82, 0x00},
		"too many length octets":  {0x30, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"unterminated high tag":   {0x1f, 0x80},
	}
	for name, value := range tests {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeSearchOptionsValue(value)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}
