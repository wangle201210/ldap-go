package ldapwire

import (
	"errors"
	"math"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestDynamicRefreshRequestValueRoundTrip(t *testing.T) {
	t.Parallel()

	want := DynamicRefreshRequestValue{
		EntryName:  "uid=alice,ou=people,dc=example,dc=com",
		RequestTTL: 120,
	}
	got, err := DecodeDynamicRefreshRequestValue(
		EncodeDynamicRefreshRequestValue(want.EntryName, want.RequestTTL),
		true,
	)
	if err != nil {
		t.Fatalf("DecodeDynamicRefreshRequestValue(): %v", err)
	}
	if got != want {
		t.Fatalf("dynamic refresh request = %#v, want %#v", got, want)
	}
}

func TestDecodeDynamicRefreshRequestValueRejectsMalformedBER(t *testing.T) {
	t.Parallel()

	wrongTag := ber.NewSequence("RefreshRequestValue")
	wrongTag.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		"uid=alice,dc=example,dc=com",
		"entryName",
	))
	wrongTag.AppendChild(ber.NewInteger(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		120,
		"requestTtl",
	))
	extra := append(
		EncodeDynamicRefreshRequestValue("uid=alice,dc=example,dc=com", 120),
		0,
	)
	tooLarge := EncodeDynamicRefreshRequestValue(
		"uid=alice,dc=example,dc=com",
		math.MaxInt32+1,
	)
	for name, test := range map[string]struct {
		value   []byte
		present bool
	}{
		"absent":       {},
		"empty":        {value: []byte{}, present: true},
		"wrong tag":    {value: wrongTag.Bytes(), present: true},
		"trailing":     {value: extra, present: true},
		"out of range": {value: tooLarge, present: true},
	} {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeDynamicRefreshRequestValue(test.value, test.present)
			if !errors.Is(err, ErrMalformedMessage) {
				t.Fatalf("decode error = %v, want ErrMalformedMessage", err)
			}
		})
	}
}

func TestDynamicRefreshResponseValueRoundTrip(t *testing.T) {
	t.Parallel()

	encoded := EncodeDynamicRefreshResponseValue(3600)
	got, err := DecodeDynamicRefreshResponseValue(encoded)
	if err != nil {
		t.Fatalf("DecodeDynamicRefreshResponseValue(): %v", err)
	}
	if got != 3600 {
		t.Fatalf("response TTL = %d, want 3600", got)
	}
}
