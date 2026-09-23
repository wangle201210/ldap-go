package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Keep these two consumers identical to HEAD 9581b3d for differential tests and benchmarks.
func entryCodecShortOriginalField(value []byte) ([]byte, []byte, error) {
	length, count := binary.Uvarint(value)
	if count <= 0 {
		return nil, nil, errors.New("invalid length")
	}
	value = value[count:]
	if length > uint64(len(value)) {
		return nil, nil, errors.New("truncated value")
	}
	return value[:int(length):int(length)], value[int(length):], nil
}

func entryCodecShortOriginalCount(value []byte) (int, []byte, error) {
	count, width := binary.Uvarint(value)
	if width <= 0 {
		return 0, nil, errors.New("invalid count")
	}
	if count > uint64(math.MaxInt) {
		return 0, nil, errors.New("count overflows int")
	}
	return int(count), value[width:], nil
}

func entryCodecShortCheckError(t *testing.T, got, want error) {
	t.Helper()
	for got != nil || want != nil {
		if got == nil || want == nil || reflect.TypeOf(got) != reflect.TypeOf(want) || got.Error() != want.Error() {
			t.Fatalf("error chain = %T(%v), want %T(%v)", got, got, want, want)
		}
		got, want = errors.Unwrap(got), errors.Unwrap(want)
	}
}

func entryCodecShortCheckSlice(t *testing.T, got, want []byte) {
	t.Helper()
	if (got == nil) != (want == nil) || len(got) != len(want) || cap(got) != cap(want) || !bytes.Equal(got, want) {
		t.Fatalf("slice = %x (nil=%t len=%d cap=%d), want %x (nil=%t len=%d cap=%d)",
			got, got == nil, len(got), cap(got), want, want == nil, len(want), cap(want))
	}
	// Pointer also checks empty, zero-capacity slices that cannot be resliced.
	if reflect.ValueOf(got).Pointer() != reflect.ValueOf(want).Pointer() {
		t.Fatal("slice does not alias the original input at the same offset")
	}
	if len(want) > 0 {
		before := want[0]
		got[0] ^= 0xff
		if want[0] != before^0xff {
			t.Fatal("slice mutation did not reach the original input")
		}
		got[0] = before
	}
}

func entryCodecShortCompareConsumers(t *testing.T, input []byte) {
	t.Helper()
	unchanged := bytes.Clone(input)
	got, rest, err := consumeEntryBinaryField(input)
	want, wantRest, wantErr := entryCodecShortOriginalField(input)
	entryCodecShortCheckError(t, err, wantErr)
	entryCodecShortCheckSlice(t, got, want)
	entryCodecShortCheckSlice(t, rest, wantRest)
	count, rest, err := consumeEntryBinaryCount(input)
	wantCount, wantRest, wantErr := entryCodecShortOriginalCount(input)
	if count != wantCount {
		t.Fatalf("count = %d, want %d for %x", count, wantCount, input)
	}
	entryCodecShortCheckError(t, err, wantErr)
	entryCodecShortCheckSlice(t, rest, wantRest)
	if !bytes.Equal(input, unchanged) {
		t.Fatal("consumer changed encoded input")
	}
}

func TestEntryCodecShortConsumersDifferential(t *testing.T) {
	t.Parallel()
	entryCodecShortCompareConsumers(t, nil)
	entryCodecShortCompareConsumers(t, []byte{})
	entryCodecShortCompareConsumers(t, make([]byte, 0, 8))
	for first := range 256 {
		t.Run(fmt.Sprintf("Byte%02x", first), func(t *testing.T) {
			for _, size := range []int{0, 1, max(0, first-1), first, first + 1, 127, 128, 255} {
				backing := bytes.Repeat([]byte{0x5a}, size+10)
				input := backing[3 : 4+size]
				input[0] = byte(first)
				entryCodecShortCompareConsumers(t, input)
				entryCodecShortCompareConsumers(t, input[:len(input):len(input)])
			}
		})
	}
	values := []uint64{0, 1, 126, 127, 128, 129, 255, 256, uint64(math.MaxInt), uint64(math.MaxInt) + 1, math.MaxUint64}
	for shift := 7; shift < 64; shift += 7 {
		values = append(values, 1<<shift-1, 1<<shift, 1<<shift+1)
	}
	for _, value := range values {
		t.Run(fmt.Sprintf("Varint%d", value), func(t *testing.T) {
			encoded := binary.AppendUvarint(nil, value)
			for width := range len(encoded) + 1 {
				entryCodecShortCompareConsumers(t, encoded[:width])
			}
			entryCodecShortCompareConsumers(t, append(bytes.Clone(encoded), 0xa5, 0x5a))
			if value <= 16384 {
				encoded = append(encoded, bytes.Repeat([]byte{0x5a}, int(value))...)
				entryCodecShortCompareConsumers(t, encoded)
				entryCodecShortCompareConsumers(t, append(encoded, 0xa5))
			}
		})
	}
	for width := 2; width <= 11; width++ {
		for _, low := range []byte{0, 1, 127} {
			nonminimal := bytes.Repeat([]byte{0x80}, width)
			nonminimal[0], nonminimal[width-1] = low|0x80, 0
			entryCodecShortCompareConsumers(t, nonminimal)
			entryCodecShortCompareConsumers(t, append(nonminimal, bytes.Repeat([]byte{0x5a}, int(low))...))
		}
		entryCodecShortCompareConsumers(t, bytes.Repeat([]byte{0x80}, width))
		entryCodecShortCompareConsumers(t, bytes.Repeat([]byte{0xff}, width))
	}
	for last := range 256 {
		input := append(bytes.Repeat([]byte{0xff}, 9), byte(last))
		entryCodecShortCompareConsumers(t, input)
		entryCodecShortCompareConsumers(t, append(input, 0))
	}
}

func TestEntryCodecShortMutatedCodecDifferential(t *testing.T) {
	t.Parallel()
	entry := directory.Entry{
		DN: "uid=alice,dc=example",
		Attributes: []directory.Attribute{
			{Description: "uid", Values: [][]byte{[]byte("alice"), {}}},
			{Description: "description", Values: [][]byte{bytes.Repeat([]byte("x"), 128)}},
		},
	}
	encoded, err := encodeEntry(entry, "identity", entry.DN)
	if err != nil {
		t.Fatal(err)
	}
	compare := func(input []byte) {
		t.Helper()
		got, gotErr := decodeStoredEntry(input)
		want, wantErr := entryCodecShortOriginalDecodeV2(input[len(entryBinaryPrefix):])
		if wantErr != nil {
			wantErr = fmt.Errorf("decode entry: %w", wantErr)
		}
		entryCodecShortCheckError(t, gotErr, wantErr)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("decode %x = %#v, want %#v", input, got, want)
		}
		if gotErr == nil {
			entryCodecCheckCapacities(t, got)
		}
	}
	compare(encoded)
	compare(append(bytes.Clone(encoded), 0))
	for i := len(entryBinaryPrefix); i < len(encoded); i++ {
		compare(encoded[:i])
		for _, replacement := range []byte{0, 1, 2, 32, 126, 127, 128, 129, 254, 255} {
			mutated := bytes.Clone(encoded)
			mutated[i] = replacement
			compare(mutated)
		}
	}
}

// These V2 decoding functions copy the baseline, using only the original consumers.
func entryCodecShortOriginalDecodeV2(value []byte) (storedEntry, error) {
	dn, remaining, err := entryCodecShortOriginalField(value)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN: %w", err)
	}
	binding, remaining, err := entryCodecShortOriginalField(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("DN binding: %w", err)
	}
	if len(binding) != 0 && len(binding) != sha256.Size {
		return storedEntry{}, fmt.Errorf("DN binding has invalid length %d", len(binding))
	}
	return entryCodecShortOriginalAttributes(dn, binding, remaining)
}

func entryCodecShortOriginalAttributes(dn, binding, value []byte) (storedEntry, error) {
	remaining := value
	attributeCount, remaining, err := entryCodecShortOriginalCount(remaining)
	if err != nil {
		return storedEntry{}, fmt.Errorf("attribute count: %w", err)
	}
	if attributeCount > len(remaining) {
		return storedEntry{}, errors.New("attribute count exceeds encoded entry size")
	}
	stored := storedEntry{Entry: directory.Entry{DN: string(dn)}, DNBinding: binding}
	if attributeCount > 0 {
		stored.Attributes = make([]directory.Attribute, 0, attributeCount)
	}
	for attributeIndex := 0; attributeIndex < attributeCount; attributeIndex++ {
		description, next, fieldErr := entryCodecShortOriginalField(remaining)
		if fieldErr != nil {
			return storedEntry{}, fmt.Errorf("attribute %d description: %w", attributeIndex, fieldErr)
		}
		valueCount, next, fieldErr := entryCodecShortOriginalCount(next)
		if fieldErr != nil {
			return storedEntry{}, fmt.Errorf("attribute %d value count: %w", attributeIndex, fieldErr)
		}
		if valueCount > len(next) {
			return storedEntry{}, fmt.Errorf("attribute %d value count exceeds encoded entry size", attributeIndex)
		}
		attribute := directory.Attribute{Description: string(description)}
		if valueCount > 0 {
			attribute.Values = make([][]byte, 0, valueCount)
		}
		for valueIndex := 0; valueIndex < valueCount; valueIndex++ {
			encodedValue, afterValue, valueErr := entryCodecShortOriginalField(next)
			if valueErr != nil {
				return storedEntry{}, fmt.Errorf("attribute %d value %d: %w", attributeIndex, valueIndex, valueErr)
			}
			attribute.Values = append(attribute.Values, encodedValue)
			next = afterValue
		}
		stored.Attributes = append(stored.Attributes, attribute)
		remaining = next
	}
	if len(remaining) != 0 {
		return storedEntry{}, fmt.Errorf("%d trailing bytes", len(remaining))
	}
	return stored, nil
}
