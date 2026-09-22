package ldapwire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"testing/iotest"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Keep the packet-based path as an oracle without replacing production files.
func readSearchMessageReference(reader io.Reader, maxSize int64, maxContent uint64, depth func() int) (Message, int, error) {
	frame, err := readFrameWithContentLimit(reader, maxSize, maxContent)
	if err != nil {
		return Message{}, 0, err
	}
	packet, err := ber.DecodePacketErr(frame)
	if err != nil {
		return Message{}, len(frame), malformed("decode BER: %v", err)
	}
	message, err := decodeMessageWithFilterDepth(packet, depth())
	return message, len(frame), err
}

func compareSearchDecode(t testing.TB, data []byte, maxSize int64, maxContent uint64, depth int) {
	t.Helper()
	reader, referenceReader := bytes.NewReader(data), bytes.NewReader(data)
	calls, referenceCalls := 0, 0
	got, size, err := ReadMessageWithDynamicFilterDepthAndSize(reader, maxSize, maxContent, func() int {
		calls++
		return depth
	})
	want, referenceSize, referenceErr := readSearchMessageReference(referenceReader, maxSize, maxContent, func() int {
		referenceCalls++
		return depth
	})
	if !reflect.DeepEqual(got, want) || size != referenceSize || fmt.Sprint(err) != fmt.Sprint(referenceErr) ||
		calls != referenceCalls || reader.Len() != referenceReader.Len() {
		t.Fatalf("frame %x, limits %d/%d/%d\ngot:  %#v, size %d, error %v, calls %d, remaining %d\nwant: %#v, size %d, error %v, calls %d, remaining %d",
			data, maxSize, maxContent, depth, got, size, err, calls, reader.Len(),
			want, referenceSize, referenceErr, referenceCalls, referenceReader.Len())
	}
	for _, sentinel := range []error{ErrMalformedMessage, ErrMessageTooLarge, ErrFilterTooDeep, io.EOF, io.ErrUnexpectedEOF} {
		if errors.Is(err, sentinel) != errors.Is(referenceErr, sentinel) {
			t.Fatalf("frame %x: errors.Is(%v) differs: %v / %v", data, sentinel, err, referenceErr)
		}
	}
}

func searchTestTLV(tag byte, children ...[]byte) []byte {
	packet := ber.Encode(ber.Class(tag&0xc0), ber.Type(tag&0x20), ber.Tag(tag&0x1f), nil, "")
	for _, child := range children {
		_, _ = packet.Data.Write(child)
	}
	return packet.Bytes()
}

func searchTestFields() [][]byte {
	return [][]byte{
		searchTestTLV(0x04, []byte("dc=example,dc=com")),
		{0x0a, 1, 2}, {0x0a, 1, 0}, {0x02, 1, 0}, {0x02, 1, 0}, {0x01, 1, 0},
		searchTestTLV(0xa3, searchTestTLV(0x04, []byte("uid")), searchTestTLV(0x04, []byte("alice"))),
		searchTestTLV(0x30, searchTestTLV(0x04, []byte("cn"))),
	}
}

func TestShortSearchFrameEligibility(t *testing.T) {
	for name, frame := range searchDecodeFixtures(t) {
		t.Run(name, func(t *testing.T) {
			got, ok := decodeShortSearchFrame(frame)
			if want := name == "Equality" || name == "Presence"; ok != want {
				t.Fatalf("fast path = %v, want %v", ok, want)
			}
			if ok {
				want, _, err := readSearchMessageReference(bytes.NewReader(frame), 4096, 0, func() int { return 0 })
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("fast path = %#v, reference = %#v, error %v", got, want, err)
				}
			}
			compareSearchDecode(t, frame, 4096, 0, DefaultMaxFilterDepth)
		})
	}
}

func TestShortSearchIntegers(t *testing.T) {
	values := [][]byte{
		nil, {0}, {1}, {0x7f}, {0x80}, {0xff}, {0, 0x80}, {0, 0, 1},
		{0x7f, 0xff, 0xff, 0xff}, {0x80, 0, 0, 0}, {0, 0x80, 0, 0, 0},
		{0xff, 0x7f, 0xff, 0xff, 0xff},
		{0, 0, 0, 0, 0, 0, 0, 1}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	for _, value := range values {
		for _, tag := range []byte{0x02, 0x0a} {
			id := searchTestTLV(tag, value)
			compareSearchDecode(t, searchTestTLV(0x30, id, searchTestTLV(0x63, searchTestFields()...)), 4096, 0, 0)
			for index := 1; index <= 4; index++ {
				fields := searchTestFields()
				fields[index] = searchTestTLV(tag, value)
				frame := searchTestTLV(0x30, []byte{0x02, 1, 1}, searchTestTLV(0x63, fields...))
				compareSearchDecode(t, frame, 4096, 0, 0)
			}
		}
	}
}

func searchDecodeEdgeFrames() map[string][]byte {
	frames := make(map[string][]byte)
	wrap := func(fields [][]byte) []byte {
		return searchTestTLV(0x30, []byte{0x02, 1, 1}, searchTestTLV(0x63, fields...))
	}
	for _, value := range [][]byte{nil, {0}, {1}, {0x7f}, {0x80}, {0xff}, {0, 1}} {
		fields := searchTestFields()
		fields[5] = searchTestTLV(0x01, value)
		frames[fmt.Sprintf("boolean-%x", value)] = wrap(fields)
	}
	for name, filter := range map[string][]byte{
		"empty-assertion":      searchTestTLV(0xa3, searchTestTLV(0x04, []byte("uid")), []byte{0x04, 0}),
		"binary-assertion":     searchTestTLV(0xa3, searchTestTLV(0x04, []byte("uid")), []byte{0x04, 3, 0, 0xff, 0x80}),
		"empty-attribute":      searchTestTLV(0xa3, []byte{0x04, 0}, []byte{0x04, 0}),
		"empty-present":        {0x87, 0},
		"indefinite-equality":  {0xa3, 0x80, 0x04, 1, 'x', 0x04, 1, 'y', 0, 0},
		"extra-equality-child": {0xa3, 8, 0x04, 1, 'x', 0x04, 1, 'y', 0x04, 0},
		"high-present-tag":     {0x9f, 7, 1, 'x'},
		"nonminimal-length":    {0xa3, 0x81, 6, 0x04, 1, 'x', 0x04, 1, 'y'},
		"leading-zero-length":  {0xa3, 0x82, 0, 6, 0x04, 1, 'x', 0x04, 1, 'y'},
		"primitive-indefinite": {0x87, 0x80, 0, 0},
	} {
		fields := searchTestFields()
		fields[6] = filter
		frames[name] = wrap(fields)
	}
	for name, selection := range map[string][]byte{
		"empty-selection":          {0x30, 0},
		"empty-selected-attribute": {0x30, 2, 0x04, 0},
		"indefinite-selection":     {0x30, 0x80, 0x04, 1, '*', 0, 0},
		"high-selected-tag":        {0x30, 4, 0x1f, 4, 1, '*'},
		"invalid-selection":        {0x30, 3, 0x02, 1, 1},
	} {
		fields := searchTestFields()
		fields[7] = selection
		frames[name] = wrap(fields)
	}
	fields := searchTestFields()
	operation := searchTestTLV(0x63, fields...)
	id := []byte{0x02, 1, 1}
	frames["high-id-tag"] = searchTestTLV(0x30, []byte{0x1f, 2, 1, 1}, operation)
	frames["indefinite-operation"] = searchTestTLV(0x30, id, []byte{0x63, 0x80}, bytes.Join(fields, nil), []byte{0, 0})
	frames["primitive-operation"] = searchTestTLV(0x30, id, searchTestTLV(0x43, fields...))
	frames["high-operation-tag"] = searchTestTLV(0x30, id, append([]byte{0x7f, 3}, operation[1:]...))
	frames["extra-search-field"] = searchTestTLV(0x30, id, searchTestTLV(0x63, append(fields, []byte{0x04, 0})...))
	frames["missing-search-field"] = searchTestTLV(0x30, id, searchTestTLV(0x63, fields[:7]...))
	frames["extra-envelope-child"] = searchTestTLV(0x30, id, operation, []byte{0xa0, 0, 0x04, 0})
	for name, controls := range map[string][]byte{
		"empty-controls":         {0xa0, 0},
		"wrong-controls-wrapper": {0x30, 0},
		"malformed-control":      {0xa0, 2, 0x04, 0},
		"invalid-control-value":  {0xa0, 8, 0x30, 6, 0x04, 1, 'x', 0x02, 1, 1},
		"malformed-control-ber":  {0xa0, 1, 0x30},
	} {
		frames[name] = searchTestTLV(0x30, id, operation, controls)
	}
	return frames
}

func TestShortSearchBERCompatibility(t *testing.T) {
	for name, frame := range searchDecodeEdgeFrames() {
		t.Run(name, func(t *testing.T) {
			for _, depth := range []int{-1, 0, DefaultMaxFilterDepth} {
				compareSearchDecode(t, frame, 4096, 0, depth)
			}
		})
	}
}

func TestShortSearchLengthBoundary(t *testing.T) {
	for _, contentLength := range []int{126, 127, 128, 129} {
		fields := searchTestFields()
		fields[6] = []byte{0x87, 0}
		emptyFrame := searchTestTLV(0x30, []byte{0x02, 1, 1}, searchTestTLV(0x63, fields...))
		fields[6] = searchTestTLV(0x87, bytes.Repeat([]byte("a"), contentLength-(len(emptyFrame)-2)))
		frame := searchTestTLV(0x30, []byte{0x02, 1, 1}, searchTestTLV(0x63, fields...))
		headerLength := 2
		if frame[1]&0x80 != 0 {
			headerLength += int(frame[1] & 0x7f)
		}
		if len(frame)-headerLength != contentLength {
			t.Fatalf("fixture content length = %d, want %d", len(frame)-headerLength, contentLength)
		}
		if _, ok := decodeShortSearchFrame(frame); ok != (contentLength < 128) {
			t.Fatalf("content length %d: fast path = %v", contentLength, ok)
		}
		compareSearchDecode(t, frame, int64(len(frame)), uint64(contentLength), 0)
		compareSearchDecode(t, frame, int64(len(frame)-1), uint64(contentLength), 0)
		compareSearchDecode(t, frame, int64(len(frame)), uint64(contentLength-1), 0)
	}
}

func TestShortSearchByteMutations(t *testing.T) {
	for _, name := range []string{"Equality", "Presence", "Controls", "Nested"} {
		frame := searchDecodeFixtures(t)[name]
		t.Run(name, func(t *testing.T) {
			for offset := range frame {
				compareSearchDecode(t, frame[:offset], 4096, 0, 0)
				mutated := bytes.Clone(frame)
				for value := 0; value < 256; value++ {
					mutated[offset] = byte(value)
					compareSearchDecode(t, mutated, 4096, 0, 0)
				}
			}
		})
	}
}

func TestShortSearchLimits(t *testing.T) {
	for _, frame := range searchDecodeFixtures(t) {
		headerLength := 2
		if frame[1]&0x80 != 0 {
			headerLength += int(frame[1] & 0x7f)
		}
		contentLength := len(frame) - headerLength
		for _, maxSize := range []int64{-1, 0, 1, int64(len(frame) - 1), int64(len(frame)), 4096} {
			for _, maxContent := range []uint64{0, 1, uint64(contentLength - 1), uint64(contentLength), 4096} {
				for _, depth := range []int{-1, 0, 1, DefaultMaxFilterDepth} {
					compareSearchDecode(t, frame, maxSize, maxContent, depth)
				}
			}
		}
	}
	// These library globals are also part of the reference decoder's contract.
	oldLength, oldDepth := ber.MaxPacketLengthBytes, ber.MaxNestingDepth
	t.Cleanup(func() { ber.MaxPacketLengthBytes, ber.MaxNestingDepth = oldLength, oldDepth })
	for _, frame := range searchDecodeFixtures(t) {
		for _, maxLength := range []int64{-1, 0, 1, int64(len(frame) - 3), int64(len(frame) - 2)} {
			for _, maxDepth := range []int{-1, 0, 1, 2, 3, 4, 5} {
				ber.MaxPacketLengthBytes, ber.MaxNestingDepth = maxLength, maxDepth
				compareSearchDecode(t, frame, 4096, 0, 0)
			}
		}
	}
}

func TestShortSearchStreamAndOwnership(t *testing.T) {
	for _, frame := range searchDecodeFixtures(t) {
		stream := bytes.NewReader(bytes.Repeat(frame, 2))
		for range 2 {
			calls := 0
			got, size, err := ReadMessageWithDynamicFilterDepthAndSize(iotest.OneByteReader(stream), 4096, 0, func() int {
				calls++
				if stream.Len()%len(frame) != 0 {
					t.Fatal("depth provider called before complete frame was read")
				}
				return DefaultMaxFilterDepth
			})
			want, _, referenceErr := readSearchMessageReference(bytes.NewReader(frame), 4096, 0, func() int { return DefaultMaxFilterDepth })
			if err != nil || referenceErr != nil || calls != 1 || size != len(frame) || !reflect.DeepEqual(got, want) {
				t.Fatalf("stream decode = %#v, %d, %v; reference %#v, %v", got, size, err, want, referenceErr)
			}
		}
		if stream.Len() != 0 {
			t.Fatal("unread stream data")
		}
		if got, ok := decodeShortSearchFrame(frame); ok {
			want, _ := decodeShortSearchFrame(bytes.Clone(frame))
			clear(frame)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("decoded request aliases input frame")
			}
		}
	}
}

func TestPacketStringCopiesData(t *testing.T) {
	for _, value := range [][]byte{nil, []byte("uid"), {0, 0xff, 0x80}} {
		packet := octetString(value)
		got, err := packetString(packet)
		if err != nil || got != string(value) {
			t.Fatalf("packetString = %q, %v", got, err)
		}
		clear(packet.Data.Bytes())
		if got != string(value) {
			t.Fatal("decoded string aliases packet data")
		}
	}
	for _, packet := range []*ber.Packet{nil, ber.NewSequence(""), ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "")} {
		got, err := packetString(packet)
		if got != "" || err == nil || err.Error() != "not an octet string" {
			t.Fatalf("invalid packet: %q, %v", got, err)
		}
	}
}

func FuzzReadSearchMessageReference(f *testing.F) {
	for _, frame := range searchDecodeFixtures(f) {
		f.Add(frame, int8(0))
	}
	for _, frame := range searchDecodeEdgeFrames() {
		f.Add(frame, int8(0))
	}
	for _, frame := range [][]byte{nil, {0x30, 0x80}, {0x30, 0x81, 1}, {0x30, 0x82, 0, 0x80}, {0x30, 0x89}} {
		f.Add(frame, int8(-1))
	}
	f.Fuzz(func(t *testing.T, frame []byte, depth int8) {
		compareSearchDecode(t, frame, 64<<10, 32<<10, int(depth))
	})
}
