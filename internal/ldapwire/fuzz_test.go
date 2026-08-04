package ldapwire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func FuzzReadMessageRoundTrip(f *testing.F) {
	seeds := []Message{
		{
			ID: 1,
			Request: BindRequest{
				Version: 3,
				Name:    "cn=admin,dc=example,dc=com",
				Authentication: Authentication{
					Simple: []byte("secret"),
				},
			},
		},
		{
			ID: 2,
			Request: SearchRequest{
				BaseDN:       "dc=example,dc=com",
				Scope:        directory.ScopeWholeSubtree,
				DerefAliases: NeverDerefAliases,
				SizeLimit:    100,
				Filter: directory.Filter{
					Kind: directory.FilterAnd,
					Children: []directory.Filter{
						{
							Kind:      directory.FilterEquality,
							Attribute: "objectClass",
							Assertion: []byte("person"),
						},
						{
							Kind:      directory.FilterPresent,
							Attribute: "uid",
						},
					},
				},
				Attributes: []string{"uid", "cn"},
			},
			Controls: []Control{{
				OID:      "1.2.840.113556.1.4.319",
				Critical: true,
				Value:    []byte{0x30, 0x05, 0x02, 0x01, 0x05, 0x04, 0x00},
				HasValue: true,
			}},
		},
		{
			ID: 3,
			Request: AddRequest{Entry: directory.Entry{
				DN: "uid=alice,ou=people,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{
						Description: "objectClass",
						Values:      [][]byte{[]byte("inetOrgPerson")},
					},
					{Description: "uid", Values: [][]byte{[]byte("alice")}},
					{Description: "cn", Values: [][]byte{[]byte("Alice")}},
					{Description: "sn", Values: [][]byte{[]byte("Example")}},
				},
			}},
		},
	}
	for _, seed := range seeds {
		encoded, err := EncodeRequestMessage(seed)
		if err != nil {
			f.Fatalf("encode seed: %v", err)
		}
		f.Add(encoded)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := ReadMessage(bytes.NewReader(data), 64<<10)
		if err != nil {
			return
		}
		encoded, err := EncodeRequestMessage(message)
		if err != nil {
			if _, unsupported := message.Request.(UnsupportedRequest); unsupported {
				return
			}
			t.Fatalf("re-encode %T: %v", message.Request, err)
		}
		roundTripped, err := ReadMessage(bytes.NewReader(encoded), int64(len(encoded)))
		if err != nil {
			t.Fatalf("decode re-encoded %T: %v", message.Request, err)
		}
		if !reflect.DeepEqual(roundTripped, message) {
			t.Fatalf("message round trip mismatch\nfirst:  %#v\nsecond: %#v", message, roundTripped)
		}
	})
}

func FuzzDecodeFilterRoundTrip(f *testing.F) {
	seeds := []directory.Filter{
		{Kind: directory.FilterPresent, Attribute: "objectClass"},
		{
			Kind:      directory.FilterEquality,
			Attribute: "uid",
			Assertion: []byte("alice"),
		},
		{
			Kind:      directory.FilterSubstrings,
			Attribute: "cn",
			Substring: directory.Substring{
				Initial: []byte("Al"),
				Any:     [][]byte{[]byte("ic")},
				Final:   []byte("e"),
			},
		},
	}
	for _, seed := range seeds {
		packet, err := encodeFilter(seed, 0)
		if err != nil {
			f.Fatalf("encode filter seed: %v", err)
		}
		f.Add(packet.Bytes())
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		filter, err := DecodeFilter(data)
		if err != nil {
			return
		}
		packet, err := encodeFilter(filter, 0)
		if err != nil {
			t.Fatalf("re-encode filter: %v", err)
		}
		roundTripped, err := DecodeFilter(packet.Bytes())
		if err != nil {
			t.Fatalf("decode re-encoded filter: %v", err)
		}
		if !reflect.DeepEqual(roundTripped, filter) {
			t.Fatalf("filter round trip mismatch\nfirst:  %#v\nsecond: %#v", filter, roundTripped)
		}
	})
}
