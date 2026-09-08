package mdbentry

import (
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func TestConfigGrammar(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint64
		code  uint16
	}{
		{"0", 0, 0}, {"1", 1, 0}, {"18446744073709551615", ^uint64(0), 0},
		{"18446744073709551616", 0, 19}, {"-1", 0, 19}, {"-0", 0, 21},
		{"01", 0, 21}, {"+1", 0, 21}, {"0x10", 0, 21}, {"", 0, 21}, {"1\x00", 0, 21},
	} {
		got, err := ParseValue(tc.value)
		if tc.code == 0 {
			if err != nil || got != tc.want {
				t.Fatalf("%q: %d %v", tc.value, got, err)
			}
			continue
		}
		var configErr *ConfigError
		if !errors.As(err, &configErr) || configErr.Code != tc.code {
			t.Fatalf("%q: %v, want code %d", tc.value, err, tc.code)
		}
	}
	for raw, want := range map[string]uint64{"0": 0, "+1": 1, "010": 8, "0x10": 16, "+0Xff": 255, "18446744073709551615": ^uint64(0)} {
		got, err := ParseDirective(raw)
		if got != want || err != nil {
			t.Fatalf("directive %q: %d %v", raw, got, err)
		}
	}
	for _, raw := range []string{"-1", "-0", " 1", "1 ", "1K", "08", "0b10", "1_000", "18446744073709551616"} {
		if _, err := ParseDirective(raw); err == nil {
			t.Fatalf("accepted directive %q", raw)
		}
	}
}

func TestExactStorageAccounting(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values []string
		size   uint64
	}{
		{"cn", []string{"Test"}, 42}, // 16+8+(4+5)+(4+5)
		{"cn", []string{"  "}, 37},   // normalized all-space Directory String is one space
		{"jpegPhoto", []string{string([]byte{0, 255, 1})}, 32},
		{"entryUUID", []string{"11111111-1111-1111-1111-111111111111"}, 86},
		{"objectClass", []string{"top", "person"}, 43},
		{"description;lang-en", []string{"One", " Two "}, 58},
	} {
		entry := directory.Entry{DN: "cn=ignored", Attributes: []directory.Attribute{{Description: tc.name}}}
		for _, v := range tc.values {
			entry.Attributes[0].Values = append(entry.Attributes[0].Values, []byte(v))
		}
		if err := Check(entry, registry, tc.size); err != nil {
			t.Fatalf("%s exact=%d: %v", tc.name, tc.size, err)
		}
		if err := Check(entry, registry, tc.size-1); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("%s below boundary: %v", tc.name, err)
		}
		entry.DN = strings.Repeat("cn=ignored,", 1000) + "dc=test"
		if err := Check(entry, registry, tc.size); err != nil {
			t.Fatalf("DN counted: %v", err)
		}
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{Description: "description", Values: [][]byte{[]byte(strings.Repeat("x", 8<<20))}}}}
	if got := testing.AllocsPerRun(10, func() {
		if !errors.Is(Check(entry, registry, 1024), ErrTooLarge) {
			panic("limit bypass")
		}
	}); got != 0 {
		t.Fatalf("large rejected entry allocated %g objects", got)
	}
	if err := Check(entry, registry, 0); err != nil {
		t.Fatal(err)
	}
}
