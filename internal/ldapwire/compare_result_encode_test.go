package ldapwire

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Keep the original packet path as an oracle for the complete LDAPMessage.
func encodeResultResponseOldPacket(messageID int64, tag uint64, result Result, controls []Control) []byte {
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, "LDAPResult")
	appendLDAPResult(response, result)
	return encodeMessage(messageID, response, controls)
}

func TestCompareResultEncodingMatchesOldPacket(t *testing.T) {
	t.Parallel()

	for _, code := range []ResultCode{ResultCompareFalse, ResultCompareTrue} {
		for _, messageID := range []int64{
			math.MinInt64, -32769, -129, -128, -1, 0, 1, 127, 128, 255, 256,
			32767, 32768, 65535, 65536, 1<<23 - 1, 1 << 23,
			1<<24 - 1, 1 << 24, math.MaxInt32, math.MaxInt32 + 1, math.MaxInt64,
		} {
			for _, test := range []struct {
				name     string
				result   Result
				controls []Control
			}{
				{name: "empty"},
				{name: "empty-slices", result: Result{Referrals: []string{}}, controls: []Control{}},
				{name: "matched-dn", result: Result{MatchedDN: "dc=example,dc=com"}},
				{name: "diagnostic", result: Result{DiagnosticMessage: "compare diagnostic\x00\xff"}},
				{name: "referral", result: Result{Referrals: []string{"ldap://example/dc=example,dc=com"}}},
				{name: "empty-referral", result: Result{Referrals: []string{""}}},
				{name: "control", controls: []Control{{OID: "1.2.3"}}},
				{name: "critical-control", controls: []Control{{OID: "1.2.3", Critical: true}}},
				{name: "explicit-empty-control-value", controls: []Control{{OID: "1.2.3", HasValue: true}}},
				{name: "implicit-empty-control-value", controls: []Control{{OID: "1.2.3", Value: []byte{}}}},
				{name: "binary-control-value", controls: []Control{{OID: "1.2.3", Value: []byte{0, 0xff, 0x80}}}},
				{
					name: "all-fields",
					result: Result{
						MatchedDN: "dc=example,dc=com", DiagnosticMessage: "compare diagnostic",
						Referrals: []string{"ldap://one.example", "ldaps://two.example"},
					},
					controls: []Control{
						{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 0xff}},
						{OID: "1.2.4", Value: []byte{0x30, 0x81, 3, 0x02, 1, 0xff}},
					},
				},
			} {
				t.Run(fmt.Sprintf("code%d/id%d/%s", code, messageID, test.name), func(t *testing.T) {
					test.result.Code = code
					assertResultResponseMatchesOldPacket(t, messageID, ApplicationCompareResponse, test.result, test.controls)
				})
			}
		}
	}
}

func TestCompareResultEncodingLengthBoundaries(t *testing.T) {
	t.Parallel()

	for _, code := range []ResultCode{ResultCompareFalse, ResultCompareTrue} {
		for _, length := range []int{1, 110, 111, 117, 118, 125, 126, 127, 128, 255, 256, 65535, 65536} {
			t.Run(fmt.Sprintf("code%d/length%d", code, length), func(t *testing.T) {
				value := strings.Repeat("x", length)
				for _, result := range []Result{
					{Code: code, MatchedDN: value},
					{Code: code, DiagnosticMessage: value},
					{Code: code, Referrals: []string{value}},
				} {
					assertResultResponseMatchesOldPacket(t, 128, ApplicationCompareResponse, result, nil)
				}
				assertResultResponseMatchesOldPacket(t, 128, ApplicationCompareResponse, Result{Code: code}, []Control{
					{OID: "1.2.3", Critical: true, HasValue: true, Value: bytes.Repeat([]byte{0xff}, length)},
				})
			})
		}
	}
}

func TestResultEncodingTagsAndCodesMatchOldPacket(t *testing.T) {
	t.Parallel()

	for _, tag := range []uint64{
		ApplicationBindResponse, ApplicationSearchResultDone, ApplicationCompareResponse,
		30, 31, 128, 256,
	} {
		for _, code := range []ResultCode{
			ResultSuccess, ResultCompareFalse, ResultCompareTrue,
			ResultNoSuchAttribute, ResultInvalidCredentials, 127, 128, 255, 256, 65535,
		} {
			for _, messageID := range []int64{-1, 0, 128, math.MaxInt32, math.MaxInt32 + 1, math.MaxInt64} {
				t.Run(fmt.Sprintf("tag%d/code%d/id%d", tag, code, messageID), func(t *testing.T) {
					assertResultResponseMatchesOldPacket(t, messageID, tag, Result{Code: code}, nil)
				})
			}
		}
	}
}

func assertResultResponseMatchesOldPacket(t *testing.T, messageID int64, tag uint64, result Result, controls []Control) {
	t.Helper()
	want := encodeResultResponseOldPacket(messageID, tag, result, controls)
	got := EncodeResultResponse(messageID, tag, result, controls)
	if !bytes.Equal(got, want) {
		t.Fatalf("LDAPMessage differs from old packet encoding:\ngot  %x\nwant %x", got, want)
	}
	again := EncodeResultResponse(messageID, tag, result, controls)
	clear(got)
	if !bytes.Equal(again, want) {
		t.Fatal("encoded responses share mutable storage")
	}
}

func BenchmarkEncodeCompareResultResponse(b *testing.B) {
	for _, test := range []struct {
		name string
		code ResultCode
	}{
		{name: "False", code: ResultCompareFalse},
		{name: "True", code: ResultCompareTrue},
	} {
		b.Run(test.name, func(b *testing.B) {
			result := Result{Code: test.code}
			size := int64(len(encodeResultResponseOldPacket(128, ApplicationCompareResponse, result, nil)))
			b.Run("Direct", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(size)
				for b.Loop() {
					_ = EncodeResultResponse(128, ApplicationCompareResponse, result, nil)
				}
			})
			b.Run("OldPacket", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(size)
				for b.Loop() {
					_ = encodeResultResponseOldPacket(128, ApplicationCompareResponse, result, nil)
				}
			})
		})
	}
}
