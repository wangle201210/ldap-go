package ldapwire

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestGeneralizedResultEncodingMatchesOldPacket(t *testing.T) {
	t.Parallel()

	codes := []ResultCode{
		ResultSuccess, ResultOperationsError, ResultProtocolError,
		ResultTimeLimitExceeded, ResultSizeLimitExceeded, ResultCompareFalse, ResultCompareTrue,
		ResultReferral, ResultNoSuchAttribute, ResultNoSuchObject, ResultInvalidCredentials,
		ResultInsufficientAccessRights, ResultUnwillingToPerform, ResultOther,
		ResultSyncRefreshRequired, ResultNoOperation, ResultTransactionIDInvalid,
		-1, 255, 256, 65535, 65536, math.MinInt, math.MaxInt,
	}
	for shift := 7; shift < strconv.IntSize-1; shift += 8 {
		boundary := ResultCode(1) << shift
		codes = append(codes, -boundary-1, -boundary, boundary-1, boundary)
	}
	for _, tag := range []uint64{
		ApplicationBindResponse, ApplicationSearchResultDone, ApplicationModifyResponse,
		ApplicationAddResponse, ApplicationDeleteResponse, ApplicationModifyDNResponse,
		ApplicationCompareResponse, 0, 30, 31, 127, 128, 255, 256, math.MaxUint64,
	} {
		for _, code := range codes {
			for _, test := range []struct {
				name       string
				matchedDN  string
				diagnostic string
			}{
				{name: "empty"},
				{name: "matched-dn", matchedDN: "dc=example,dc=com"},
				{name: "diagnostic", diagnostic: "invalid credentials"},
				{name: "binary", matchedDN: "dn\x00\xff", diagnostic: "diagnostic\x80\x00\xff"},
				{name: "utf8", matchedDN: "uid=\u7528\u6237,dc=example", diagnostic: "\u5bc6\u7801\u65e0\u6548"},
				{name: "long-fields", matchedDN: strings.Repeat("d", 128), diagnostic: strings.Repeat("x", 256)},
			} {
				t.Run(fmt.Sprintf("tag%d/code%d/%s", tag, code, test.name), func(t *testing.T) {
					assertResultResponseMatchesOldPacket(t, 128, tag, Result{
						Code: code, MatchedDN: test.matchedDN, DiagnosticMessage: test.diagnostic,
					}, nil)
				})
			}
		}
	}
}

func TestGeneralizedResultEncodingMessageIDBoundaries(t *testing.T) {
	t.Parallel()

	messageIDs := []int64{math.MinInt64, -1, 0, 1, 255, 256, 65535, 65536, math.MaxInt64}
	for shift := 7; shift < 63; shift += 8 {
		boundary := int64(1) << shift
		messageIDs = append(messageIDs, -boundary-1, -boundary, boundary-1, boundary)
	}
	for _, messageID := range messageIDs {
		for _, code := range []ResultCode{ResultInvalidCredentials, 128, math.MinInt, math.MaxInt} {
			t.Run(fmt.Sprintf("id%d/code%d", messageID, code), func(t *testing.T) {
				for _, tag := range []uint64{ApplicationBindResponse, ApplicationSearchResultDone, ApplicationCompareResponse} {
					assertResultResponseMatchesOldPacket(t, messageID, tag, Result{Code: code}, nil)
					assertResultResponseMatchesOldPacket(t, messageID, tag, Result{
						Code: code, MatchedDN: "dc=example", DiagnosticMessage: "failure\x00\xff",
					}, nil)
				}
			})
		}
	}
}

func TestGeneralizedResultEncodingLengthBoundaries(t *testing.T) {
	t.Parallel()

	lengths := []int{0, 1}
	for _, boundary := range []int{128, 256, 65536} {
		// Include the enclosing operation and message length transitions as well
		// as the string transition, including eight-byte IDs and result codes.
		for offset := -1; offset <= 32; offset++ {
			lengths = append(lengths, boundary-offset)
		}
	}
	for _, length := range lengths {
		for _, code := range []ResultCode{ResultInvalidCredentials, 128, math.MaxInt} {
			t.Run(fmt.Sprintf("length%d/code%d", length, code), func(t *testing.T) {
				value := strings.Repeat("\xff", length)
				for _, messageID := range []int64{128, math.MaxInt64} {
					for _, result := range []Result{
						{Code: code, MatchedDN: value},
						{Code: code, DiagnosticMessage: value},
						{Code: code, MatchedDN: value, DiagnosticMessage: value},
					} {
						assertResultResponseMatchesOldPacket(t, messageID, ApplicationBindResponse, result, nil)
					}
				}
			})
		}
	}
}

func TestGeneralizedResultEncodingControlsAndReferrals(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		referrals []string
		controls  []Control
	}{
		{name: "nil"},
		{name: "empty", referrals: []string{}, controls: []Control{}},
		{name: "empty-referral", referrals: []string{""}},
		{name: "referrals", referrals: []string{"ldap://one.example", "ldaps://two.example", "ldap://one.example"}},
		{name: "binary-referral", referrals: []string{"ldap://example/\x00\xff"}},
		{name: "absent-value", controls: []Control{{OID: "1.2.3"}}},
		{name: "critical", controls: []Control{{OID: "1.2.3", Critical: true}}},
		{name: "explicit-empty", controls: []Control{{OID: "1.2.3", HasValue: true}}},
		{name: "implicit-empty", controls: []Control{{OID: "1.2.3", Value: []byte{}}}},
		{name: "binary-value", controls: []Control{{OID: "1.2.3", Value: []byte{0, 0xff, 0x80}}}},
		{
			name: "all-fields", referrals: []string{"", "ldap://example/\x00\xff"},
			controls: []Control{
				{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte{0, 0xff}},
				{OID: "1.2.3", Value: []byte{0x30, 0x81, 3, 0x02, 1, 0xff}},
				{OID: "", Critical: true, HasValue: true},
				{OID: "1.02.3\x00\xff"},
			},
		},
	} {
		for _, code := range []ResultCode{-1, ResultInvalidCredentials, 128, math.MaxInt} {
			for _, messageID := range []int64{-1, 128, math.MaxInt64} {
				t.Run(fmt.Sprintf("%s/code%d/id%d", test.name, code, messageID), func(t *testing.T) {
					for _, tag := range []uint64{ApplicationBindResponse, ApplicationSearchResultDone, ApplicationCompareResponse, 31} {
						assertResultResponseMatchesOldPacket(t, messageID, tag, Result{
							Code: code, MatchedDN: "dc=example", DiagnosticMessage: "diagnostic\x00\xff", Referrals: test.referrals,
						}, test.controls)
					}
				})
			}
		}
	}
	for _, length := range []int{0, 1, 110, 111, 117, 118, 120, 121, 125, 126, 127, 128, 255, 256, 65535, 65536} {
		t.Run(fmt.Sprintf("length%d", length), func(t *testing.T) {
			value := strings.Repeat("\xff", length)
			result := Result{Code: ResultInvalidCredentials, Referrals: []string{value}}
			assertResultResponseMatchesOldPacket(t, 128, ApplicationBindResponse, result, nil)
			controls := []Control{{OID: "1.2.3", Critical: true, HasValue: true, Value: []byte(value)}}
			assertResultResponseMatchesOldPacket(t, 128, ApplicationBindResponse, result, controls)
			result.Referrals = nil
			assertResultResponseMatchesOldPacket(t, 128, ApplicationBindResponse, result, controls)
		})
	}
}

func TestGeneralizedResultEncodingWrappers(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		tag    uint64
		encode func(int64, Result, []Control) []byte
	}{
		{name: "bind", tag: ApplicationBindResponse, encode: EncodeBindResponse},
		{name: "search-done", tag: ApplicationSearchResultDone, encode: EncodeSearchResultDone},
	} {
		for _, code := range []ResultCode{-1, ResultSuccess, ResultInvalidCredentials, 128, math.MaxInt} {
			t.Run(fmt.Sprintf("%s/code%d", test.name, code), func(t *testing.T) {
				for _, messageID := range []int64{-1, 0, 128, math.MaxInt64} {
					for _, controls := range [][]Control{nil, {}, {{OID: "1.2.3", HasValue: true}}} {
						for _, referrals := range [][]string{nil, {}, {"ldap://example"}} {
							result := Result{Code: code, DiagnosticMessage: "diagnostic\x00\xff", Referrals: referrals}
							want := encodeResultResponseOldPacket(messageID, test.tag, result, controls)
							got := test.encode(messageID, result, controls)
							if !bytes.Equal(got, want) {
								t.Fatalf("LDAPMessage differs from old packet encoding:\ngot  %x\nwant %x", got, want)
							}
							again := test.encode(messageID, result, controls)
							clear(got)
							if !bytes.Equal(again, want) || !bytes.Equal(test.encode(messageID, result, controls), want) {
								t.Fatal("encoded response aliases inputs or other responses")
							}
						}
					}
				}
			})
		}
	}
}

func TestGeneralizedResultEncodingAllocations(t *testing.T) {
	for _, test := range []struct {
		name      string
		messageID int64
		tag       uint64
		result    Result
	}{
		{name: "bind-success", messageID: 128, tag: ApplicationBindResponse},
		{name: "search-success", messageID: math.MaxInt64, tag: ApplicationSearchResultDone},
		{name: "compare-false", messageID: 128, tag: ApplicationCompareResponse, result: Result{Code: ResultCompareFalse}},
		{name: "compare-true", messageID: math.MaxInt32, tag: ApplicationCompareResponse, result: Result{Code: ResultCompareTrue}},
		{name: "invalid-credentials", messageID: 128, tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials}},
		{name: "diagnostic", messageID: 128, tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}},
		{name: "long-fields", messageID: 128, tag: ApplicationModifyResponse, result: Result{
			Code: ResultNoSuchObject, MatchedDN: strings.Repeat("d", 128), DiagnosticMessage: strings.Repeat("x", 65536),
		}},
		{name: "max-code-and-id", messageID: math.MaxInt64, tag: ApplicationBindResponse, result: Result{Code: math.MaxInt}},
		{name: "empty-slices", messageID: 128, tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials, Referrals: []string{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var encoded []byte
			allocations := testing.AllocsPerRun(100, func() {
				encoded = EncodeResultResponse(test.messageID, test.tag, test.result, []Control{})
			})
			if allocations != 1 {
				t.Fatalf("encoding allocated %g times, want one output allocation", allocations)
			}
			want := encodeResultResponseOldPacket(test.messageID, test.tag, test.result, nil)
			if !bytes.Equal(encoded, want) {
				t.Fatalf("LDAPMessage differs from old packet encoding:\ngot  %x\nwant %x", encoded, want)
			}
		})
	}
}

func BenchmarkEncodeGeneralizedResultResponse(b *testing.B) {
	for _, test := range []struct {
		name     string
		tag      uint64
		result   Result
		controls []Control
	}{
		{name: "BindSuccess", tag: ApplicationBindResponse},
		{name: "CompareFalse", tag: ApplicationCompareResponse, result: Result{Code: ResultCompareFalse}},
		{name: "CompareTrue", tag: ApplicationCompareResponse, result: Result{Code: ResultCompareTrue}},
		{name: "InvalidCredentials", tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials}},
		{name: "BindDiagnostic", tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}},
		{name: "SearchLimit", tag: ApplicationSearchResultDone, result: Result{Code: ResultSizeLimitExceeded, DiagnosticMessage: "size limit exceeded"}},
		{name: "ModifyMatchedDN", tag: ApplicationModifyResponse, result: Result{Code: ResultNoSuchObject, MatchedDN: "dc=example,dc=com"}},
		{name: "LongDiagnostic", tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials, DiagnosticMessage: strings.Repeat("x", 65536)}},
		{name: "MaxResultCode", tag: ApplicationBindResponse, result: Result{Code: math.MaxInt}},
		{name: "ControlFallback", tag: ApplicationBindResponse, result: Result{Code: ResultInvalidCredentials}, controls: []Control{{OID: "1.2.3", HasValue: true}}},
		{name: "ReferralFallback", tag: ApplicationSearchResultDone, result: Result{Code: ResultReferral, Referrals: []string{"ldap://example"}}},
	} {
		b.Run(test.name, func(b *testing.B) {
			size := int64(len(encodeResultResponseOldPacket(128, test.tag, test.result, test.controls)))
			b.Run("Current", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(size)
				for b.Loop() {
					_ = EncodeResultResponse(128, test.tag, test.result, test.controls)
				}
			})
			b.Run("OldPacket", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(size)
				for b.Loop() {
					_ = encodeResultResponseOldPacket(128, test.tag, test.result, test.controls)
				}
			})
		})
	}
}
