package server

import (
	"bytes"
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const (
	metaProxyLocalBase   = "dc=meta,dc=test"
	metaProxyRemoteBase  = "dc=example,dc=com"
	metaProxyLocalAlice  = "uid=alice,ou=people,dc=meta,dc=test"
	metaProxyRemoteAlice = "uid=alice,ou=people,dc=example,dc=com"
	metaProxyLocalBob    = "uid=bob,ou=people,dc=meta,dc=test"
	metaProxyRemoteBob   = "uid=bob,ou=people,dc=example,dc=com"
	metaProxyLocalGroup  = "cn=staff,ou=groups,dc=meta,dc=test"
	metaProxyRemoteGroup = "cn=staff,ou=groups,dc=example,dc=com"
)

func TestMetaProxyMapsDroppedSearchAttributesAndFilters(t *testing.T) {
	mapping := &rwmRuntimeConfiguration{
		attributesToRemote: make(map[string]string),
		attributesToLocal:  make(map[string]string),
		classesToRemote:    make(map[string]string),
		classesToLocal:     make(map[string]string),
	}
	if err := applyRWMMapDirective(mapping, []string{"attribute", "*"}); err != nil {
		t.Fatalf("configure attribute *: %v", err)
	}
	message := ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN: metaProxyLocalBase,
			Scope:  directory.ScopeWholeSubtree,
			Filter: directory.Filter{
				Kind:      directory.FilterEquality,
				Attribute: "description",
				Assertion: []byte("provider-map"),
			},
			Attributes: []string{"uid", "cn"},
		},
	}
	mappedMessage, err := mapMetaRequestToRemote(mapping, message)
	if err != nil {
		t.Fatalf("map Search with dropped names: %v", err)
	}
	mapped := mappedMessage.Request.(ldapwire.SearchRequest)
	if want := []string{"1.1"}; !reflect.DeepEqual(mapped.Attributes, want) {
		t.Fatalf("mapped attributes = %#v, want %#v", mapped.Attributes, want)
	}
	wantFilter := directory.Filter{
		Kind: directory.FilterNot,
		Children: []directory.Filter{{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		}},
	}
	if !reflect.DeepEqual(mapped.Filter, wantFilter) {
		t.Fatalf("mapped filter = %#v, want computed false %#v", mapped.Filter, wantFilter)
	}
}

func TestMetaProxyMapsSearchRequestToRemote(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	controlValue := []byte{0x01, 0x02, 0x03}
	message := ldapwire.Message{
		ID: 17,
		Request: ldapwire.SearchRequest{
			BaseDN:       "ou=groups," + metaProxyLocalBase,
			Scope:        directory.ScopeWholeSubtree,
			DerefAliases: ldapwire.DerefAlways,
			SizeLimit:    25,
			TimeLimit:    4,
			TypesOnly:    true,
			Filter: directory.Filter{
				Kind: directory.FilterAnd,
				Children: []directory.Filter{
					{
						Kind:      directory.FilterEquality,
						Attribute: "member",
						Assertion: []byte(metaProxyLocalAlice),
					},
					{
						Kind: directory.FilterOr,
						Children: []directory.Filter{
							{
								Kind:      directory.FilterEquality,
								Attribute: "objectClass",
								Assertion: []byte("groupOfNames"),
							},
						},
					},
				},
			},
			Attributes: []string{"member;binary", "objectClass", "*", "+", "1.1"},
		},
		Controls: []ldapwire.Control{{
			OID:      "1.2.3.4",
			Critical: true,
			Value:    controlValue,
			HasValue: true,
		}},
	}

	mappedMessage, err := mapMetaRequestToRemote(mapping, message)
	if err != nil {
		t.Fatalf("mapMetaRequestToRemote(Search): %v", err)
	}
	mapped, ok := mappedMessage.Request.(ldapwire.SearchRequest)
	if !ok {
		t.Fatalf("mapped request type = %T, want ldapwire.SearchRequest", mappedMessage.Request)
	}
	if mapped.BaseDN != "ou=groups,"+metaProxyRemoteBase {
		t.Fatalf("mapped Search base = %q", mapped.BaseDN)
	}
	if mapped.Scope != directory.ScopeWholeSubtree ||
		mapped.DerefAliases != ldapwire.DerefAlways ||
		mapped.SizeLimit != 25 || mapped.TimeLimit != 4 || !mapped.TypesOnly {
		t.Fatalf("non-mapping Search fields changed: %#v", mapped)
	}
	wantFilter := directory.Filter{
		Kind:      directory.FilterAnd,
		Substring: directory.Substring{Any: [][]byte{}},
		Children: []directory.Filter{
			{
				Kind:      directory.FilterEquality,
				Attribute: "uniqueMember",
				Assertion: []byte(metaProxyRemoteAlice),
				Substring: directory.Substring{Any: [][]byte{}},
			},
			{
				Kind:      directory.FilterOr,
				Substring: directory.Substring{Any: [][]byte{}},
				Children: []directory.Filter{
					{
						Kind:      directory.FilterEquality,
						Attribute: "objectClass",
						Assertion: []byte("groupOfUniqueNames"),
						Substring: directory.Substring{Any: [][]byte{}},
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(mapped.Filter, wantFilter) {
		t.Fatalf("mapped Search filter = %#v, want %#v", mapped.Filter, wantFilter)
	}
	wantAttributes := []string{"uniqueMember;binary", "objectClass", "*", "+", "1.1"}
	if !reflect.DeepEqual(mapped.Attributes, wantAttributes) {
		t.Fatalf("mapped Search attributes = %#v, want %#v", mapped.Attributes, wantAttributes)
	}
	if !reflect.DeepEqual(mappedMessage.Controls, message.Controls) {
		t.Fatalf("mapped Search controls = %#v, want %#v", mappedMessage.Controls, message.Controls)
	}
	controlValue[0] = 0xff
	if mappedMessage.Controls[0].Value[0] != 0x01 {
		t.Fatal("mapped Search control aliases the source control value")
	}
}

func TestMetaProxyMapsAddAndModifyRequestsToRemote(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	add := ldapwire.AddRequest{Entry: directory.Entry{
		DN: metaProxyLocalGroup,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: metaProxyTestValues("top", "groupOfNames")},
			{Description: "member;binary", Values: metaProxyTestValues(metaProxyLocalAlice)},
			{Description: "owner", Values: metaProxyTestValues(metaProxyLocalBob)},
			{Description: "ref", Values: metaProxyTestValues("ldap://provider/" + metaProxyLocalAlice)},
			{Description: "cn", Values: metaProxyTestValues("staff")},
		},
	}}

	mappedAddMessage, err := mapMetaRequestToRemote(mapping, ldapwire.Message{ID: 1, Request: add})
	if err != nil {
		t.Fatalf("mapMetaRequestToRemote(Add): %v", err)
	}
	mappedAdd, ok := mappedAddMessage.Request.(ldapwire.AddRequest)
	if !ok {
		t.Fatalf("mapped Add type = %T", mappedAddMessage.Request)
	}
	wantAdd := ldapwire.AddRequest{Entry: directory.Entry{
		DN: metaProxyRemoteGroup,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: metaProxyTestValues("top", "groupOfUniqueNames")},
			{Description: "uniqueMember;binary", Values: metaProxyTestValues(metaProxyRemoteAlice)},
			{Description: "owner", Values: metaProxyTestValues(metaProxyRemoteBob)},
			{Description: "ref", Values: metaProxyTestValues("ldap://provider/" + metaProxyRemoteAlice)},
			{Description: "cn", Values: metaProxyTestValues("staff")},
		},
	}}
	if !reflect.DeepEqual(mappedAdd, wantAdd) {
		t.Fatalf("mapped Add = %#v, want %#v", mappedAdd, wantAdd)
	}

	modify := ldapwire.ModifyRequest{
		DN: metaProxyLocalGroup,
		Changes: []ldapwire.Modification{
			{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "member",
					Values:      metaProxyTestValues(metaProxyLocalAlice, metaProxyLocalBob),
				},
			},
			{
				Operation: ldapwire.ModificationAdd,
				Attribute: directory.Attribute{
					Description: "owner",
					Values:      metaProxyTestValues(metaProxyLocalAlice),
				},
			},
		},
	}
	mappedModifyMessage, err := mapMetaRequestToRemote(mapping, ldapwire.Message{ID: 2, Request: modify})
	if err != nil {
		t.Fatalf("mapMetaRequestToRemote(Modify): %v", err)
	}
	mappedModify, ok := mappedModifyMessage.Request.(ldapwire.ModifyRequest)
	if !ok {
		t.Fatalf("mapped Modify type = %T", mappedModifyMessage.Request)
	}
	wantModify := ldapwire.ModifyRequest{
		DN: metaProxyRemoteGroup,
		Changes: []ldapwire.Modification{
			{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "uniqueMember",
					Values:      metaProxyTestValues(metaProxyRemoteAlice, metaProxyRemoteBob),
				},
			},
			{
				Operation: ldapwire.ModificationAdd,
				Attribute: directory.Attribute{
					Description: "owner",
					Values:      metaProxyTestValues(metaProxyRemoteAlice),
				},
			},
		},
	}
	if !reflect.DeepEqual(mappedModify, wantModify) {
		t.Fatalf("mapped Modify = %#v, want %#v", mappedModify, wantModify)
	}
}

func TestMetaProxyMapsDeleteModifyDNAndCompareRequestsToRemote(t *testing.T) {
	mapping := metaProxyTestMapping(t)

	mappedDeleteMessage, err := mapMetaRequestToRemote(mapping, ldapwire.Message{
		ID:      1,
		Request: ldapwire.DeleteRequest{DN: metaProxyLocalAlice},
	})
	if err != nil {
		t.Fatalf("mapMetaRequestToRemote(Delete): %v", err)
	}
	mappedDelete := mappedDeleteMessage.Request.(ldapwire.DeleteRequest)
	if mappedDelete.DN != metaProxyRemoteAlice {
		t.Fatalf("mapped Delete DN = %q", mappedDelete.DN)
	}

	mappedModifyDNMessage, err := mapMetaRequestToRemote(mapping, ldapwire.Message{
		ID: 2,
		Request: ldapwire.ModifyDNRequest{
			DN:             metaProxyLocalAlice,
			NewRDN:         "uid=renamed",
			DeleteOldRDN:   true,
			NewSuperior:    "ou=archive," + metaProxyLocalBase,
			HasNewSuperior: true,
		},
	})
	if err != nil {
		t.Fatalf("mapMetaRequestToRemote(ModifyDN): %v", err)
	}
	mappedModifyDN := mappedModifyDNMessage.Request.(ldapwire.ModifyDNRequest)
	wantModifyDN := ldapwire.ModifyDNRequest{
		DN:             metaProxyRemoteAlice,
		NewRDN:         "uid=renamed",
		DeleteOldRDN:   true,
		NewSuperior:    "ou=archive," + metaProxyRemoteBase,
		HasNewSuperior: true,
	}
	if !reflect.DeepEqual(mappedModifyDN, wantModifyDN) {
		t.Fatalf("mapped ModifyDN = %#v, want %#v", mappedModifyDN, wantModifyDN)
	}

	assertion := []byte(metaProxyLocalAlice)
	mappedCompareMessage, err := mapMetaRequestToRemote(mapping, ldapwire.Message{
		ID: 3,
		Request: ldapwire.CompareRequest{
			DN:        metaProxyLocalGroup,
			Attribute: "member;binary",
			Assertion: assertion,
		},
	})
	if err != nil {
		t.Fatalf("mapMetaRequestToRemote(Compare): %v", err)
	}
	mappedCompare := mappedCompareMessage.Request.(ldapwire.CompareRequest)
	wantCompare := ldapwire.CompareRequest{
		DN:        metaProxyRemoteGroup,
		Attribute: "uniqueMember;binary",
		Assertion: []byte(metaProxyRemoteAlice),
	}
	if !reflect.DeepEqual(mappedCompare, wantCompare) {
		t.Fatalf("mapped Compare = %#v, want %#v", mappedCompare, wantCompare)
	}
	assertion[0] = 'x'
	if !bytes.Equal(mappedCompare.Assertion, []byte(metaProxyRemoteAlice)) {
		t.Fatal("mapped Compare assertion aliases the source assertion")
	}
}

func TestMetaProxyMapsExtendedRequestDNsToRemote(t *testing.T) {
	mapping := metaProxyTestMapping(t)

	t.Run("DynamicRefresh", func(t *testing.T) {
		message := ldapwire.Message{Request: ldapwire.ExtendedRequest{
			Name:     dynamicRefreshOID,
			Value:    ldapwire.EncodeDynamicRefreshRequestValue(metaProxyLocalAlice, 600),
			HasValue: true,
		}}
		mappedMessage, err := mapMetaRequestToRemote(mapping, message)
		if err != nil {
			t.Fatalf("mapMetaRequestToRemote(DynamicRefresh): %v", err)
		}
		mapped := mappedMessage.Request.(ldapwire.ExtendedRequest)
		decoded, err := ldapwire.DecodeDynamicRefreshRequestValue(mapped.Value, mapped.HasValue)
		if err != nil {
			t.Fatalf("DecodeDynamicRefreshRequestValue(mapped): %v", err)
		}
		if decoded.EntryName != metaProxyRemoteAlice || decoded.RequestTTL != 600 {
			t.Fatalf("mapped DynamicRefresh = %#v", decoded)
		}
	})

	t.Run("PasswordModify", func(t *testing.T) {
		value := encodeChainedPasswordModifyValue(ldapwire.PasswordModifyRequestValue{
			UserIdentity:    []byte(metaProxyLocalAlice),
			OldPassword:     []byte("old-secret"),
			NewPassword:     []byte("new-secret"),
			HasUserIdentity: true,
			HasOldPassword:  true,
			HasNewPassword:  true,
		})
		message := ldapwire.Message{Request: ldapwire.ExtendedRequest{
			Name:     passwordModifyOID,
			Value:    value,
			HasValue: true,
		}}
		mappedMessage, err := mapMetaRequestToRemote(mapping, message)
		if err != nil {
			t.Fatalf("mapMetaRequestToRemote(PasswordModify): %v", err)
		}
		mapped := mappedMessage.Request.(ldapwire.ExtendedRequest)
		decoded, err := ldapwire.DecodePasswordModifyRequestValue(mapped.Value, mapped.HasValue)
		if err != nil {
			t.Fatalf("DecodePasswordModifyRequestValue(mapped): %v", err)
		}
		if string(decoded.UserIdentity) != metaProxyRemoteAlice ||
			string(decoded.OldPassword) != "old-secret" ||
			string(decoded.NewPassword) != "new-secret" ||
			!decoded.HasUserIdentity || !decoded.HasOldPassword || !decoded.HasNewPassword {
			t.Fatalf("mapped PasswordModify = %#v", decoded)
		}
	})
}

func TestMetaProxyMapsSearchResponsesAndResultToLocal(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	controls := []ldapwire.Control{
		{OID: "1.2.840.113556.1.4.319", Value: []byte{0x30, 0x00}, HasValue: true},
		{OID: "1.3.6.1.4.1.4203.1.10.1", Critical: true},
	}
	remoteEntry := directory.Entry{
		DN: metaProxyRemoteGroup,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: metaProxyTestValues("top", "groupOfUniqueNames")},
			{Description: "uniqueMember;binary", Values: metaProxyTestValues(metaProxyRemoteAlice)},
			{Description: "owner", Values: metaProxyTestValues(metaProxyRemoteBob)},
			{Description: "ref", Values: metaProxyTestValues("ldap://provider/" + metaProxyRemoteAlice)},
		},
	}
	remoteReference := "ldap://provider/ou=people," + metaProxyRemoteBase
	remoteResult := ldapwire.Result{
		Code:              ldapwire.ResultNoSuchObject,
		MatchedDN:         "ou=people," + metaProxyRemoteBase,
		DiagnosticMessage: "remote result",
		Referrals:         []string{remoteReference},
	}
	remoteLocalResult := ldapwire.Result{
		Code:              ldapwire.ResultReferral,
		MatchedDN:         metaProxyRemoteGroup,
		DiagnosticMessage: "local fallback",
		Referrals:         []string{"ldap://fallback/" + metaProxyRemoteGroup},
	}
	attempt := chainAttempt{
		packets: []*ber.Packet{
			metaProxyTestPacket(t, ldapwire.EncodeSearchResultEntry(91, remoteEntry, controls)),
			metaProxyTestPacket(t, ldapwire.EncodeSearchResultReference(91, []string{remoteReference}, controls)),
			metaProxyTestPacket(t, ldapwire.EncodeSearchResultDone(91, remoteResult, controls)),
		},
		result:      remoteResult,
		hasResult:   true,
		hasEntries:  true,
		localResult: &remoteLocalResult,
	}

	mapped, err := mapMetaAttemptToLocal(mapping, attempt)
	if err != nil {
		t.Fatalf("mapMetaAttemptToLocal(): %v", err)
	}
	wantResult := ldapwire.Result{
		Code:              ldapwire.ResultNoSuchObject,
		MatchedDN:         "ou=people," + metaProxyLocalBase,
		DiagnosticMessage: "remote result",
		Referrals:         []string{"ldap://provider/ou=people," + metaProxyLocalBase},
	}
	if !reflect.DeepEqual(mapped.result, wantResult) {
		t.Fatalf("mapped attempt result = %#v, want %#v", mapped.result, wantResult)
	}
	wantLocalResult := ldapwire.Result{
		Code:              ldapwire.ResultReferral,
		MatchedDN:         metaProxyLocalGroup,
		DiagnosticMessage: "local fallback",
		Referrals:         []string{"ldap://fallback/" + metaProxyLocalGroup},
	}
	if mapped.localResult == nil || !reflect.DeepEqual(*mapped.localResult, wantLocalResult) {
		t.Fatalf("mapped local result = %#v, want %#v", mapped.localResult, wantLocalResult)
	}

	mappedEntry, err := decodeTranslucentSearchEntry(mapped.packets[0])
	if err != nil {
		t.Fatalf("decode mapped SearchResultEntry: %v", err)
	}
	wantEntry := directory.Entry{
		DN: metaProxyLocalGroup,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: metaProxyTestValues("top", "groupOfNames")},
			{Description: "member;binary", Values: metaProxyTestValues(metaProxyLocalAlice)},
			{Description: "owner", Values: metaProxyTestValues(metaProxyLocalBob)},
			{Description: "ref", Values: metaProxyTestValues("ldap://provider/" + metaProxyLocalAlice)},
		},
	}
	if !reflect.DeepEqual(mappedEntry, wantEntry) {
		t.Fatalf("mapped SearchResultEntry = %#v, want %#v", mappedEntry, wantEntry)
	}
	metaProxyAssertControls(t, mapped.packets[0], controls)

	mappedReferences, err := chainSearchReferences(mapped.packets[1])
	if err != nil {
		t.Fatalf("decode mapped SearchResultReference: %v", err)
	}
	wantReferences := []string{"ldap://provider/ou=people," + metaProxyLocalBase}
	if !reflect.DeepEqual(mappedReferences, wantReferences) {
		t.Fatalf("mapped SearchResultReference = %#v, want %#v", mappedReferences, wantReferences)
	}
	metaProxyAssertControls(t, mapped.packets[1], controls)

	mappedDone, err := chainLDAPResult(
		mapped.packets[2],
		0,
		ldapwire.ApplicationSearchResultDone,
	)
	if err != nil {
		t.Fatalf("decode mapped SearchResultDone: %v", err)
	}
	if !reflect.DeepEqual(mappedDone, wantResult) {
		t.Fatalf("mapped SearchResultDone = %#v, want %#v", mappedDone, wantResult)
	}
	metaProxyAssertControls(t, mapped.packets[2], controls)
}

func TestMapMetaAttemptToLocalReturnsPartialAttemptOnPacketFailure(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	remote := metaProxyTestPacket(t, ldapwire.EncodeSearchResultEntry(
		91,
		directory.Entry{
			DN: metaProxyRemoteAlice,
			Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      metaProxyTestValues("inetOrgPerson"),
			}},
		},
		nil,
	))
	malformed := ber.NewSequence("malformed response")
	attempt := chainAttempt{
		packets:   []*ber.Packet{remote, malformed},
		result:    ldapwire.Result{Code: ldapwire.ResultSuccess},
		hasResult: true,
	}

	mapped, err := mapMetaAttemptToLocal(mapping, attempt)
	if err == nil {
		t.Fatal("mapMetaAttemptToLocal accepted a malformed response")
	}
	if len(mapped.packets) != 2 || mapped.packets[0] == remote ||
		mapped.packets[1] != malformed {
		t.Fatalf("partial mapped attempt = %#v", mapped.packets)
	}
	entry, decodeErr := decodeTranslucentSearchEntry(mapped.packets[0])
	if decodeErr != nil || entry.DN != metaProxyLocalAlice {
		t.Fatalf("partial mapped entry = %#v, %v", entry, decodeErr)
	}
}

func TestMetaProxyMapsEveryFinalResponseToLocal(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	controls := []ldapwire.Control{{
		OID:      "1.2.3.5",
		Critical: true,
		Value:    []byte{0xde, 0xad, 0xbe, 0xef},
		HasValue: true,
	}}
	remote := ldapwire.Result{
		Code:              ldapwire.ResultNoSuchObject,
		MatchedDN:         "ou=people," + metaProxyRemoteBase,
		DiagnosticMessage: "not found",
		Referrals:         []string{"ldap://provider/" + metaProxyRemoteAlice},
	}
	want := ldapwire.Result{
		Code:              ldapwire.ResultNoSuchObject,
		MatchedDN:         "ou=people," + metaProxyLocalBase,
		DiagnosticMessage: "not found",
		Referrals:         []string{"ldap://provider/" + metaProxyLocalAlice},
	}
	tags := []uint64{
		ldapwire.ApplicationBindResponse,
		ldapwire.ApplicationSearchResultDone,
		ldapwire.ApplicationModifyResponse,
		ldapwire.ApplicationAddResponse,
		ldapwire.ApplicationDeleteResponse,
		ldapwire.ApplicationModifyDNResponse,
		ldapwire.ApplicationCompareResponse,
		ldapwire.ApplicationExtendedResponse,
	}
	for _, tag := range tags {
		t.Run(ldapwire.ResultCode(tag).String(), func(t *testing.T) {
			packet := metaProxyTestPacket(t, ldapwire.EncodeResultResponse(37, tag, remote, controls))
			mappedResult, err := mapMetaResult(mapping, remote)
			if err != nil {
				t.Fatalf("mapMetaResult(): %v", err)
			}
			mappedPacket, err := mapMetaResponsePacket(mapping, packet, mappedResult)
			if err != nil {
				t.Fatalf("mapMetaResponsePacket(tag %d): %v", tag, err)
			}
			got, err := chainLDAPResult(mappedPacket, 0, tag)
			if err != nil {
				t.Fatalf("decode mapped final response tag %d: %v", tag, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("mapped final response tag %d = %#v, want %#v", tag, got, want)
			}
			metaProxyAssertControls(t, mappedPacket, controls)
		})
	}
}

func TestMetaProxyPreservesOptionalBindAndExtendedResponseFields(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	remote := ldapwire.Result{
		Code:      ldapwire.ResultNoSuchObject,
		MatchedDN: "ou=people," + metaProxyRemoteBase,
	}
	mappedResult, err := mapMetaResult(mapping, remote)
	if err != nil {
		t.Fatalf("mapMetaResult(): %v", err)
	}
	tests := []struct {
		name          string
		encoded       []byte
		responseTag   uint64
		optionalTag   ber.Tag
		optionalValue []byte
	}{
		{
			name: "Bind server SASL credentials",
			encoded: ldapwire.EncodeSASLBindResponse(
				73,
				remote,
				[]byte{0x00, 0xff, 0x42},
				true,
				nil,
			),
			responseTag:   ldapwire.ApplicationBindResponse,
			optionalTag:   7,
			optionalValue: []byte{0x00, 0xff, 0x42},
		},
		{
			name: "Extended response value",
			encoded: ldapwire.EncodeExtendedResponse(
				73,
				remote,
				passwordModifyOID,
				[]byte{0x30, 0x00},
				nil,
			),
			responseTag:   ldapwire.ApplicationExtendedResponse,
			optionalTag:   11,
			optionalValue: []byte{0x30, 0x00},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := metaProxyTestPacket(t, test.encoded)
			mapped, err := mapMetaResponsePacket(mapping, packet, mappedResult)
			if err != nil {
				t.Fatalf("mapMetaResponsePacket(): %v", err)
			}
			result, err := chainLDAPResult(mapped, 0, test.responseTag)
			if err != nil {
				t.Fatalf("chainLDAPResult(): %v", err)
			}
			if result.MatchedDN != "ou=people,"+metaProxyLocalBase {
				t.Fatalf("mapped matchedDN = %q", result.MatchedDN)
			}
			operation := mapped.Children[1]
			var got []byte
			for _, child := range operation.Children[3:] {
				if child.ClassType == ber.ClassContext && child.Tag == test.optionalTag {
					got = append([]byte(nil), child.Data.Bytes()...)
				}
			}
			if !bytes.Equal(got, test.optionalValue) {
				t.Fatalf("optional response field = %x, want %x", got, test.optionalValue)
			}
		})
	}
}

func TestMetaProxyRejectsInvalidDNs(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	badDN := "uid=broken,"
	tests := []struct {
		name    string
		request ldapwire.Request
	}{
		{name: "Search base", request: ldapwire.SearchRequest{BaseDN: badDN}},
		{name: "Search DN assertion", request: ldapwire.SearchRequest{
			BaseDN: metaProxyLocalBase,
			Filter: directory.Filter{
				Kind:      directory.FilterEquality,
				Attribute: "member",
				Assertion: []byte(badDN),
			},
		}},
		{name: "Add entry DN", request: ldapwire.AddRequest{Entry: directory.Entry{DN: badDN}}},
		{name: "Add DN-valued attribute", request: ldapwire.AddRequest{Entry: directory.Entry{
			DN: metaProxyLocalGroup,
			Attributes: []directory.Attribute{{
				Description: "member",
				Values:      metaProxyTestValues(badDN),
			}},
		}}},
		{name: "Modify DN", request: ldapwire.ModifyRequest{DN: badDN}},
		{name: "Modify DN-valued attribute", request: ldapwire.ModifyRequest{
			DN: metaProxyLocalGroup,
			Changes: []ldapwire.Modification{{
				Operation: ldapwire.ModificationReplace,
				Attribute: directory.Attribute{
					Description: "member",
					Values:      metaProxyTestValues(badDN),
				},
			}},
		}},
		{name: "Delete DN", request: ldapwire.DeleteRequest{DN: badDN}},
		{name: "ModifyDN source", request: ldapwire.ModifyDNRequest{DN: badDN}},
		{name: "ModifyDN newSuperior", request: ldapwire.ModifyDNRequest{
			DN:             metaProxyLocalAlice,
			NewRDN:         "uid=renamed",
			NewSuperior:    badDN,
			HasNewSuperior: true,
		}},
		{name: "Compare DN", request: ldapwire.CompareRequest{DN: badDN}},
		{name: "Compare DN assertion", request: ldapwire.CompareRequest{
			DN:        metaProxyLocalGroup,
			Attribute: "member",
			Assertion: []byte(badDN),
		}},
		{name: "DynamicRefresh DN", request: ldapwire.ExtendedRequest{
			Name:     dynamicRefreshOID,
			Value:    ldapwire.EncodeDynamicRefreshRequestValue(badDN, 60),
			HasValue: true,
		}},
		{name: "PasswordModify DN", request: ldapwire.ExtendedRequest{
			Name: passwordModifyOID,
			Value: encodeChainedPasswordModifyValue(ldapwire.PasswordModifyRequestValue{
				UserIdentity:    []byte(badDN),
				HasUserIdentity: true,
			}),
			HasValue: true,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := mapMetaRequestToRemote(mapping, ldapwire.Message{Request: test.request}); err == nil {
				t.Fatalf("mapMetaRequestToRemote(%s) accepted invalid DN", test.name)
			}
		})
	}

	if _, err := mapMetaResult(mapping, ldapwire.Result{MatchedDN: badDN}); err == nil {
		t.Fatal("mapMetaResult() accepted invalid matchedDN")
	}
	badEntry := metaProxyTestPacket(t, ldapwire.EncodeSearchResultEntry(1, directory.Entry{
		DN: badDN,
	}, nil))
	if _, err := mapMetaResponsePacket(mapping, badEntry, ldapwire.Result{}); err == nil {
		t.Fatal("mapMetaResponsePacket() accepted invalid SearchResultEntry DN")
	}
}

func TestMetaProxyModifyDNStaysInTarget(t *testing.T) {
	mapping := metaProxyTestMapping(t)
	tests := []struct {
		name     string
		request  ldapwire.ModifyDNRequest
		expected bool
	}{
		{
			name:     "same parent",
			request:  ldapwire.ModifyDNRequest{DN: metaProxyLocalAlice},
			expected: true,
		},
		{
			name: "target suffix",
			request: ldapwire.ModifyDNRequest{
				DN:             metaProxyLocalAlice,
				NewSuperior:    metaProxyLocalBase,
				HasNewSuperior: true,
			},
			expected: true,
		},
		{
			name: "descendant of target",
			request: ldapwire.ModifyDNRequest{
				DN:             metaProxyLocalAlice,
				NewSuperior:    "ou=archive," + metaProxyLocalBase,
				HasNewSuperior: true,
			},
			expected: true,
		},
		{
			name: "different target",
			request: ldapwire.ModifyDNRequest{
				DN:             metaProxyLocalAlice,
				NewSuperior:    "ou=people,dc=other,dc=test",
				HasNewSuperior: true,
			},
			expected: false,
		},
		{
			name: "remote target namespace",
			request: ldapwire.ModifyDNRequest{
				DN:             metaProxyLocalAlice,
				NewSuperior:    "ou=people," + metaProxyRemoteBase,
				HasNewSuperior: true,
			},
			expected: false,
		},
		{
			name: "invalid newSuperior",
			request: ldapwire.ModifyDNRequest{
				DN:             metaProxyLocalAlice,
				NewSuperior:    "ou=broken,",
				HasNewSuperior: true,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := metaModifyDNStaysInTarget(mapping, test.request); got != test.expected {
				t.Fatalf("metaModifyDNStaysInTarget() = %t, want %t", got, test.expected)
			}
		})
	}
}

func metaProxyTestMapping(t *testing.T) *rwmRuntimeConfiguration {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
	local, err := directory.ParseDN(metaProxyLocalBase)
	if err != nil {
		t.Fatalf("parse local suffix: %v", err)
	}
	remote, err := directory.ParseDN(metaProxyRemoteBase)
	if err != nil {
		t.Fatalf("parse remote suffix: %v", err)
	}
	return &rwmRuntimeConfiguration{
		suffix: &rwmSuffixMapping{
			local:  local,
			remote: remote,
		},
		attributesToRemote: map[string]string{"member": "uniqueMember"},
		attributesToLocal:  map[string]string{"uniquemember": "member"},
		classesToRemote:    map[string]string{"groupofnames": "groupOfUniqueNames"},
		classesToLocal:     map[string]string{"groupofuniquenames": "groupOfNames"},
		schema:             registry,
	}
}

func metaProxyTestValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = []byte(values[index])
	}
	return result
}

func metaProxyTestPacket(t *testing.T, encoded []byte) *ber.Packet {
	t.Helper()
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("decode LDAP packet: %v", err)
	}
	return packet
}

func metaProxyAssertControls(
	t *testing.T,
	packet *ber.Packet,
	want []ldapwire.Control,
) {
	t.Helper()
	got, err := decodePBindResponseControls(packet)
	if err != nil {
		t.Fatalf("decode mapped response controls: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mapped response controls = %#v, want %#v", got, want)
	}
}
