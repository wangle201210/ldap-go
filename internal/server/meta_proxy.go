package server

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func mapMetaRequestToRemote(
	mapping *rwmRuntimeConfiguration,
	message ldapwire.Message,
) (ldapwire.Message, error) {
	message.Controls = cloneLDAPControls(message.Controls)
	switch request := message.Request.(type) {
	case ldapwire.BindRequest:
		name, err := mapMetaDNString(mapping, request.Name, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.Name = name
		request.Authentication.Simple = bytes.Clone(request.Authentication.Simple)
		request.Authentication.SASLCredentials = bytes.Clone(
			request.Authentication.SASLCredentials,
		)
		message.Request = request
	case ldapwire.SearchRequest:
		base, err := mapMetaDNString(mapping, request.BaseDN, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.BaseDN = base
		request.Filter, err = mapMetaFilter(mapping, request.Filter, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		mappedAttributes := make([]string, 0, len(request.Attributes))
		for _, description := range request.Attributes {
			mapped := mapping.mapAttributeDescription(description, true)
			if mapped != "" {
				mappedAttributes = append(mappedAttributes, mapped)
			}
		}
		if len(request.Attributes) != 0 && len(mappedAttributes) == 0 {
			mappedAttributes = append(mappedAttributes, "1.1")
		}
		request.Attributes = mappedAttributes
		message.Request = request
	case ldapwire.AddRequest:
		entry, err := mapping.mapEntryToRemote(request.Entry)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.Entry = entry
		message.Request = request
	case ldapwire.ModifyRequest:
		dn, err := mapMetaDNString(mapping, request.DN, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.DN = dn
		request.Changes = append([]ldapwire.Modification(nil), request.Changes...)
		for index := range request.Changes {
			attribute, err := mapMetaAttribute(
				mapping,
				request.Changes[index].Attribute,
				true,
			)
			if err != nil {
				return ldapwire.Message{}, err
			}
			request.Changes[index].Attribute = attribute
		}
		message.Request = request
	case ldapwire.DeleteRequest:
		dn, err := mapMetaDNString(mapping, request.DN, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.DN = dn
		message.Request = request
	case ldapwire.ModifyDNRequest:
		dn, err := mapMetaDNString(mapping, request.DN, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.DN = dn
		if request.HasNewSuperior {
			request.NewSuperior, err = mapMetaDNString(
				mapping,
				request.NewSuperior,
				true,
			)
			if err != nil {
				return ldapwire.Message{}, err
			}
		}
		message.Request = request
	case ldapwire.CompareRequest:
		dn, err := mapMetaDNString(mapping, request.DN, true)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.DN = dn
		attribute, err := mapMetaAttribute(
			mapping,
			directory.Attribute{
				Description: request.Attribute,
				Values:      [][]byte{request.Assertion},
			},
			true,
		)
		if err != nil {
			return ldapwire.Message{}, err
		}
		request.Attribute = attribute.Description
		if len(attribute.Values) == 1 {
			request.Assertion = bytes.Clone(attribute.Values[0])
		}
		message.Request = request
	case ldapwire.ExtendedRequest:
		mapped, err := mapMetaExtendedRequest(mapping, request)
		if err != nil {
			return ldapwire.Message{}, err
		}
		message.Request = mapped
	}
	return message, nil
}

func mapMetaExtendedRequest(
	mapping *rwmRuntimeConfiguration,
	request ldapwire.ExtendedRequest,
) (ldapwire.ExtendedRequest, error) {
	switch request.Name {
	case passwordModifyOID:
		decoded, err := ldapwire.DecodePasswordModifyRequestValue(
			request.Value,
			request.HasValue,
		)
		if err != nil || !decoded.HasUserIdentity {
			return request, err
		}
		mapped, err := mapMetaDNString(mapping, string(decoded.UserIdentity), true)
		if err != nil {
			return request, err
		}
		decoded.UserIdentity = []byte(mapped)
		request.Value = encodeChainedPasswordModifyValue(decoded)
		request.HasValue = true
	case dynamicRefreshOID:
		decoded, err := ldapwire.DecodeDynamicRefreshRequestValue(
			request.Value,
			request.HasValue,
		)
		if err != nil {
			return request, err
		}
		mapped, err := mapMetaDNString(mapping, decoded.EntryName, true)
		if err != nil {
			return request, err
		}
		decoded.EntryName = mapped
		request.Value = ldapwire.EncodeDynamicRefreshRequestValue(
			decoded.EntryName,
			decoded.RequestTTL,
		)
		request.HasValue = true
	}
	return request, nil
}

func mapMetaDNString(
	mapping *rwmRuntimeConfiguration,
	raw string,
	toRemote bool,
) (string, error) {
	if raw == "" {
		return "", nil
	}
	dn, err := directory.ParseDN(raw)
	if err != nil {
		return "", err
	}
	if toRemote {
		dn, err = mapping.mapDNToRemote(dn)
	} else {
		dn, err = mapping.mapDNToLocal(dn)
	}
	if err != nil {
		return "", err
	}
	return dn.String(), nil
}

func mapMetaAttribute(
	mapping *rwmRuntimeConfiguration,
	attribute directory.Attribute,
	toRemote bool,
) (directory.Attribute, error) {
	entry := directory.Entry{
		DN: "cn=meta-mapping",
		Attributes: []directory.Attribute{{
			Description: attribute.Description,
			Values:      cloneByteValues(attribute.Values),
		}},
	}
	var (
		mapped directory.Entry
		err    error
	)
	if toRemote {
		mapped, err = mapping.mapEntryToRemote(entry)
	} else {
		mapped, err = mapping.mapEntryToLocal(entry)
	}
	if err != nil {
		return directory.Attribute{}, err
	}
	if len(mapped.Attributes) != 1 {
		return directory.Attribute{}, errors.New("meta attribute mapping produced an invalid attribute")
	}
	return mapped.Attributes[0], nil
}

func mapMetaFilter(
	mapping *rwmRuntimeConfiguration,
	filter directory.Filter,
	toRemote bool,
) (directory.Filter, error) {
	filter.Children = append([]directory.Filter(nil), filter.Children...)
	for index := range filter.Children {
		mapped, err := mapMetaFilter(mapping, filter.Children[index], toRemote)
		if err != nil {
			return directory.Filter{}, err
		}
		filter.Children[index] = mapped
	}
	filter.Assertion = bytes.Clone(filter.Assertion)
	filter.Substring.Initial = bytes.Clone(filter.Substring.Initial)
	filter.Substring.Final = bytes.Clone(filter.Substring.Final)
	filter.Substring.Any = cloneByteValues(filter.Substring.Any)
	if filter.Attribute == "" {
		return filter, nil
	}
	mappedDescription := mapping.mapAttributeDescription(filter.Attribute, toRemote)
	if mappedDescription == "" {
		return metaComputedFalseFilter(), nil
	}
	if metaObjectClassDescription(filter.Attribute) ||
		metaObjectClassDescription(mappedDescription) {
		filter.Attribute = mappedDescription
		if len(filter.Assertion) != 0 {
			mapped := mapping.mapObjectClass(string(filter.Assertion), toRemote)
			if mapped != "" {
				filter.Assertion = []byte(mapped)
			}
		}
		return filter, nil
	}
	attribute, err := mapMetaAttribute(
		mapping,
		directory.Attribute{
			Description: filter.Attribute,
			Values:      [][]byte{filter.Assertion},
		},
		toRemote,
	)
	if err != nil {
		return directory.Filter{}, err
	}
	filter.Attribute = attribute.Description
	if len(attribute.Values) == 1 {
		filter.Assertion = bytes.Clone(attribute.Values[0])
	}
	return filter, nil
}

func metaComputedFalseFilter() directory.Filter {
	return directory.Filter{
		Kind: directory.FilterNot,
		Children: []directory.Filter{{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		}},
	}
}

func metaObjectClassDescription(description string) bool {
	switch strings.ToLower(baseAttributeName(description)) {
	case "objectclass", "structuralobjectclass":
		return true
	default:
		return false
	}
}

func mapMetaAttemptToLocal(
	mapping *rwmRuntimeConfiguration,
	attempt chainAttempt,
) (chainAttempt, error) {
	result, err := mapMetaResult(mapping, attempt.result)
	if err != nil {
		return attempt, err
	}
	attempt.result = result
	if attempt.localResult != nil {
		mapped, err := mapMetaResult(mapping, *attempt.localResult)
		if err != nil {
			return attempt, err
		}
		attempt.localResult = &mapped
	}
	for index, packet := range attempt.packets {
		mapped, err := mapMetaResponsePacket(mapping, packet, attempt.result)
		if err != nil {
			return attempt, err
		}
		attempt.packets[index] = mapped
	}
	return attempt, nil
}

func mapMetaResponsePacket(
	mapping *rwmRuntimeConfiguration,
	packet *ber.Packet,
	result ldapwire.Result,
) (*ber.Packet, error) {
	if packet == nil || len(packet.Children) < 2 {
		return nil, errors.New("malformed back-meta response packet")
	}
	tag := uint64(packet.Children[1].Tag)
	var encoded []byte
	switch tag {
	case ldapwire.ApplicationSearchResultEntry:
		controls, err := decodePBindResponseControls(packet)
		if err != nil {
			return nil, err
		}
		entry, err := decodeTranslucentSearchEntry(packet)
		if err != nil {
			return nil, err
		}
		entry, err = mapping.mapEntryToLocal(entry)
		if err != nil {
			return nil, err
		}
		encoded = ldapwire.EncodeSearchResultEntry(0, entry, controls)
	case ldapwire.ApplicationSearchResultReference:
		controls, err := decodePBindResponseControls(packet)
		if err != nil {
			return nil, err
		}
		referrals, err := chainSearchReferences(packet)
		if err != nil {
			return nil, err
		}
		for index := range referrals {
			referrals[index] = string(mapping.mapLDAPURLValue([]byte(referrals[index]), false))
		}
		encoded = ldapwire.EncodeSearchResultReference(0, referrals, controls)
	case ldapwire.ApplicationSearchResultDone,
		ldapwire.ApplicationBindResponse,
		ldapwire.ApplicationModifyResponse,
		ldapwire.ApplicationAddResponse,
		ldapwire.ApplicationDeleteResponse,
		ldapwire.ApplicationModifyDNResponse,
		ldapwire.ApplicationCompareResponse,
		ldapwire.ApplicationExtendedResponse:
		return mapMetaLDAPResultPacket(packet, result)
	default:
		return packet, nil
	}
	mapped, err := ber.DecodePacketErr(encoded)
	if err != nil {
		return nil, fmt.Errorf("encode mapped back-meta response tag %d: %w", tag, err)
	}
	return mapped, nil
}

func mapMetaLDAPResultPacket(
	packet *ber.Packet,
	result ldapwire.Result,
) (*ber.Packet, error) {
	if packet == nil || len(packet.Children) < 2 || len(packet.Children[1].Children) < 3 {
		return nil, errors.New("malformed back-meta LDAP result packet")
	}
	packet.Children[0] = ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		0,
		"messageID",
	)
	operation := packet.Children[1]
	operation.Children[1] = ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		result.MatchedDN,
		"matchedDN",
	)
	for index := 3; index < len(operation.Children); index++ {
		child := operation.Children[index]
		if child.ClassType != ber.ClassContext ||
			child.TagType != ber.TypeConstructed || child.Tag != 3 {
			continue
		}
		referral := ber.Encode(
			ber.ClassContext,
			ber.TypeConstructed,
			3,
			nil,
			"referral",
		)
		for _, uri := range result.Referrals {
			referral.AppendChild(ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				uri,
				"referral URI",
			))
		}
		operation.Children[index] = referral
		break
	}
	return packet, nil
}

func mapMetaResult(
	mapping *rwmRuntimeConfiguration,
	result ldapwire.Result,
) (ldapwire.Result, error) {
	matched, err := mapMetaDNString(mapping, result.MatchedDN, false)
	if err != nil {
		return ldapwire.Result{}, err
	}
	result.MatchedDN = matched
	result.Referrals = append([]string(nil), result.Referrals...)
	for index := range result.Referrals {
		result.Referrals[index] = string(mapping.mapLDAPURLValue(
			[]byte(result.Referrals[index]),
			false,
		))
	}
	return result, nil
}

func metaRequestTargetDN(
	state *connectionState,
	request ldapwire.Request,
) (directory.DN, bool) {
	target, _, _, ok := chainOperationTarget(state, request)
	return target, ok
}

func metaModifyDNStaysInTarget(
	mapping *rwmRuntimeConfiguration,
	request ldapwire.ModifyDNRequest,
) bool {
	if !request.HasNewSuperior || mapping == nil || mapping.suffix == nil {
		return true
	}
	newSuperior, err := directory.ParseDN(request.NewSuperior)
	if err != nil {
		return false
	}
	newSuperior, err = mapping.normalizeDN(newSuperior)
	if err != nil {
		return false
	}
	local, err := mapping.normalizeDN(mapping.suffix.local)
	return err == nil && (local.Equal(newSuperior) || local.AncestorOf(newSuperior))
}

func metaDescriptionIsSpecial(value string) bool {
	return rwmSpecialAttributeDescription(value)
}
