package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	ldapControlPreRead  = "1.3.6.1.1.13.1"
	ldapControlPostRead = "1.3.6.1.1.13.2"
)

func (output *ldapSearchLDIFOutput) writeOpenLDAPResponseControls(
	controls []ldapSearchResponseControl,
) error {
	for _, control := range controls {
		if output.level < 2 {
			value := control.oid + " " + strconv.FormatBool(control.critical)
			if control.hasValue && len(control.value) > 0 {
				value += " " + base64.StdEncoding.EncodeToString(control.value)
			}
			if output.level == 0 {
				if err := writeLDIFAttribute(output.writer, "control", []byte(value)); err != nil {
					return err
				}
			} else if err := writeCommentLDIFAttribute(
				output.writer,
				"control",
				[]byte(value),
				false,
			); err != nil {
				return err
			}
		}
		if err := output.writeKnownResponseControl(control); err != nil {
			return err
		}
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeKnownResponseControl(
	control ldapSearchResponseControl,
) error {
	if !control.hasValue {
		return nil
	}
	switch control.oid {
	case ldap.ControlTypePaging:
		return output.writePagedResultsControl(control.value)
	case ldap.ControlTypeServerSideSortingResult:
		return output.writeSortResultControl(control.value)
	case ldap.ControlTypeVLVResponse:
		return output.writeVLVResultControl(control.value)
	case ldap.ControlTypeBeheraPasswordPolicy:
		return output.writePasswordPolicyControl(control.value)
	case ldapControlPreRead:
		return output.writeReadEntryControl("preread", control.value)
	case ldapControlPostRead:
		return output.writeReadEntryControl("postread", control.value)
	case ldap.ControlTypeSyncState:
		return output.writeSyncStateControl(control.value)
	case ldap.ControlTypeSyncDone:
		return output.writeSyncDoneControl(control.value)
	default:
		return nil
	}
}

func (output *ldapSearchLDIFOutput) writeControlExplanation(name, value string) error {
	if output.level == 0 {
		return writeLDIFAttribute(output.writer, name, []byte(value))
	}
	return writeCommentLDIFAttribute(output.writer, name, []byte(value), false)
}

func (output *ldapSearchLDIFOutput) writePagedResultsControl(value []byte) error {
	estimate, cookie, err := ldapwire.DecodePagedResultsValue(value)
	if err != nil {
		return nil
	}
	var explanation strings.Builder
	if estimate > 0 {
		fmt.Fprintf(&explanation, "estimate=%d ", estimate)
	}
	explanation.WriteString("cookie=")
	if len(cookie) > 0 {
		explanation.WriteString(base64.StdEncoding.EncodeToString(cookie))
	}
	return output.writeControlExplanation("pagedresults", explanation.String())
}

func (output *ldapSearchLDIFOutput) writeSortResultControl(value []byte) error {
	result, attribute, err := ldapwire.DecodeSortResultValue(value)
	if err != nil {
		return nil
	}
	explanation := fmt.Sprintf("(%d) %s", result, openLDAPControlResultText(result))
	if attribute != "" {
		explanation += " " + attribute
	}
	return output.writeControlExplanation("sortResult", explanation)
}

func (output *ldapSearchLDIFOutput) writeVLVResultControl(value []byte) error {
	response, err := ldapwire.DecodeVirtualListViewResponseValue(value)
	if err != nil {
		return nil
	}
	contextID := ""
	if response.HasContextID && len(response.ContextID) > 0 {
		contextID = base64.StdEncoding.EncodeToString(response.ContextID)
	}
	explanation := fmt.Sprintf(
		"pos=%d count=%d context=%s (%d) %s",
		response.TargetPosition,
		response.ContentCount,
		contextID,
		response.Result,
		openLDAPControlResultText(response.Result),
	)
	return output.writeControlExplanation("vlvResult", explanation)
}

func openLDAPControlResultText(code ldapwire.ResultCode) string {
	if value, ok := map[ldapwire.ResultCode]string{
		0:  "Success",
		1:  "Operations error",
		2:  "Protocol error",
		3:  "Time limit exceeded",
		4:  "Size limit exceeded",
		8:  "Strong(er) authentication required",
		11: "Administrative limit exceeded",
		12: "Critical extension is unavailable",
		16: "No such attribute",
		18: "Inappropriate matching",
		50: "Insufficient access",
		51: "Server is busy",
		52: "Server is unavailable",
		53: "Server is unwilling to perform",
		76: "Virtual List View error",
		80: "Other (e.g., implementation specific) error",
	}[code]; ok {
		return value
	}
	return "Unknown error"
}

type ldapPasswordPolicyResponse struct {
	expire   int64
	grace    int64
	error    int64
	hasError bool
}

func (output *ldapSearchLDIFOutput) writePasswordPolicyControl(value []byte) error {
	response, err := decodeLDAPPasswordPolicyResponse(value)
	if err != nil {
		return nil
	}
	parts := make([]string, 0, 3)
	if response.expire >= 0 {
		parts = append(parts, fmt.Sprintf("expire=%d", response.expire))
	}
	if response.grace >= 0 {
		parts = append(parts, fmt.Sprintf("grace=%d", response.grace))
	}
	if response.hasError {
		parts = append(parts, fmt.Sprintf(
			"error=%d (%s)",
			response.error,
			openLDAPPasswordPolicyErrorText(response.error),
		))
	}
	return output.writeControlExplanation("ppolicy", strings.Join(parts, " "))
}

func decodeLDAPPasswordPolicyResponse(value []byte) (ldapPasswordPolicyResponse, error) {
	packet, err := decodeLDAPControlBER(value)
	if err != nil || packet.ClassType != ber.ClassUniversal ||
		packet.Tag != ber.TagSequence || packet.TagType != ber.TypeConstructed ||
		len(packet.Children) > 2 {
		return ldapPasswordPolicyResponse{}, fmt.Errorf("malformed password policy response")
	}
	response := ldapPasswordPolicyResponse{expire: -1, grace: -1}
	position := 0
	if position < len(packet.Children) && packet.Children[position].ClassType == ber.ClassContext &&
		packet.Children[position].TagType == ber.TypeConstructed &&
		packet.Children[position].Tag == 0 {
		warning := packet.Children[position]
		if len(warning.Children) != 1 || warning.Children[0].ClassType != ber.ClassContext ||
			warning.Children[0].TagType != ber.TypePrimitive ||
			(warning.Children[0].Tag != 0 && warning.Children[0].Tag != 1) {
			return ldapPasswordPolicyResponse{}, fmt.Errorf("malformed password policy warning")
		}
		warningValue, parseErr := parseLDAPControlInteger(warning.Children[0])
		if parseErr != nil || warningValue < 0 {
			return ldapPasswordPolicyResponse{}, fmt.Errorf("malformed password policy warning value")
		}
		if warning.Children[0].Tag == 0 {
			response.expire = warningValue
		} else {
			response.grace = warningValue
		}
		position++
	}
	if position < len(packet.Children) {
		errorPacket := packet.Children[position]
		if errorPacket.ClassType != ber.ClassContext ||
			errorPacket.TagType != ber.TypePrimitive || errorPacket.Tag != 1 {
			return ldapPasswordPolicyResponse{}, fmt.Errorf("malformed password policy error")
		}
		response.error, err = parseLDAPControlInteger(errorPacket)
		if err != nil || response.error < 0 || response.error > 9 {
			return ldapPasswordPolicyResponse{}, fmt.Errorf("malformed password policy error value")
		}
		response.hasError = true
		position++
	}
	if position != len(packet.Children) {
		return ldapPasswordPolicyResponse{}, fmt.Errorf("malformed password policy fields")
	}
	return response, nil
}

func openLDAPPasswordPolicyErrorText(code int64) string {
	if value, ok := map[int64]string{
		0: "Password expired",
		1: "Account locked",
		2: "Password must be changed",
		3: "Policy prevents password modification",
		4: "Policy requires old password in order to change password",
		5: "Password fails quality checks",
		6: "Password is too short for policy",
		7: "Password has been changed too recently",
		8: "New password is in list of old passwords",
		9: "Password is too long for policy",
	}[code]; ok {
		return value
	}
	return "Unknown error code"
}

type ldapReadControlEntry struct {
	dn         []byte
	attributes []ldapReadControlAttribute
}

type ldapReadControlAttribute struct {
	description string
	values      [][]byte
}

func (output *ldapSearchLDIFOutput) writeReadEntryControl(kind string, value []byte) error {
	entry, err := decodeLDAPReadControlEntry(value)
	if err != nil {
		return nil
	}
	if err := writeFoldedLDIFLine(output.writer, []byte("# ==> "+kind)); err != nil {
		return err
	}
	if err := writeLDIFAttribute(output.writer, "dn", entry.dn); err != nil {
		return err
	}
	for _, attribute := range entry.attributes {
		for _, attributeValue := range attribute.values {
			if output.level == 0 {
				if err := writeLDIFAttribute(output.writer, attribute.description, attributeValue); err != nil {
					return err
				}
				continue
			}
			if err := writeCommentLDIFAttribute(
				output.writer,
				attribute.description,
				attributeValue,
				ldifValueRequiresBase64(attributeValue),
			); err != nil {
				return err
			}
		}
	}
	return writeFoldedLDIFLine(output.writer, []byte("# <== "+kind))
}

func decodeLDAPReadControlEntry(value []byte) (ldapReadControlEntry, error) {
	packet, err := decodeLDAPControlBER(value)
	if err != nil || packet.ClassType != ber.ClassApplication ||
		packet.TagType != ber.TypeConstructed || packet.Tag != ldap.ApplicationSearchResultEntry ||
		len(packet.Children) != 2 {
		return ldapReadControlEntry{}, fmt.Errorf("malformed read control entry")
	}
	dn, err := ldapControlOctetString(packet.Children[0])
	if err != nil {
		return ldapReadControlEntry{}, err
	}
	attributeList := packet.Children[1]
	if attributeList.ClassType != ber.ClassUniversal ||
		attributeList.TagType != ber.TypeConstructed || attributeList.Tag != ber.TagSequence {
		return ldapReadControlEntry{}, fmt.Errorf("malformed read control attributes")
	}
	entry := ldapReadControlEntry{dn: dn, attributes: make([]ldapReadControlAttribute, 0, len(attributeList.Children))}
	for _, encoded := range attributeList.Children {
		if encoded.ClassType != ber.ClassUniversal || encoded.TagType != ber.TypeConstructed ||
			encoded.Tag != ber.TagSequence || len(encoded.Children) != 2 {
			return ldapReadControlEntry{}, fmt.Errorf("malformed read control attribute")
		}
		description, err := ldapControlOctetString(encoded.Children[0])
		if err != nil || !validLDIFAttributeDescription(string(description)) {
			return ldapReadControlEntry{}, fmt.Errorf("malformed read control attribute description")
		}
		set := encoded.Children[1]
		if set.ClassType != ber.ClassUniversal || set.TagType != ber.TypeConstructed ||
			set.Tag != ber.TagSet {
			return ldapReadControlEntry{}, fmt.Errorf("malformed read control values")
		}
		attribute := ldapReadControlAttribute{description: string(description)}
		for _, encodedValue := range set.Children {
			decoded, err := ldapControlOctetString(encodedValue)
			if err != nil {
				return ldapReadControlEntry{}, err
			}
			attribute.values = append(attribute.values, decoded)
		}
		entry.attributes = append(entry.attributes, attribute)
	}
	return entry, nil
}

func (output *ldapSearchLDIFOutput) writeSyncStateControl(value []byte) error {
	if output.level != 0 {
		return nil
	}
	state, err := ldapwire.DecodeSyncStateValue(value)
	if err != nil {
		return nil
	}
	verb := map[ldapwire.SyncState]string{
		ldapwire.SyncStatePresent: "present",
		ldapwire.SyncStateAdd:     "added",
		ldapwire.SyncStateModify:  "modified",
		ldapwire.SyncStateDelete:  "deleted",
	}[state.State]
	if _, err := fmt.Fprintf(
		output.writer,
		"# SyncState control, UUID %s %s\n",
		formatLDAPSyncUUID(state.EntryUUID),
		verb,
	); err != nil {
		return err
	}
	if state.HasCookie {
		return writeLDAPSyncCookie(output.writer, state.Cookie)
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeSyncDoneControl(value []byte) error {
	if output.level != 0 {
		return nil
	}
	done, err := ldapwire.DecodeSyncDoneValue(value)
	if err != nil {
		return nil
	}
	refreshDeletes := 0
	if done.RefreshDeletes {
		refreshDeletes = 1
	}
	if _, err := fmt.Fprintf(
		output.writer,
		"# SyncDone control refreshDeletes=%d\n",
		refreshDeletes,
	); err != nil {
		return err
	}
	if done.HasCookie {
		return writeLDAPSyncCookie(output.writer, done.Cookie)
	}
	return nil
}

func (output *ldapSearchLDIFOutput) writeSyncInfoIntermediate(
	response ldapSearchWireResponse,
) error {
	switch {
	case output.level >= 2:
		return nil
	case output.level == 1:
		_, err := io.WriteString(output.writer, "# SyncInfo Received\n")
		return err
	}
	if _, err := io.WriteString(output.writer, "# SyncInfo Received: "); err != nil {
		return err
	}
	if !response.hasIntermediateData {
		_, err := io.WriteString(output.writer, "empty SyncInfoValue\nSyncInfoValue unknown\n")
		return err
	}
	info, err := ldapwire.DecodeSyncInfoValue(response.intermediateData)
	if err != nil {
		_, writeErr := io.WriteString(output.writer, "SyncInfoValue unknown\n")
		return writeErr
	}
	switch info.Kind {
	case ldapwire.SyncInfoNewCookie:
		if _, err := io.WriteString(output.writer, "new cookie\n"); err != nil {
			return err
		}
		return writeLDAPSyncCookie(output.writer, info.Cookie)
	case ldapwire.SyncInfoRefreshDelete, ldapwire.SyncInfoRefreshPresent:
		label := "refresh delete\n"
		if info.Kind == ldapwire.SyncInfoRefreshPresent {
			label = "refresh present\n"
		}
		if _, err := io.WriteString(output.writer, label); err != nil {
			return err
		}
		if info.HasCookie {
			if err := writeLDAPSyncCookie(output.writer, info.Cookie); err != nil {
				return err
			}
		}
		if info.RefreshDone {
			_, err := io.WriteString(output.writer, "# refresh done, switching to persist stage\n")
			return err
		}
		return nil
	case ldapwire.SyncInfoIDSet:
		if _, err := io.WriteString(output.writer, "ID Set\n"); err != nil {
			return err
		}
		if info.HasCookie {
			if err := writeLDAPSyncCookie(output.writer, info.Cookie); err != nil {
				return err
			}
		}
		if info.RefreshDeletes {
			if _, err := io.WriteString(
				output.writer,
				"# following UUIDs no longer match the search\n",
			); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(output.writer, "# syncUUIDs:\n"); err != nil {
			return err
		}
		for _, uuid := range info.UUIDs {
			if _, err := fmt.Fprintf(output.writer, "#\t%s\n", formatLDAPSyncUUID(uuid)); err != nil {
				return err
			}
		}
		return nil
	default:
		_, err := io.WriteString(output.writer, "SyncInfoValue unknown\n")
		return err
	}
}

func writeLDAPSyncCookie(writer io.Writer, cookie []byte) error {
	return writeCommentLDIFAttribute(
		writer,
		"cookie",
		func() []byte {
			if ldifValueRequiresBase64(cookie) {
				encoded := make([]byte, base64.StdEncoding.EncodedLen(len(cookie)))
				base64.StdEncoding.Encode(encoded, cookie)
				return encoded
			}
			return cookie
		}(),
		ldifValueRequiresBase64(cookie),
	)
}

func formatLDAPSyncUUID(value ldapwire.SyncUUID) string {
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	)
}

func decodeLDAPControlBER(value []byte) (*ber.Packet, error) {
	reader := bytes.NewReader(value)
	packet, err := ber.ReadPacket(reader)
	if err != nil || reader.Len() != 0 {
		return nil, fmt.Errorf("malformed BER control value")
	}
	return packet, nil
}

func ldapControlOctetString(packet *ber.Packet) ([]byte, error) {
	if packet == nil || packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypePrimitive || packet.Tag != ber.TagOctetString {
		return nil, fmt.Errorf("expected an octet string")
	}
	return append([]byte(nil), packet.Data.Bytes()...), nil
}

func parseLDAPControlInteger(packet *ber.Packet) (int64, error) {
	if packet == nil || packet.Data == nil || packet.Data.Len() == 0 {
		return 0, fmt.Errorf("expected an integer")
	}
	return ber.ParseInt64(packet.Data.Bytes())
}
