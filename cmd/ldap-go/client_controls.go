package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const maxLDAPControlValueSize = 8 << 20

const (
	ldapAssertionControlOID             = "1.3.6.1.1.12"
	ldapNoOpControlOID                  = "1.3.6.1.4.1.4203.666.5.2"
	ldapRelaxControlOID                 = "1.3.6.1.4.1.4203.666.5.12"
	ldapProxyAuthorizationControlOID    = "2.16.840.1.113730.3.4.18"
	ldapSessionTrackingUsernameFormatID = ldapwire.SessionTrackingControlOID + ".3"
)

type ldapControlValueSyntax uint8

const (
	ldapControlValueOpenLDAPGeneral ldapControlValueSyntax = iota + 1
	ldapControlValueLDIF
)

// ldapRawControl preserves the distinction between an omitted control value and
// an explicitly supplied empty OCTET STRING, which ldap.ControlString cannot.
type ldapRawControl struct {
	oid      string
	critical bool
	value    []byte
	hasValue bool
	// OpenLDAP adds named ppolicy and sessiontracking controls to Bind too.
	bindRequest bool
	// The session identifier must be resolved from SASL or simple-bind options.
	sessionTrackingDefault bool
}

func (control *ldapRawControl) GetControlType() string {
	return control.oid
}

func (control *ldapRawControl) Encode() *ber.Packet {
	packet := ber.NewSequence("Control")
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		control.oid,
		"Control Type",
	))
	if control.critical {
		packet.AppendChild(ber.NewBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"Criticality",
		))
	}
	if control.hasValue {
		value := ber.Encode(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			nil,
			"Control Value",
		)
		_, _ = value.Data.Write(control.value)
		packet.AppendChild(value)
	}
	return packet
}

func (control *ldapRawControl) String() string {
	return fmt.Sprintf(
		"Control Type: %q Criticality: %t Has Value: %t Value Length: %d",
		control.oid,
		control.critical,
		control.hasValue,
		len(control.value),
	)
}

func (control *ldapRawControl) clear() {
	clear(control.value)
	control.value = nil
}

// parseLDAPGeneralControlSpecs accepts OpenLDAP's named -e controls as well as
// the numeric OID form accepted by parseLDAPControlSpec.
func parseLDAPGeneralControlSpecs(specs []string) ([]ldap.Control, error) {
	controls := make([]ldap.Control, 0, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		control, named, err := parseLDAPNamedGeneralControlSpec(spec)
		if err == nil && !named {
			control, err = parseLDAPControlSpec(spec, ldapControlValueOpenLDAPGeneral)
		}
		if err != nil {
			clearLDAPControls(controls)
			return nil, err
		}
		if _, duplicate := seen[control.oid]; duplicate {
			control.clear()
			clearLDAPControls(controls)
			return nil, fmt.Errorf("LDAP control %s was provided more than once", control.oid)
		}
		seen[control.oid] = struct{}{}
		controls = append(controls, control)
	}
	return controls, nil
}

func parseLDAPNamedGeneralControlSpec(spec string) (*ldapRawControl, bool, error) {
	criticality := 0
	remainder := spec
	for strings.HasPrefix(remainder, "!") {
		criticality++
		remainder = remainder[1:]
	}
	name, parameter, hasParameter := strings.Cut(remainder, "=")
	critical := criticality > 0

	control := &ldapRawControl{}
	switch strings.ToLower(name) {
	case "assert":
		if !hasParameter {
			return nil, true, errors.New("assert: control value expected")
		}
		filter, err := ldap.CompileFilter(parameter)
		if err != nil {
			return nil, true, fmt.Errorf("assert: invalid LDAP filter: %w", err)
		}
		control.oid = ldapAssertionControlOID
		control.critical = critical
		control.value = filter.Bytes()
		control.hasValue = true

	case "authzid":
		if !hasParameter {
			return nil, true, errors.New("authzid: control value expected")
		}
		if criticality == 0 {
			return nil, true, errors.New("authzid: must be marked critical")
		}
		control.oid = ldapProxyAuthorizationControlOID
		control.critical = criticality == 1
		control.value = []byte(parameter)
		control.hasValue = true

	case "managedsait":
		if hasParameter {
			return nil, true, errors.New("manageDSAit: no control value expected")
		}
		control.oid = ldap.ControlTypeManageDsaIT
		control.critical = critical

	case "noop":
		if hasParameter {
			return nil, true, errors.New("noop: no control value expected")
		}
		control.oid = ldapNoOpControlOID
		control.critical = critical

	case "ppolicy":
		if hasParameter {
			return nil, true, errors.New("ppolicy: no control value expected")
		}
		if criticality != 0 {
			return nil, true, errors.New("ppolicy: critical flag not allowed")
		}
		control.oid = ldap.ControlTypeBeheraPasswordPolicy
		control.bindRequest = true

	case "preread", "postread":
		if strings.EqualFold(name, "preread") {
			control.oid = ldapControlPreRead
		} else {
			control.oid = ldapControlPostRead
		}
		control.critical = critical
		control.value = encodeLDAPReadAttributeSelection(parameter, hasParameter)
		control.hasValue = true

	case "relax", "managedit":
		if hasParameter {
			return nil, true, errors.New("relax: no control value expected")
		}
		control.oid = ldapRelaxControlOID
		control.critical = critical

	case "sessiontracking":
		if criticality != 0 {
			return nil, true, errors.New("sessiontracking: critical flag not allowed")
		}
		sourceIP, sourceName := ldapSessionTrackingSource()
		identifier := ""
		if hasParameter {
			identifier = parameter
		}
		control.oid = ldapwire.SessionTrackingControlOID
		control.value = ldapwire.EncodeSessionTrackingValue(ldapwire.SessionTrackingValue{
			SessionSourceIP:           []byte(sourceIP),
			SessionSourceName:         []byte(sourceName),
			FormatOID:                 []byte(ldapSessionTrackingUsernameFormatID),
			SessionTrackingIdentifier: []byte(identifier),
		})
		control.hasValue = true
		control.bindRequest = true
		control.sessionTrackingDefault = !hasParameter

	default:
		return nil, false, nil
	}

	if len(control.value) > maxLDAPControlValueSize {
		control.clear()
		return nil, true, fmt.Errorf(
			"LDAP control %s value exceeds %d bytes",
			control.oid,
			maxLDAPControlValueSize,
		)
	}
	return control, true, nil
}

func encodeLDAPReadAttributeSelection(parameter string, hasParameter bool) []byte {
	sequence := ber.NewSequence("AttributeSelection")
	if hasParameter {
		for _, attribute := range strings.FieldsFunc(parameter, func(character rune) bool {
			return character == ','
		}) {
			sequence.AppendChild(ber.NewString(
				ber.ClassUniversal,
				ber.TypePrimitive,
				ber.TagOctetString,
				attribute,
				"AttributeDescription",
			))
		}
	}
	return sequence.Bytes()
}

func ldapSessionTrackingSource() (ip, name string) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", ""
	}
	addresses, err := net.LookupIP(hostname)
	if err != nil {
		return "", hostname
	}
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			return ipv4.String(), hostname
		}
	}
	return "", hostname
}

func resolveLDAPSessionTrackingDefaults(
	controls []ldap.Control,
	identifier string,
) error {
	for _, generic := range controls {
		control, ok := generic.(*ldapRawControl)
		if !ok || !control.sessionTrackingDefault {
			continue
		}
		value, validFormatOID, err := ldapwire.DecodeSessionTrackingValue(control.value)
		if err != nil {
			return fmt.Errorf("decode generated sessiontracking control: %w", err)
		}
		if !validFormatOID {
			return errors.New("generated sessiontracking control has an invalid format OID")
		}
		value.SessionTrackingIdentifier = []byte(identifier)
		encoded := ldapwire.EncodeSessionTrackingValue(value)
		if len(encoded) > maxLDAPControlValueSize {
			clear(encoded)
			return fmt.Errorf(
				"LDAP control %s value exceeds %d bytes",
				control.oid,
				maxLDAPControlValueSize,
			)
		}
		clear(control.value)
		control.value = encoded
	}
	return nil
}

func ldapBindRequestControls(controls []ldap.Control) []ldap.Control {
	selected := make([]ldap.Control, 0, 2)
	for _, generic := range controls {
		control, ok := generic.(*ldapRawControl)
		if ok && control.bindRequest {
			selected = append(selected, control)
		}
	}
	return selected
}

func ldapRawControlsToWire(controls []ldap.Control) ([]ldapwire.Control, error) {
	wireControls := make([]ldapwire.Control, 0, len(controls))
	for _, generic := range controls {
		control, ok := generic.(*ldapRawControl)
		if !ok {
			return nil, fmt.Errorf(
				"cannot encode LDAP control %s of type %T",
				generic.GetControlType(),
				generic,
			)
		}
		wireControls = append(wireControls, ldapwire.Control{
			OID:      control.oid,
			Critical: control.critical,
			Value:    control.value,
			HasValue: control.hasValue,
		})
	}
	return wireControls, nil
}

func parseLDAPControlSpecs(
	specs []string,
	syntax ldapControlValueSyntax,
) ([]ldap.Control, error) {
	controls := make([]ldap.Control, 0, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		control, err := parseLDAPControlSpec(spec, syntax)
		if err != nil {
			clearLDAPControls(controls)
			return nil, err
		}
		if _, duplicate := seen[control.oid]; duplicate {
			control.clear()
			clearLDAPControls(controls)
			return nil, fmt.Errorf("LDAP control %s was provided more than once", control.oid)
		}
		seen[control.oid] = struct{}{}
		controls = append(controls, control)
	}
	return controls, nil
}

func parseLDAPControlSpec(
	spec string,
	syntax ldapControlValueSyntax,
) (*ldapRawControl, error) {
	if spec == "" {
		return nil, errors.New("LDAP control specification must not be empty")
	}
	critical := false
	for strings.HasPrefix(spec, "!") {
		critical = true
		spec = spec[1:]
	}
	oid, encodedValue, hasValue := strings.Cut(spec, "=")
	if !validLDAPOperationOID(oid) {
		return nil, fmt.Errorf("invalid LDAP control OID %q", oid)
	}
	control := &ldapRawControl{oid: oid, critical: critical, hasValue: hasValue}
	if !hasValue {
		return control, nil
	}

	value, err := parseLDAPControlValue(encodedValue, oid, syntax)
	if err != nil {
		return nil, err
	}
	control.value = value
	return control, nil
}

func parseLDAPControlValue(
	encodedValue, oid string,
	syntax ldapControlValueSyntax,
) ([]byte, error) {
	switch {
	case strings.HasPrefix(encodedValue, "::"):
		return decodeLDAPControlBase64(encodedValue[2:], oid)
	case strings.HasPrefix(encodedValue, ":<"):
		return readLDAPControlValueFile(encodedValue[2:], oid)
	case strings.HasPrefix(encodedValue, ":"):
		value := []byte(encodedValue[1:])
		if len(value) > maxLDAPControlValueSize {
			clear(value)
			return nil, fmt.Errorf(
				"LDAP control %s value exceeds %d bytes",
				oid,
				maxLDAPControlValueSize,
			)
		}
		return value, nil
	case strings.HasPrefix(encodedValue, "<"):
		return readLDAPControlValueFile(encodedValue[1:], oid)
	case syntax == ldapControlValueOpenLDAPGeneral:
		return decodeLDAPControlBase64(encodedValue, oid)
	default:
		return nil, fmt.Errorf(
			"LDAP control %s value must use =:<string>, =::<base64>, or =:<file URI>",
			oid,
		)
	}
}

func decodeLDAPControlBase64(value, oid string) ([]byte, error) {
	if strings.ContainsAny(value, " \t\r\n") {
		return nil, fmt.Errorf("LDAP control %s base64 value contains whitespace", oid)
	}
	if len(value) > base64.StdEncoding.EncodedLen(maxLDAPControlValueSize) {
		return nil, fmt.Errorf(
			"LDAP control %s value exceeds %d decoded bytes",
			oid,
			maxLDAPControlValueSize,
		)
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	length, err := base64.StdEncoding.Strict().Decode(decoded, []byte(value))
	if err != nil {
		clear(decoded)
		return nil, fmt.Errorf("decode LDAP control %s value as base64: %w", oid, err)
	}
	return decoded[:length], nil
}

func readLDAPControlValueFile(reference, oid string) ([]byte, error) {
	if reference == "" {
		return nil, fmt.Errorf("LDAP control %s file reference must not be empty", oid)
	}
	path := reference
	if parsed, err := url.Parse(reference); err != nil {
		return nil, fmt.Errorf("parse LDAP control %s file URI: %w", oid, err)
	} else if parsed.Scheme != "" {
		if !strings.EqualFold(parsed.Scheme, "file") {
			return nil, fmt.Errorf("LDAP control %s value URI must use file://", oid)
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost")) {
			return nil, fmt.Errorf("LDAP control %s value uses an invalid file URI", oid)
		}
		path = parsed.Path
	}
	if path == "" {
		return nil, fmt.Errorf("LDAP control %s file path must not be empty", oid)
	}
	path = filepath.Clean(path)
	value, err := readLimitedClientFile(path, maxLDAPControlValueSize, "LDAP control value file")
	if err != nil {
		return nil, fmt.Errorf("LDAP control %s: %w", oid, err)
	}
	return value, nil
}

func mergeLDAPControls(groups ...[]ldap.Control) ([]ldap.Control, error) {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	controls := make([]ldap.Control, 0, total)
	seen := make(map[string]struct{}, total)
	for _, group := range groups {
		for _, control := range group {
			if control == nil {
				return nil, errors.New("nil LDAP control")
			}
			oid := control.GetControlType()
			if _, duplicate := seen[oid]; duplicate {
				return nil, fmt.Errorf("LDAP control %s was provided more than once", oid)
			}
			seen[oid] = struct{}{}
			controls = append(controls, control)
		}
	}
	return controls, nil
}

func cloneLDAPControls(controls []ldap.Control) []ldap.Control {
	cloned := make([]ldap.Control, 0, len(controls))
	for _, control := range controls {
		switch control := control.(type) {
		case *ldapRawControl:
			cloned = append(cloned, &ldapRawControl{
				oid:                    control.oid,
				critical:               control.critical,
				value:                  append([]byte(nil), control.value...),
				hasValue:               control.hasValue,
				bindRequest:            control.bindRequest,
				sessionTrackingDefault: control.sessionTrackingDefault,
			})
		case *ldap.ControlPaging:
			paging := ldap.NewControlPaging(control.PagingSize)
			paging.SetCookie(nil)
			cloned = append(cloned, paging)
		default:
			cloned = append(cloned, control)
		}
	}
	return cloned
}

func clearLDAPControls(controls []ldap.Control) {
	for _, control := range controls {
		if raw, ok := control.(*ldapRawControl); ok {
			raw.clear()
		}
	}
}
