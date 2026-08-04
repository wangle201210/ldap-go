package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

const maxLDAPControlValueSize = 8 << 20

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
				oid:      control.oid,
				critical: control.critical,
				value:    append([]byte(nil), control.value...),
				hasValue: control.hasValue,
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
