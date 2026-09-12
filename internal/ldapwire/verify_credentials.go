package ldapwire

import (
	"bytes"
	"math"
	"strings"
	"unicode/utf8"
)

const VerifyCredentialsOID = "1.3.6.1.4.1.4203.666.6.5"

const (
	maxVerifyCredentialsValueBytes = min(1<<20, int(DefaultMaxMessageSize))
	maxVerifyCredentialsNameBytes  = 64 << 10
	maxVerifyCredentialsAuthBytes  = 64 << 10
	maxVerifyCredentialsControls   = 64
	maxVerifyCredentialsOIDBytes   = 1024
)

// VerifyCredentialsRequestValue contains the inner VC request. Authentication
// is the same type as BindRequest.Authentication. Cookie validity, DN syntax,
// mechanism support, and control policy belong to the operation handler.
type VerifyCredentialsRequestValue struct {
	Name           string
	Authentication Authentication
	Cookie         []byte
	HasCookie      bool
	Controls       []Control
}

// DecodeVerifyCredentialsRequestValue decodes the format in OpenLDAP 2.6.13
// (d172686d3d270bc961b78f3ff00d7019c8dfb094), libraries/libldap/vc.c and
// contrib/slapd-modules/vc/vc.c. Values are limited to 1 MiB (and never exceed
// DefaultMaxMessageSize); names, credentials, mechanisms, and cookies to 64 KiB;
// controls to 64, with OIDs of at most 1024 bytes.
//
// The existing definite-length TLV reader accepts nonminimal BER lengths and
// returns bounded slices without allocating a recursive ASN.1 tree. Only the
// fixed VC structure is traversed; credential and control values stay opaque.
func DecodeVerifyCredentialsRequestValue(
	value []byte,
	present bool,
) (VerifyCredentialsRequestValue, error) {
	if !present || len(value) == 0 {
		return VerifyCredentialsRequestValue{}, malformed("missing or empty verify credentials request value")
	}
	if len(value) > maxVerifyCredentialsValueBytes {
		return VerifyCredentialsRequestValue{}, malformed("verify credentials request value exceeds size limit")
	}
	outer, trailing, err := readDerefBERElement(value)
	if err != nil || outer.identifier != 0x30 || len(trailing) != 0 {
		return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials request sequence")
	}

	first, remaining, err := readDerefBERElement(outer.content)
	if err != nil {
		return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials request fields")
	}
	var cookie []byte
	hasCookie := first.identifier == 0x80
	if hasCookie {
		if len(first.content) > maxVerifyCredentialsAuthBytes {
			return VerifyCredentialsRequestValue{}, malformed("verify credentials cookie exceeds size limit")
		}
		cookie = first.content
		first, remaining, err = readDerefBERElement(remaining)
		if err != nil {
			return VerifyCredentialsRequestValue{}, malformed("missing verify credentials name")
		}
	}
	if first.identifier != 0x04 || len(first.content) > maxVerifyCredentialsNameBytes ||
		!utf8.Valid(first.content) || bytes.IndexByte(first.content, 0) >= 0 {
		return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials name")
	}
	name := first.content
	auth, remaining, err := readDerefBERElement(remaining)
	if err != nil {
		return VerifyCredentialsRequestValue{}, malformed("missing verify credentials authentication")
	}

	var mechanism, credentials []byte
	var hasSASLCredentials bool
	switch auth.identifier {
	case 0x80:
		if len(auth.content) > maxVerifyCredentialsAuthBytes {
			return VerifyCredentialsRequestValue{}, malformed("verify credentials password exceeds size limit")
		}
		credentials = auth.content
	case 0xa3:
		mech, rest, decodeErr := readDerefBERElement(auth.content)
		if decodeErr != nil || mech.identifier != 0x04 || len(mech.content) == 0 ||
			len(mech.content) > maxVerifyCredentialsAuthBytes ||
			!utf8.Valid(mech.content) || bytes.IndexByte(mech.content, 0) >= 0 {
			return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials SASL mechanism")
		}
		mechanism = mech.content
		if len(rest) != 0 {
			cred, extra, decodeErr := readDerefBERElement(rest)
			if decodeErr != nil || cred.identifier != 0x04 || len(extra) != 0 ||
				len(cred.content) > maxVerifyCredentialsAuthBytes {
				return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials SASL credentials")
			}
			credentials, hasSASLCredentials = cred.content, true
		}
	default:
		return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials authentication choice")
	}

	var controls []Control
	if len(remaining) != 0 {
		wrapper, extra, decodeErr := readDerefBERElement(remaining)
		if decodeErr != nil || wrapper.identifier != 0xa2 || len(extra) != 0 {
			return VerifyCredentialsRequestValue{}, malformed("invalid verify credentials controls wrapper")
		}
		controls, err = decodeVerifyCredentialsControls(wrapper.content)
		if err != nil {
			return VerifyCredentialsRequestValue{}, err
		}
	}

	request := VerifyCredentialsRequestValue{
		Name: string(name), Cookie: bytes.Clone(cookie), HasCookie: hasCookie, Controls: controls,
	}
	if auth.identifier == 0xa3 {
		request.Authentication = Authentication{
			IsSASL: true, SASLMechanism: string(mechanism),
			SASLCredentials: bytes.Clone(credentials), HasSASLCredentials: hasSASLCredentials,
		}
	} else {
		request.Authentication.Simple = bytes.Clone(credentials)
	}
	return request, nil
}

func decodeVerifyCredentialsControls(content []byte) ([]Control, error) {
	controls := make([]Control, 0)
	for len(content) != 0 {
		if len(controls) == maxVerifyCredentialsControls {
			return nil, malformed("verify credentials controls exceed count limit")
		}
		encoded, rest, err := readDerefBERElement(content)
		if err != nil || encoded.identifier != 0x30 {
			return nil, malformed("invalid verify credentials control sequence")
		}
		oid, fields, err := readDerefBERElement(encoded.content)
		if err != nil || oid.identifier != 0x04 || len(oid.content) > maxVerifyCredentialsOIDBytes ||
			!validDerefNumericOID(string(oid.content)) {
			return nil, malformed("invalid verify credentials control OID")
		}
		control := Control{OID: string(oid.content)}
		if len(fields) != 0 && fields[0] == 0x01 {
			critical, remaining, decodeErr := readDerefBERElement(fields)
			if decodeErr != nil || len(critical.content) != 1 {
				return nil, malformed("invalid verify credentials control criticality")
			}
			control.Critical = critical.content[0] != 0
			fields = remaining
		}
		if len(fields) != 0 {
			value, extra, decodeErr := readDerefBERElement(fields)
			if decodeErr != nil || value.identifier != 0x04 || len(extra) != 0 {
				return nil, malformed("invalid verify credentials control value or field order")
			}
			control.HasValue, control.Value = true, bytes.Clone(value.content)
		}
		controls = append(controls, control)
		content = rest
	}
	return controls, nil
}

// EncodeVerifyCredentialsResponseValue encodes the inner value only: INTEGER
// result code, OCTET STRING diagnostic message, and optional [2] controls.
// This matches vc_create_response, whose result code is not ENUMERATED.
// MatchedDN and Referrals have no inner VC fields and are ignored. The caller
// must omit the response name when wrapping this value in an ExtendedResponse.
func EncodeVerifyCredentialsResponseValue(result Result, controls []Control) ([]byte, error) {
	if result.Code < 0 || int64(result.Code) > math.MaxInt32 {
		return nil, malformed("invalid verify credentials result code")
	}
	if len(result.DiagnosticMessage) > maxVerifyCredentialsValueBytes ||
		!utf8.ValidString(result.DiagnosticMessage) || strings.IndexByte(result.DiagnosticMessage, 0) >= 0 {
		return nil, malformed("invalid verify credentials diagnostic message")
	}
	if len(controls) > maxVerifyCredentialsControls {
		return nil, malformed("verify credentials controls exceed count limit")
	}

	// Reserve the complete bounded output before copying any caller data.
	var controlSizes [maxVerifyCredentialsControls]int
	controlsSize := 0
	for index, control := range controls {
		if len(control.OID) > maxVerifyCredentialsOIDBytes || !validDerefNumericOID(control.OID) {
			return nil, malformed("invalid verify credentials control OID")
		}
		if len(control.Value) > maxVerifyCredentialsValueBytes {
			return nil, malformed("verify credentials control value exceeds size limit")
		}
		size := berElementSize(len(control.OID))
		if control.Critical {
			size += berElementSize(1)
		}
		if control.HasValue || control.Value != nil {
			size += berElementSize(len(control.Value))
		}
		controlSizes[index] = size
		controlsSize += berElementSize(size)
		if controlsSize > maxVerifyCredentialsValueBytes {
			return nil, malformed("verify credentials response controls exceed size limit")
		}
	}
	size := berElementSize(int(integerContentSize(int64(result.Code)))) +
		berElementSize(len(result.DiagnosticMessage))
	if len(controls) != 0 {
		size += berElementSize(controlsSize)
	}
	if berElementSize(size) > maxVerifyCredentialsValueBytes {
		return nil, malformed("verify credentials response value exceeds size limit")
	}

	encoded := make([]byte, 0, berElementSize(size))
	encoded = appendBERHeader(encoded, 0x30, size)
	encoded = appendBERPositiveInteger(encoded, 0x02, int64(result.Code))
	encoded = appendBERBytes(encoded, 0x04, []byte(result.DiagnosticMessage))
	if len(controls) != 0 {
		encoded = appendBERHeader(encoded, 0xa2, controlsSize)
		for index, control := range controls {
			encoded = appendBERHeader(encoded, 0x30, controlSizes[index])
			encoded = appendBERBytes(encoded, 0x04, []byte(control.OID))
			if control.Critical {
				encoded = append(encoded, 0x01, 0x01, 0xff)
			}
			if control.HasValue || control.Value != nil {
				encoded = appendBERBytes(encoded, 0x04, control.Value)
			}
		}
	}
	return encoded, nil
}
