package server

import (
	"bytes"
	"strings"

	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	sessionTrackingRadiusSessionFormatOID      = ldapwire.SessionTrackingControlOID + ".1"
	sessionTrackingRadiusMultiSessionFormatOID = ldapwire.SessionTrackingControlOID + ".2"
	sessionTrackingUsernameFormatOID           = ldapwire.SessionTrackingControlOID + ".3"
)

func parseSessionTrackingControls(
	request ldapwire.Request,
	controls []ldapwire.Control,
) ([]audit.SessionTracking, *ldapwire.Result) {
	supported, parse := sessionTrackingOperationSupport(request)
	if !parse {
		return nil, nil
	}
	var values []audit.SessionTracking
	for _, control := range controls {
		if control.OID != ldapwire.SessionTrackingControlOID {
			continue
		}
		if !supported {
			if control.Critical {
				_, failure := unsupportedCriticalControl()
				return values, failure
			}
			continue
		}
		if control.Critical {
			return values, controlResult(
				ldapwire.ResultProtocolError,
				"sessionTracking criticality is TRUE",
			)
		}
		if !control.HasValue {
			return values, controlResult(
				ldapwire.ResultProtocolError,
				"sessionTracking control value is absent",
			)
		}
		if len(control.Value) == 0 {
			return values, controlResult(
				ldapwire.ResultProtocolError,
				"sessionTracking control value is empty",
			)
		}
		decoded, formatOIDValid, err := ldapwire.DecodeSessionTrackingValue(control.Value)
		if err != nil {
			return values, controlResult(
				ldapwire.ResultProtocolError,
				"sessionTracking control decoding error",
			)
		}
		if !formatOIDValid {
			// OpenLDAP 2.6.13 accidentally returns success for an invalid
			// format OID and omits that control from its log prefix.
			clearSessionTrackingValue(&decoded)
			continue
		}
		value, ok := auditSessionTrackingValue(decoded)
		clearSessionTrackingValue(&decoded)
		if ok {
			values = append(values, value)
		}
	}
	return values, nil
}

func sessionTrackingOperationSupport(request ldapwire.Request) (supported, parse bool) {
	switch request := request.(type) {
	case ldapwire.BindRequest,
		ldapwire.SearchRequest,
		ldapwire.CompareRequest,
		ldapwire.AddRequest,
		ldapwire.ModifyRequest,
		ldapwire.DeleteRequest,
		ldapwire.ModifyDNRequest:
		return true, true
	case ldapwire.ExtendedRequest:
		switch request.Name {
		case passwordModifyOID, whoAmIOID, dynamicRefreshOID:
			return true, true
		default:
			return false, true
		}
	case ldapwire.UnbindRequest, ldapwire.AbandonRequest, ldapwire.UnsupportedRequest:
		return false, false
	default:
		return false, true
	}
}

func auditSessionTrackingValue(
	value ldapwire.SessionTrackingValue,
) (audit.SessionTracking, bool) {
	result := audit.SessionTracking{
		FormatOID:         string(value.FormatOID),
		IdentifierPresent: len(value.SessionTrackingIdentifier) != 0,
	}
	switch result.FormatOID {
	case sessionTrackingRadiusSessionFormatOID:
		result.FormatName = "RADIUS-Acct-Session-Id"
	case sessionTrackingRadiusMultiSessionFormatOID:
		result.FormatName = "RADIUS-Acct-Multi-Session-Id"
	case sessionTrackingUsernameFormatOID:
		result.FormatName = "USERNAME"
	}
	if openLDAPLDIFPrintable(value.SessionSourceIP) {
		result.SourceIP = auditSafeString(string(value.SessionSourceIP))
	}
	if openLDAPLDIFPrintable(value.SessionSourceName) {
		result.SourceName = auditSafeString(string(value.SessionSourceName))
	}
	if openLDAPLDIFPrintable(value.SessionTrackingIdentifier) {
		result.Identifier = auditSafeString(string(value.SessionTrackingIdentifier))
	}
	return result,
		result.SourceIP != "" || result.SourceName != "" || result.IdentifierPresent
}

func clearSessionTrackingValue(value *ldapwire.SessionTrackingValue) {
	if value == nil {
		return
	}
	clear(value.SessionSourceIP)
	clear(value.SessionSourceName)
	clear(value.FormatOID)
	clear(value.SessionTrackingIdentifier)
	*value = ldapwire.SessionTrackingValue{}
}

func openLDAPLDIFPrintable(value []byte) bool {
	if len(value) == 0 || value[0] <= ' ' || value[0] > '~' ||
		value[0] == ':' || value[0] == '<' ||
		value[len(value)-1] <= ' ' || value[len(value)-1] > '~' {
		return false
	}
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return !bytes.ContainsFunc(value, func(character rune) bool {
		return character < ' ' || character > '~'
	})
}

func withoutSessionTrackingControls(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != ldapwire.SessionTrackingControlOID {
			filtered = append(filtered, control)
		}
	}
	return filtered
}

func sessionTrackingLogValue(value audit.SessionTracking) string {
	parts := make([]string, 0, 3)
	if value.SourceIP != "" {
		parts = append(parts, "IP="+value.SourceIP)
	}
	if value.SourceName != "" {
		parts = append(parts, "NAME="+value.SourceName)
	}
	if value.IdentifierPresent {
		format := value.FormatName
		if format == "" {
			format = value.FormatOID
		}
		parts = append(parts, format+"="+value.Identifier)
	}
	return strings.Join(parts, " ")
}
