package server

import "github.com/wangle201210/ldap-go/internal/ldapwire"

func prevalidateLazyCommitControls(
	request ldapwire.Request,
	controls []ldapwire.Control,
) *ldapwire.Result {
	supported, parse := lazyCommitOperationSupport(request)
	if !parse {
		return nil
	}
	found := false
	for _, control := range controls {
		if control.OID != lazyCommitControlOID {
			continue
		}
		if !supported {
			continue
		}
		if found {
			return controlResult(
				ldapwire.ResultProtocolError,
				`"Lazy Commit?" control specified multiple times`,
			)
		}
		found = true
		if control.HasValue {
			return controlResult(
				ldapwire.ResultProtocolError,
				`"Lazy Commit?" control value not absent`,
			)
		}
	}
	return nil
}

func lazyCommitOperationSupport(request ldapwire.Request) (supported, parse bool) {
	switch request.(type) {
	case ldapwire.SearchRequest,
		ldapwire.CompareRequest,
		ldapwire.AddRequest,
		ldapwire.ModifyRequest,
		ldapwire.DeleteRequest,
		ldapwire.ModifyDNRequest:
		return true, true
	case ldapwire.BindRequest, ldapwire.ExtendedRequest:
		return false, true
	case ldapwire.UnbindRequest, ldapwire.AbandonRequest, ldapwire.UnsupportedRequest:
		return false, false
	default:
		return false, true
	}
}

func withoutLazyCommitControls(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != lazyCommitControlOID {
			filtered = append(filtered, control)
		}
	}
	return filtered
}
