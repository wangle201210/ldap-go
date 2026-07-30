package server

import (
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const assertionControlOID = "1.3.6.1.1.12"

type requestControls struct {
	assertion *directory.Filter
}

func parseRequestControls(
	controls []ldapwire.Control,
) (requestControls, *ldapwire.Result) {
	var parsed requestControls
	for _, control := range controls {
		switch control.OID {
		case assertionControlOID:
			if parsed.assertion != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"assert control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"assert control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"assert control value is empty",
				)
			}
			filter, err := ldapwire.DecodeFilter(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"assert control filter is invalid",
				)
			}
			parsed.assertion = &filter
		default:
			if control.Critical {
				return requestControls{}, controlResult(
					ldapwire.ResultUnavailableCriticalExtension,
					"unsupported critical control",
				)
			}
		}
	}
	return parsed, nil
}

func controlResult(
	code ldapwire.ResultCode,
	diagnostic string,
) *ldapwire.Result {
	result := ldapwire.ResultError(code, diagnostic)
	return &result
}

func (server *Server) checkAssertion(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	filter *directory.Filter,
) error {
	if filter == nil {
		return nil
	}
	matches, err := server.filterMatches(
		runtime,
		reader,
		boundDN,
		entry,
		*filter,
	)
	if err != nil || !matches {
		return operationFailed(ldapwire.ResultAssertionFailed, "")
	}
	return nil
}
