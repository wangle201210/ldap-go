package server

import (
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	assertionControlOID    = "1.3.6.1.1.12"
	preReadControlOID      = "1.3.6.1.1.13.1"
	postReadControlOID     = "1.3.6.1.1.13.2"
	pagedResultsControlOID = "1.2.840.113556.1.4.319"
	sortRequestControlOID  = "1.2.840.113556.1.4.473"
	sortResponseControlOID = "1.2.840.113556.1.4.474"
	vlvRequestControlOID   = "2.16.840.1.113730.3.4.9"
	vlvResponseControlOID  = "2.16.840.1.113730.3.4.10"
	manageDsaITControlOID  = "2.16.840.1.113730.3.4.2"
	subentriesControlOID   = "1.3.6.1.4.1.4203.1.10.1"
)

type requestControlSupport uint16

const (
	supportsAssertion requestControlSupport = 1 << iota
	supportsPreRead
	supportsPostRead
	supportsPagedResults
	supportsServerSideSort
	supportsVirtualListView
	supportsManageDsaIT
	supportsSubentries
)

type requestControls struct {
	assertion   *directory.Filter
	preRead     *readControlRequest
	postRead    *readControlRequest
	paging      *pagedResultsRequest
	sorting     *serverSideSortRequest
	vlv         *virtualListViewRequest
	manageDsaIT bool
	subentries  *bool
}

type readControlRequest struct {
	attributes []string
	critical   bool
}

func parseRequestControls(
	controls []ldapwire.Control,
	supported requestControlSupport,
) (requestControls, *ldapwire.Result) {
	var parsed requestControls
	for _, control := range controls {
		switch control.OID {
		case assertionControlOID:
			if supported&supportsAssertion == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
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
		case preReadControlOID:
			if supported&supportsPreRead == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.preRead != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"preread control specified multiple times",
				)
			}
			request, result := parseReadControl(control, "preread")
			if result != nil {
				return requestControls{}, result
			}
			parsed.preRead = request
		case postReadControlOID:
			if supported&supportsPostRead == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.postRead != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"postread control specified multiple times",
				)
			}
			request, result := parseReadControl(control, "postread")
			if result != nil {
				return requestControls{}, result
			}
			parsed.postRead = request
		case pagedResultsControlOID:
			if supported&supportsPagedResults == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.paging != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"paged results control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"paged results control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"paged results control value is empty",
				)
			}
			size, cookie, err := ldapwire.DecodePagedResultsValue(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"paged results control could not be decoded",
				)
			}
			parsed.paging = &pagedResultsRequest{
				size:   size,
				cookie: cookie,
			}
		case sortRequestControlOID:
			if supported&supportsServerSideSort == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.sorting != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"server-side sort control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"server-side sort control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"server-side sort control value is empty",
				)
			}
			keys, err := ldapwire.DecodeSortRequestValue(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"server-side sort control could not be decoded",
				)
			}
			parsed.sorting = &serverSideSortRequest{
				keys:     keys,
				critical: control.Critical,
			}
		case vlvRequestControlOID:
			if supported&supportsVirtualListView == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.vlv != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"VLV control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"VLV control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"VLV control value is empty",
				)
			}
			request, err := ldapwire.DecodeVirtualListViewRequestValue(
				control.Value,
			)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"VLV control could not be decoded",
				)
			}
			parsed.vlv = &virtualListViewRequest{
				request:  request,
				critical: control.Critical,
			}
		case manageDsaITControlOID:
			if supported&supportsManageDsaIT == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.manageDsaIT {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"manageDSAit control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"manageDSAit control value not absent",
				)
			}
			parsed.manageDsaIT = true
		case subentriesControlOID:
			if supported&supportsSubentries == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.subentries != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"subentries control specified multiple times",
				)
			}
			if !control.HasValue ||
				len(control.Value) != 3 ||
				control.Value[0] != 0x01 ||
				control.Value[1] != 0x01 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"subentries control value encoding is bogus",
				)
			}
			visible := control.Value[2] != 0
			parsed.subentries = &visible
		default:
			if control.Critical {
				return unsupportedCriticalControl()
			}
		}
	}
	return parsed, nil
}

func parseReadControl(
	control ldapwire.Control,
	name string,
) (*readControlRequest, *ldapwire.Result) {
	if !control.HasValue {
		return nil, controlResult(
			ldapwire.ResultProtocolError,
			name+" control value is absent",
		)
	}
	if len(control.Value) == 0 {
		return nil, controlResult(
			ldapwire.ResultProtocolError,
			name+" control value is empty",
		)
	}
	attributes, err := ldapwire.DecodeAttributeSelection(control.Value)
	if err != nil {
		return nil, controlResult(
			ldapwire.ResultProtocolError,
			name+" control attribute selection is invalid",
		)
	}
	return &readControlRequest{
		attributes: attributes,
		critical:   control.Critical,
	}, nil
}

func unsupportedCriticalControl() (requestControls, *ldapwire.Result) {
	return requestControls{}, controlResult(
		ldapwire.ResultUnavailableCriticalExtension,
		"unsupported critical control",
	)
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

func (server *Server) readResponseControl(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	request *readControlRequest,
	oid string,
) (*ldapwire.Control, error) {
	if request == nil {
		return nil, nil
	}
	for _, attribute := range request.attributes {
		if isSpecialAttributeSelection(attribute) {
			continue
		}
		if _, exists := runtime.schema.AttributeType(attribute); !exists && request.critical {
			return nil, operationFailed(
				ldapwire.ResultUndefinedAttributeType,
				"unknown attribute type in read control",
			)
		}
	}

	entry = withSubschemaReference(entry)
	if !server.allowed(
		runtime,
		reader,
		boundDN,
		entry,
		"entry",
		nil,
		acl.Read,
	) {
		if request.critical {
			return nil, operationFailed(
				ldapwire.ResultInsufficientAccessRights,
				"",
			)
		}
		return nil, nil
	}
	readable := server.attributesWithPrivilege(
		runtime,
		reader,
		boundDN,
		entry,
		acl.Read,
		false,
	)
	selected := server.selectEntry(
		runtime,
		readable,
		request.attributes,
		false,
	)
	return &ldapwire.Control{
		OID:      oid,
		Value:    ldapwire.EncodeReadControlValue(selected),
		HasValue: true,
	}, nil
}

func isSpecialAttributeSelection(attribute string) bool {
	return strings.EqualFold(attribute, "1.1") ||
		strings.EqualFold(attribute, "*") ||
		strings.EqualFold(attribute, "+")
}
