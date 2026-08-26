package server

import (
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	assertionControlOID        = "1.3.6.1.1.12"
	preReadControlOID          = "1.3.6.1.1.13.1"
	postReadControlOID         = "1.3.6.1.1.13.2"
	noOpControlOID             = "1.3.6.1.4.1.4203.666.5.2"
	pagedResultsControlOID     = "1.2.840.113556.1.4.319"
	sortRequestControlOID      = "1.2.840.113556.1.4.473"
	sortResponseControlOID     = "1.2.840.113556.1.4.474"
	vlvRequestControlOID       = "2.16.840.1.113730.3.4.9"
	vlvResponseControlOID      = "2.16.840.1.113730.3.4.10"
	manageDsaITControlOID      = "2.16.840.1.113730.3.4.2"
	relaxControlOID            = "1.3.6.1.4.1.4203.666.5.12"
	permissiveModifyControlOID = "1.2.840.113556.1.4.1413"
	dontUseCopyControlOID      = "1.3.6.1.1.22"
	subentriesControlOID       = "1.3.6.1.4.1.4203.1.10.1"
	syncRequestControlOID      = "1.3.6.1.4.1.4203.1.9.1.1"
	syncStateControlOID        = "1.3.6.1.4.1.4203.1.9.1.2"
	syncDoneControlOID         = "1.3.6.1.4.1.4203.1.9.1.3"
	syncInfoOID                = "1.3.6.1.4.1.4203.1.9.1.4"
	valueSortControlOID        = "1.3.6.1.4.1.4203.666.5.14"
	domainScopeControlOID      = ldapwire.DomainScopeControlOID
	searchOptionsControlOID    = ldapwire.SearchOptionsControlOID
	treeDeleteControlOID       = "1.2.840.113556.1.4.805"
	lazyCommitControlOID       = "1.2.840.113556.1.4.619"
)

type requestControlSupport uint32

const (
	supportsAssertion requestControlSupport = 1 << iota
	supportsPreRead
	supportsPostRead
	supportsPagedResults
	supportsServerSideSort
	supportsVirtualListView
	supportsManageDsaIT
	supportsSubentries
	supportsSync
	supportsDontUseCopy
	supportsPasswordPolicy
	supportsAccountUsability
	supportsRelax
	supportsValueSort
	supportsNoOp
	supportsPermissiveModify
	supportsDeref
	supportsMatchedValues
	supportsDomainScope
	supportsSearchOptions
	supportsTreeDelete
	supportsLazyCommit
)

type requestControls struct {
	assertion        *directory.Filter
	preRead          *readControlRequest
	postRead         *readControlRequest
	paging           *pagedResultsRequest
	sorting          *serverSideSortRequest
	vlv              *virtualListViewRequest
	manageDsaIT      bool
	dontUseCopy      bool
	subentries       *bool
	sync             *syncRequestControl
	passwordPolicy   bool
	accountUsability bool
	relax            bool
	noOp             bool
	permissiveModify bool
	valueSort        *valueSortControlRequest
	deref            *derefControlRequest
	matchedValues    *matchedValuesControlRequest
	chaining         *chainBehaviorRequest
	domainScope      bool
	treeDelete       *treeDeleteControlRequest
	lazyCommit       bool
}

type readControlRequest struct {
	attributes []string
	critical   bool
}

type syncRequestControl struct {
	request  ldapwire.SyncRequestValue
	critical bool
}

type valueSortControlRequest struct {
	raw      bool
	critical bool
}

type matchedValuesControlRequest struct {
	filters  []directory.Filter
	critical bool
}

type treeDeleteControlRequest struct {
	critical bool
}

func parseRequestControls(
	controls []ldapwire.Control,
	supported requestControlSupport,
) (requestControls, *ldapwire.Result) {
	return parseRequestControlsWithDisallows(
		controls,
		supported,
		disallowsRuntimeConfiguration{},
	)
}

func parseRequestControlsWithDisallows(
	controls []ldapwire.Control,
	supported requestControlSupport,
	disallows disallowsRuntimeConfiguration,
) (requestControls, *ldapwire.Result) {
	var parsed requestControls
	chaining, controlFailure := parseChainingBehaviorControls(controls)
	if controlFailure != nil {
		return requestControls{}, controlFailure
	}
	parsed.chaining = chaining
	for _, control := range controls {
		switch control.OID {
		case chainingBehaviorControlOID:
			continue
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
		case ldapwire.MatchedValuesControlOID:
			if supported&supportsMatchedValues == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.matchedValues != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valuesReturnFilter control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valuesReturnFilter control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valuesReturnFilter control value is empty",
				)
			}
			filters, err := ldapwire.DecodeValuesReturnFilter(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valuesReturnFilter control could not be decoded",
				)
			}
			parsed.matchedValues = &matchedValuesControlRequest{
				filters:  filters,
				critical: control.Critical,
			}
		case domainScopeControlOID:
			if supported&supportsDomainScope == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.domainScope {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"domainScope control specified multiple times",
				)
			}
			if len(control.Value) != 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"domainScope control value not absent",
				)
			}
			parsed.domainScope = true
		case searchOptionsControlOID:
			if supported&supportsSearchOptions == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"searchOptions control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"searchOptions control value is empty",
				)
			}
			flags, err := ldapwire.DecodeSearchOptionsValue(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"searchOptions control decoding error",
				)
			}
			if flags & ^int32(1) != 0 {
				if control.Critical {
					return requestControls{}, controlResult(
						ldapwire.ResultUnwillingToPerform,
						"searchOptions contained unrecognized flag",
					)
				}
				continue
			}
			if flags&1 != 0 {
				if parsed.domainScope {
					return requestControls{}, controlResult(
						ldapwire.ResultProtocolError,
						"searchOptions control specified multiple times or with domainScope control",
					)
				}
				parsed.domainScope = true
			}
		case treeDeleteControlOID:
			if supported&supportsTreeDelete == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.treeDelete != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"treeDelete control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"treeDelete control value not absent",
				)
			}
			parsed.treeDelete = &treeDeleteControlRequest{critical: control.Critical}
		case lazyCommitControlOID:
			if supported&supportsLazyCommit == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.lazyCommit {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					`"Lazy Commit?" control specified multiple times`,
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					`"Lazy Commit?" control value not absent`,
				)
			}
			parsed.lazyCommit = true
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
		case noOpControlOID:
			if supported&supportsNoOp == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.noOp {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"noop control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"noop control value not absent",
				)
			}
			parsed.noOp = true
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
		case relaxControlOID:
			if supported&supportsRelax == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.relax {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"relax control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"relax control must not have a value",
				)
			}
			parsed.relax = true
		case permissiveModifyControlOID:
			if supported&supportsPermissiveModify == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.permissiveModify {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"permissiveModify control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"permissiveModify control value not absent",
				)
			}
			parsed.permissiveModify = true
		case dontUseCopyControlOID:
			if supported&supportsDontUseCopy == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.dontUseCopy {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"dontUseCopy control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"dontUseCopy control value not absent",
				)
			}
			if disallows.noncriticalDontUseCopy && !control.Critical {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"dontUseCopy criticality of FALSE not allowed",
				)
			}
			parsed.dontUseCopy = true
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
		case syncRequestControlOID:
			if supported&supportsSync == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.sync != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Sync control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Sync control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Sync control value is empty",
				)
			}
			request, err := ldapwire.DecodeSyncRequestValue(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Sync control value could not be decoded",
				)
			}
			parsed.sync = &syncRequestControl{
				request:  request,
				critical: control.Critical,
			}
		case valueSortControlOID:
			if supported&supportsValueSort == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.valueSort != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valSort control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valSort control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valSort control value is empty",
				)
			}
			raw, err := ldapwire.DecodeValueSortControlValue(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"valSort control: flag decoding error",
				)
			}
			parsed.valueSort = &valueSortControlRequest{
				raw:      raw,
				critical: control.Critical,
			}
		case ldapwire.DerefControlOID:
			if supported&supportsDeref == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.deref != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Dereference control specified multiple times",
				)
			}
			if !control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Dereference control value is absent",
				)
			}
			if len(control.Value) == 0 {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Dereference control value is empty",
				)
			}
			specs, err := decodeDerefRequestControlValue(control.Value)
			if err != nil {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"Dereference control: derefSpec decoding error",
				)
			}
			parsed.deref = &derefControlRequest{
				specs:    specs,
				critical: control.Critical,
			}
		case passwordPolicyControlOID:
			if supported&supportsPasswordPolicy == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.passwordPolicy {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"passwordPolicyRequest control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"passwordPolicyRequest control value not absent",
				)
			}
			parsed.passwordPolicy = true
		case accountUsabilityControlOID:
			if supported&supportsAccountUsability == 0 {
				if control.Critical {
					return unsupportedCriticalControl()
				}
				continue
			}
			if parsed.accountUsability {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"account usability control specified multiple times",
				)
			}
			if control.HasValue {
				return requestControls{}, controlResult(
					ldapwire.ResultProtocolError,
					"account usability control value not absent",
				)
			}
			parsed.accountUsability = true
		default:
			if control.Critical {
				return unsupportedCriticalControl()
			}
		}
	}
	if parsed.sync != nil && parsed.paging != nil {
		return requestControls{}, controlResult(
			ldapwire.ResultProtocolError,
			"Sync control specified with pagedResults control",
		)
	}
	return parsed, nil
}

func decodeDerefRequestControlValue(value []byte) ([]ldapwire.DerefSpec, error) {
	// OpenLDAP's ber_first_element accepts any short-form constructed outer
	// tag; normalize that container while retaining strict child decoding.
	if len(value) > 0 &&
		value[0]&0x20 != 0 &&
		value[0]&0x1f != 0x1f &&
		value[0] != 0x30 {
		value = append([]byte(nil), value...)
		value[0] = 0x30
	}
	return ldapwire.DecodeDerefRequestValue(value)
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
	attributes := expandObjectClassAttributeSelection(
		runtime.schema,
		request.attributes,
	)
	for _, attribute := range attributes {
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
	entry, err := withCollectiveAttributes(runtime.schema, reader, entry)
	if err != nil {
		return nil, err
	}
	if dn, parseErr := directory.ParseDN(entry.DN); parseErr == nil {
		if database := databaseForDN(runtime, dn); database != nil {
			entry, err = withSyncProviderContextCSNs(
				reader,
				*database,
				entry,
			)
			if err != nil {
				return nil, err
			}
		}
	}
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
		attributes,
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
