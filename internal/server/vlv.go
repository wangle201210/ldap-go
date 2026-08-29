package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	virtualListViewContextLength = 16

	openLDAPVLVSortControlMissing ldapwire.ResultCode = 76
	openLDAPVLVOffsetRangeError   ldapwire.ResultCode = 77
)

type virtualListViewRequest struct {
	request  ldapwire.VirtualListViewRequest
	critical bool
}

type virtualListViewItem struct {
	route       int
	dn          string
	cursorKey   string
	identityKey string
	primary     sortValue
}

type virtualListViewState struct {
	contextID       []byte
	fingerprint     [sha256.Size]byte
	runtime         *runtimeState
	items           []virtualListViewItem
	sortLease       *serverSideSortLease
	retainedBytes   int64
	releaseRetained func()
}

type virtualListViewContext struct {
	request     ldapwire.VirtualListViewRequest
	fingerprint [sha256.Size]byte
	runtime     *runtimeState
	state       *virtualListViewState
}

type virtualListViewFailure struct {
	result   ldapwire.Result
	response ldapwire.VirtualListViewResponse
}

func prepareVirtualListView(
	state *connectionState,
	searchRequest ldapwire.SearchRequest,
	controls []ldapwire.Control,
	request *virtualListViewRequest,
) (*virtualListViewContext, *virtualListViewFailure) {
	if request == nil {
		return nil, nil
	}
	fingerprint := virtualListViewFingerprint(
		state.runtime.schema,
		state.boundDN,
		searchRequest,
		controls,
	)
	context := &virtualListViewContext{
		request:     request.request,
		fingerprint: fingerprint,
		runtime:     state.runtime,
	}
	if !validVirtualListViewRange(request.request) {
		return nil, newVirtualListViewFailure(
			openLDAPVLVOffsetRangeError,
			"VLV request range is invalid",
			0,
			nil,
		)
	}
	if !request.request.HasContextID {
		return context, nil
	}

	current := state.virtualListViews[string(request.request.ContextID)]
	if len(request.request.ContextID) != virtualListViewContextLength ||
		current == nil ||
		!bytes.Equal(request.request.ContextID, current.contextID) ||
		current.runtime != state.runtime ||
		current.fingerprint != fingerprint {
		return nil, newVirtualListViewFailure(
			ldapwire.ResultProtocolError,
			"VLV contextID is invalid",
			0,
			nil,
		)
	}
	context.state = current
	return context, nil
}

func validVirtualListViewRange(request ldapwire.VirtualListViewRequest) bool {
	if request.BeforeCount < 0 ||
		request.BeforeCount > math.MaxInt32 ||
		request.AfterCount < 0 ||
		request.AfterCount > math.MaxInt32 ||
		request.BeforeCount+request.AfterCount+1 > math.MaxInt32 {
		return false
	}
	if !request.ByOffset {
		return true
	}
	return request.Offset >= 1 &&
		request.Offset <= math.MaxInt32 &&
		request.ContentCount >= 0 &&
		request.ContentCount <= math.MaxInt32
}

func newVirtualListViewFailure(
	code ldapwire.ResultCode,
	diagnostic string,
	contentCount int,
	contextID []byte,
) *virtualListViewFailure {
	return &virtualListViewFailure{
		result: ldapwire.ResultError(
			ldapwire.ResultVirtualListViewError,
			diagnostic,
		),
		response: ldapwire.VirtualListViewResponse{
			ContentCount: int64(contentCount),
			Result:       code,
			ContextID:    bytes.Clone(contextID),
			HasContextID: contextID != nil,
		},
	}
}

func (server *Server) startVirtualListView(
	state *connectionState,
	context *virtualListViewContext,
	candidates []searchCandidate,
	sortLease *serverSideSortLease,
) (*virtualListViewState, error) {
	retainedBytes := virtualListViewRetainedBytes(candidates)
	if retainedBytes > 0 && !server.searchMemoryLimiter.tryAcquire(retainedBytes) {
		return nil, errVirtualListViewMemoryLimit
	}
	releaseRetained := func() {}
	if retainedBytes > 0 {
		releaseRetained = func() {
			server.searchMemoryLimiter.release(retainedBytes)
		}
	}
	retained := false
	defer func() {
		if !retained {
			releaseRetained()
		}
	}()
	var contextID []byte
	for {
		contextID = make([]byte, virtualListViewContextLength)
		if _, err := rand.Read(contextID); err != nil {
			return nil, err
		}
		if state.virtualListViews == nil ||
			state.virtualListViews[string(contextID)] == nil {
			break
		}
	}
	items := make([]virtualListViewItem, len(candidates))
	for index := range candidates {
		var primary sortValue
		if len(candidates[index].values) > 0 {
			primary = candidates[index].values[0]
			primary.value = bytes.Clone(primary.value)
		}
		items[index] = virtualListViewItem{
			route:       candidates[index].route,
			dn:          candidates[index].dn,
			cursorKey:   candidates[index].cursorKey,
			identityKey: candidates[index].identityKey,
			primary:     primary,
		}
	}
	view := &virtualListViewState{
		contextID:       contextID,
		fingerprint:     context.fingerprint,
		runtime:         context.runtime,
		items:           items,
		sortLease:       sortLease,
		retainedBytes:   retainedBytes,
		releaseRetained: releaseRetained,
	}
	if state.virtualListViews == nil {
		state.virtualListViews = make(map[string]*virtualListViewState)
	}
	state.virtualListViews[string(contextID)] = view
	context.state = view
	retained = true
	return view, nil
}

func discardVirtualListView(
	state *connectionState,
	view *virtualListViewState,
) {
	if view == nil {
		return
	}
	key := string(view.contextID)
	if state.virtualListViews[key] != view {
		return
	}
	delete(state.virtualListViews, key)
	releaseServerSideSortLease(state, view.sortLease)
	view.releaseRetainedMemory()
	if len(state.virtualListViews) == 0 {
		state.virtualListViews = nil
	}
}

func clearVirtualListViews(state *connectionState) {
	for _, view := range state.virtualListViews {
		releaseServerSideSortLease(state, view.sortLease)
		view.releaseRetainedMemory()
	}
	state.virtualListViews = nil
}

var errVirtualListViewMemoryLimit = errors.New("VLV state memory budget exceeded")

func (view *virtualListViewState) releaseRetainedMemory() {
	if view == nil || view.releaseRetained == nil {
		return
	}
	view.releaseRetained()
	view.releaseRetained = nil
	view.retainedBytes = 0
}

func virtualListViewRetainedBytes(candidates []searchCandidate) int64 {
	size := int64(unsafe.Sizeof(virtualListViewState{})) +
		virtualListViewContextLength +
		int64(len(candidates))*int64(unsafe.Sizeof(virtualListViewItem{}))
	for _, candidate := range candidates {
		size += int64(len(candidate.dn) + len(candidate.cursorKey) + len(candidate.identityKey))
		if len(candidate.values) > 0 {
			size += int64(len(candidate.values[0].value))
		}
	}
	return size
}

func virtualListViewWindow(
	registry *schema.Registry,
	request ldapwire.VirtualListViewRequest,
	primaryKey resolvedSortKey,
	items []virtualListViewItem,
) (int, int, int, ldapwire.ResultCode, error) {
	count := len(items)
	if count == 0 {
		return 0, 0, 0, ldapwire.ResultSuccess, nil
	}

	targetPosition := 0
	if request.ByOffset {
		switch {
		case request.ContentCount > 0 &&
			request.Offset > request.ContentCount:
			return 0, 0, 0, openLDAPVLVOffsetRangeError, nil
		case request.Offset == request.ContentCount:
			targetPosition = count
		case request.Offset == 1:
			targetPosition = 1
		case request.ContentCount > 0 &&
			request.ContentCount != int64(count):
			count64 := int64(count)
			targetPosition = int(
				count64/request.ContentCount*request.Offset +
					count64%request.ContentCount*
						request.Offset/request.ContentCount,
			)
		default:
			if request.Offset > int64(count) {
				return 0, 0, 0, openLDAPVLVOffsetRangeError, nil
			}
			targetPosition = int(request.Offset)
		}
	} else {
		targetPosition = count + 1
		for index, item := range items {
			comparison, err := compareVirtualListViewAssertion(
				registry,
				primaryKey,
				item.primary,
				request.AssertionValue,
			)
			if err != nil {
				return 0, 0, 0, ldapwire.ResultInappropriateMatching, err
			}
			if comparison >= 0 {
				targetPosition = index + 1
				break
			}
		}
	}

	if targetPosition == count+1 {
		before := max(int(request.BeforeCount), 1)
		return max(0, count-before), count, targetPosition,
			ldapwire.ResultSuccess, nil
	}
	if targetPosition == 0 {
		return 0, min(count, int(request.AfterCount)+1), targetPosition,
			ldapwire.ResultSuccess, nil
	}
	start := max(0, targetPosition-1-int(request.BeforeCount))
	end := min(count, targetPosition+int(request.AfterCount))
	return start, end, targetPosition, ldapwire.ResultSuccess, nil
}

func compareVirtualListViewAssertion(
	registry *schema.Registry,
	key resolvedSortKey,
	value sortValue,
	assertion []byte,
) (int, error) {
	comparison := 1
	if value.present {
		var err error
		comparison, err = registry.CompareOrdering(
			key.attribute,
			key.orderingRule,
			value.value,
			assertion,
		)
		if err != nil {
			return 0, err
		}
	} else if _, err := registry.CompareOrdering(
		key.attribute,
		key.orderingRule,
		assertion,
		assertion,
	); err != nil {
		return 0, err
	}
	if key.reverse {
		comparison = -comparison
	}
	return comparison, nil
}

func (server *Server) virtualListViewEntries(
	ctx context.Context,
	state *connectionState,
	routes []databaseSearchRoute,
	request ldapwire.SearchRequest,
	view *virtualListViewState,
	start,
	end int,
	rawValueOrder bool,
	manageDsaIT bool,
) ([]directory.Entry, error) {
	if view == nil || start < 0 || end < start || end > len(view.items) {
		return nil, errors.New("VLV window is invalid")
	}
	entries := make([]directory.Entry, 0, end-start)
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		collectivePlans := newCollectiveAttributePlanCache(state.runtime.schema)
		collectResponses := newCollectProjectionCache(
			server,
			state.runtime,
			reader,
			state.boundDN,
		)
		nestGroupPlans := newNestGroupProjectionCache(
			ctx,
			server,
			state.runtime,
			reader,
			state.boundDN,
			nestGroupProjectionRequest{
				attributes: request.Attributes,
				typesOnly:  request.TypesOnly,
				filter:     request.Filter,
			},
		)
		for _, item := range view.items[start:end] {
			if item.route < 0 || item.route >= len(routes) {
				return fmt.Errorf("VLV route %d is invalid", item.route)
			}
			dn, err := directory.ParseDN(item.dn)
			if err != nil {
				return fmt.Errorf("parse VLV DN %q: %w", item.dn, err)
			}
			database := &state.runtime.databases[routes[item.route].databaseIndex]
			tx := readerForDatabase(reader, *database)
			dn, err = storage.NormalizeReaderDN(tx, dn)
			if err != nil {
				return fmt.Errorf("normalize VLV DN %q: %w", item.dn, err)
			}
			entry, err := tx.Get(dn)
			if errors.Is(err, storage.ErrEntryNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			matches, err := virtualListViewItemMatchesEntry(
				state.runtime.schema,
				item,
				entry,
			)
			if err != nil {
				return err
			}
			if !matches {
				continue
			}
			entry = withSubschemaReference(entry)
			entry, err = collectivePlans.apply(database.partition, tx, entry)
			if err != nil {
				return err
			}
			if !manageDsaIT {
				entry, err = nestGroupPlans.project(*database, entry)
				if err != nil {
					return err
				}
			}
			entry, err = withSyncProviderContextCSNs(
				reader,
				*database,
				entry,
			)
			if err != nil {
				return err
			}
			if !server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				"entry",
				nil,
				acl.Read,
			) {
				continue
			}
			responseEntry, err := collectResponses.apply(*database, entry)
			if err != nil {
				return err
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				tx,
				state.boundDN,
				responseEntry,
				acl.Read,
				request.TypesOnly,
			)
			readable = projectDDSRemainingTTL(readable, responseEntry, time.Now())
			selected := server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			)
			if !rawValueOrder {
				applyValueSort(
					state.runtime.schema,
					valueSortRulesForDatabase(state.runtime.databases, *database),
					&selected,
				)
			}
			entries = append(entries, selected)
		}
		return nil
	})
	return entries, err
}

func virtualListViewItemMatchesEntry(
	registry *schema.Registry,
	item virtualListViewItem,
	entry directory.Entry,
) (bool, error) {
	if item.identityKey == "" {
		return true, nil
	}
	dn, err := registry.NormalizeDN(entry.DN)
	if err != nil {
		return false, fmt.Errorf("normalize VLV entry DN %q: %w", entry.DN, err)
	}
	return dn.Key() == item.identityKey, nil
}

func virtualListViewResponseControl(
	response ldapwire.VirtualListViewResponse,
) []ldapwire.Control {
	return []ldapwire.Control{{
		OID:      vlvResponseControlOID,
		Value:    ldapwire.EncodeVirtualListViewResponseValue(response),
		HasValue: true,
	}}
}

func virtualListViewFingerprint(
	registry *schema.Registry,
	boundDN string,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
) [sha256.Size]byte {
	boundDN = normalizedVirtualListViewDN(registry, boundDN)
	request.BaseDN = normalizedVirtualListViewDN(registry, request.BaseDN)
	normalizedControls := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		switch control.OID {
		case vlvRequestControlOID:
			control.Value = nil
			control.HasValue = true
		case sortRequestControlOID:
			control = normalizedVirtualListViewSortControl(registry, control)
		}
		normalizedControls = append(normalizedControls, control)
	}
	encoded, _ := json.Marshal(struct {
		BoundDN  string
		Request  ldapwire.SearchRequest
		Controls []ldapwire.Control
	}{
		BoundDN:  boundDN,
		Request:  request,
		Controls: normalizedControls,
	})
	return sha256.Sum256(encoded)
}

func normalizedVirtualListViewDN(registry *schema.Registry, value string) string {
	if value == "" || registry == nil {
		return value
	}
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		return value
	}
	return dn.NormalizedString()
}

func normalizedVirtualListViewSortControl(
	registry *schema.Registry,
	control ldapwire.Control,
) ldapwire.Control {
	if registry == nil || !control.HasValue {
		return control
	}
	keys, err := ldapwire.DecodeSortRequestValue(control.Value)
	if err != nil {
		return control
	}
	for index := range keys {
		attribute, ok := registry.AttributeType(keys[index].AttributeType)
		if !ok {
			return control
		}
		orderingRule, err := registry.OrderingRule(
			keys[index].AttributeType,
			keys[index].OrderingRule,
		)
		if err != nil {
			return control
		}
		keys[index].AttributeType = attribute.Name()
		keys[index].OrderingRule = orderingRule
	}
	control.Value = ldapwire.EncodeSortRequestValue(keys)
	return control
}
