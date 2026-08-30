package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"unsafe"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const pagedResultsCookieLength = 16

var errPagedSearchMemoryLimit = errors.New("paged search state memory budget exceeded")

type pagedResultsRequest struct {
	size   int
	cookie []byte
}

type pagedSearchCursor struct {
	route int
	dnKey string
	valid bool
}

type pagedSortedItem struct {
	route        int
	dn           string
	normalizedDN directory.DN
}

type pagedSortedSearch struct {
	items     []pagedSortedItem
	offset    int
	truncated bool
	live      bool
}

type pagedSearchState struct {
	cookie             []byte
	fingerprint        [sha256.Size]byte
	runtime            *runtimeState
	cursor             pagedSearchCursor
	sorted             *pagedSortedSearch
	count              int
	totalLimit         int
	estimate           int
	noEstimate         bool
	sortLease          *serverSideSortLease
	retainedBytes      int64
	releaseRetained    func()
	storageRevision    uint64
	hasStorageRevision bool
}

type pagedSearchContext struct {
	size               int
	fingerprint        [sha256.Size]byte
	runtime            *runtimeState
	cursor             pagedSearchCursor
	sorted             *pagedSortedSearch
	count              int
	totalLimit         int
	estimate           int
	noEstimate         bool
	abandoned          bool
	sortLease          *serverSideSortLease
	retainedBytes      int64
	releaseRetained    func()
	storageRevision    uint64
	hasStorageRevision bool
}

func (server *Server) preparePagedSearch(
	ctx context.Context,
	state *connectionState,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
	paging *pagedResultsRequest,
	limits databaseSearchExecutionLimits,
) (*pagedSearchContext, *ldapwire.Result) {
	if paging == nil {
		return nil, nil
	}
	if len(paging.cookie) == 0 &&
		request.SizeLimit > 0 &&
		paging.size >= request.SizeLimit {
		clearPagedSearch(state)
		return nil, nil
	}
	if limits.pageTotal == -2 {
		clearPagedSearch(state)
		return nil, pagingResult(
			ldapwire.ResultAdminLimitExceeded,
			"pagedResults control not allowed",
		)
	}
	if limits.pageSize > 0 && paging.size > limits.pageSize {
		clearPagedSearch(state)
		return nil, pagingResult(
			ldapwire.ResultAdminLimitExceeded,
			"illegal pagedResults page size",
		)
	}

	fingerprint := pagedSearchFingerprint(
		state.boundDN,
		request,
		controls,
	)
	if len(paging.cookie) == 0 {
		clearPagedSearch(state)
		if paging.size == 0 {
			return nil, nil
		}
		return &pagedSearchContext{
			size:        paging.size,
			fingerprint: fingerprint,
			runtime:     state.runtime,
			totalLimit:  limits.pageTotal,
			noEstimate:  limits.pageNoEstimate,
		}, nil
	}

	if len(paging.cookie) != pagedResultsCookieLength {
		clearPagedSearch(state)
		return nil, pagingResult(
			ldapwire.ResultProtocolError,
			"paged results cookie is invalid",
		)
	}
	current := state.pagedSearch
	if current == nil ||
		!bytes.Equal(paging.cookie, current.cookie) ||
		current.runtime != state.runtime ||
		current.fingerprint != fingerprint {
		clearPagedSearch(state)
		return nil, pagingResult(
			ldapwire.ResultUnwillingToPerform,
			"paged results cookie is invalid or old",
		)
	}
	if current.count >= current.totalLimit {
		clearPagedSearch(state)
		return nil, pagingResult(
			ldapwire.ResultSizeLimitExceeded,
			"",
		)
	}
	if paging.size == 0 {
		clearPagedSearch(state)
		return &pagedSearchContext{
			size: paging.size, fingerprint: fingerprint, runtime: state.runtime,
			abandoned: true,
		}, nil
	}

	currentSorted := current.sorted
	if currentSorted != nil && currentSorted.live && current.hasStorageRevision {
		if revision, ok := server.currentStorageSnapshotRevision(ctx); !ok ||
			revision != current.storageRevision {
			currentSorted = nil
		}
	}
	retainedBytes := pagedSortedSearchRetainedBytes(currentSorted)
	if retainedBytes > 0 && !server.searchMemoryLimiter.tryAcquire(retainedBytes) {
		clearPagedSearch(state)
		return nil, pagingResult(
			ldapwire.ResultAdminLimitExceeded,
			"paged search state memory budget exceeded",
		)
	}
	context := &pagedSearchContext{
		size:               paging.size,
		fingerprint:        fingerprint,
		runtime:            state.runtime,
		cursor:             current.cursor,
		sorted:             clonePagedSortedSearch(currentSorted),
		count:              current.count,
		totalLimit:         current.totalLimit,
		estimate:           current.estimate,
		noEstimate:         current.noEstimate,
		sortLease:          current.sortLease,
		storageRevision:    current.storageRevision,
		hasStorageRevision: current.hasStorageRevision,
	}
	if retainedBytes > 0 {
		context.retainedBytes = retainedBytes
		context.releaseRetained = func() {
			server.searchMemoryLimiter.release(retainedBytes)
		}
	}
	return context, nil
}

func (server *Server) completePagedSearch(
	state *connectionState,
	paging *pagedSearchContext,
	result ldapwire.Result,
	entryCount int,
	cursor pagedSearchCursor,
	hasMore bool,
) ([]ldapwire.Control, error) {
	if paging == nil {
		return nil, nil
	}
	if result.Code != ldapwire.ResultSuccess {
		clearPagedSearch(state)
		return nil, nil
	}
	if hasMore && !cursor.valid && paging.sorted == nil {
		clearPagedSearch(state)
		return nil, errors.New("paged search continuation has no cursor")
	}

	var cookie []byte
	if hasMore {
		var err error
		cookie, err = newPagedResultsCookie()
		if err != nil {
			clearPagedSearch(state)
			return nil, err
		}
		if paging.retainedBytes == 0 {
			retainedBytes := pagedSortedSearchRetainedBytes(paging.sorted)
			if retainedBytes > 0 && !server.searchMemoryLimiter.tryAcquire(retainedBytes) {
				clearPagedSearch(state)
				return nil, errPagedSearchMemoryLimit
			}
			if retainedBytes > 0 {
				paging.retainedBytes = retainedBytes
				paging.releaseRetained = func() {
					server.searchMemoryLimiter.release(retainedBytes)
				}
			}
		}
		previous := state.pagedSearch
		state.pagedSearch = &pagedSearchState{
			cookie:             bytes.Clone(cookie),
			fingerprint:        paging.fingerprint,
			runtime:            paging.runtime,
			cursor:             cursor,
			sorted:             paging.sorted,
			count:              paging.count + entryCount,
			totalLimit:         paging.totalLimit,
			estimate:           paging.estimate,
			noEstimate:         paging.noEstimate,
			sortLease:          paging.sortLease,
			retainedBytes:      paging.retainedBytes,
			releaseRetained:    paging.releaseRetained,
			storageRevision:    paging.storageRevision,
			hasStorageRevision: paging.hasStorageRevision,
		}
		paging.sorted = nil
		paging.retainedBytes = 0
		paging.releaseRetained = nil
		releasePagedSearchState(state, previous, state.pagedSearch.sortLease)
	} else {
		clearPagedSearch(state)
	}
	return []ldapwire.Control{{
		OID: pagedResultsControlOID,
		Value: ldapwire.EncodePagedResultsValue(
			0,
			cookie,
		),
		HasValue: true,
	}}, nil
}

func (server *Server) currentStorageSnapshotRevision(
	ctx context.Context,
) (uint64, bool) {
	var revision uint64
	found := false
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		revision, found = storage.ReaderSnapshotRevision(reader)
		return nil
	})
	return revision, err == nil && found
}

func clearPagedSearch(state *connectionState) {
	releasePagedSearchState(state, state.pagedSearch, nil)
	state.pagedSearch = nil
}

func releasePagedSearchState(
	connection *connectionState,
	state *pagedSearchState,
	preservedSortLease *serverSideSortLease,
) {
	if state == nil {
		return
	}
	if state.sortLease != preservedSortLease {
		releaseServerSideSortLease(connection, state.sortLease)
	}
	if state.releaseRetained != nil {
		state.releaseRetained()
		state.releaseRetained = nil
	}
	state.retainedBytes = 0
}

func (context *pagedSearchContext) releaseRetainedMemory() {
	if context == nil || context.releaseRetained == nil {
		return
	}
	context.releaseRetained()
	context.releaseRetained = nil
	context.retainedBytes = 0
}

func pagedSortedSearchRetainedBytes(sorted *pagedSortedSearch) int64 {
	size := int64(unsafe.Sizeof(pagedSearchState{})) + pagedResultsCookieLength
	if sorted == nil {
		return size
	}
	size += int64(cap(sorted.items)) * int64(unsafe.Sizeof(pagedSortedItem{}))
	for _, item := range sorted.items {
		size += int64(len(item.dn) * 2)
	}
	return size
}

func clonePagedSortedSearch(source *pagedSortedSearch) *pagedSortedSearch {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.items = append([]pagedSortedItem(nil), source.items...)
	return &cloned
}

func newPagedResultsCookie() ([]byte, error) {
	cookie := make([]byte, pagedResultsCookieLength)
	if _, err := rand.Read(cookie); err != nil {
		return nil, err
	}
	return cookie, nil
}

func pagedSearchFingerprint(
	boundDN string,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
) [sha256.Size]byte {
	normalizedControls := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID == pagedResultsControlOID {
			control.Value = nil
			control.HasValue = true
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

func pagingResult(
	code ldapwire.ResultCode,
	diagnostic string,
) *ldapwire.Result {
	result := ldapwire.ResultError(code, diagnostic)
	return &result
}
