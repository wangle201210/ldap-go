package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const pagedResultsCookieLength = 16

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
	route int
	dn    string
}

type pagedSortedSearch struct {
	items     []pagedSortedItem
	offset    int
	truncated bool
}

type pagedSearchState struct {
	cookie      []byte
	fingerprint [sha256.Size]byte
	runtime     *runtimeState
	cursor      pagedSearchCursor
	sorted      *pagedSortedSearch
	count       int
	sortLease   *serverSideSortLease
}

type pagedSearchContext struct {
	size        int
	fingerprint [sha256.Size]byte
	runtime     *runtimeState
	cursor      pagedSearchCursor
	sorted      *pagedSortedSearch
	count       int
	abandoned   bool
	sortLease   *serverSideSortLease
}

func preparePagedSearch(
	state *connectionState,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
	paging *pagedResultsRequest,
	totalLimit int,
) (*pagedSearchContext, *ldapwire.Result) {
	if paging == nil {
		return nil, nil
	}

	fingerprint := pagedSearchFingerprint(
		state.boundDN,
		request,
		controls,
	)
	if len(paging.cookie) == 0 {
		clearPagedSearch(state)
		if paging.size == 0 || paging.size >= totalLimit {
			return nil, nil
		}
		return &pagedSearchContext{
			size:        paging.size,
			fingerprint: fingerprint,
			runtime:     state.runtime,
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

	context := &pagedSearchContext{
		size:        paging.size,
		fingerprint: fingerprint,
		runtime:     state.runtime,
		cursor:      current.cursor,
		sorted:      clonePagedSortedSearch(current.sorted),
		count:       current.count,
		sortLease:   current.sortLease,
	}
	if paging.size == 0 {
		clearPagedSearch(state)
		context.abandoned = true
	}
	return context, nil
}

func completePagedSearch(
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
		state.pagedSearch = &pagedSearchState{
			cookie:      bytes.Clone(cookie),
			fingerprint: paging.fingerprint,
			runtime:     paging.runtime,
			cursor:      cursor,
			sorted:      clonePagedSortedSearch(paging.sorted),
			count:       paging.count + entryCount,
			sortLease:   paging.sortLease,
		}
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

func clearPagedSearch(state *connectionState) {
	if state.pagedSearch != nil {
		releaseServerSideSortLease(state, state.pagedSearch.sortLease)
	}
	state.pagedSearch = nil
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
