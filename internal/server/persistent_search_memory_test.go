package server

import (
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestPagedSearchPersistentMemoryLeaseLifecycle(t *testing.T) {
	instance := &Server{searchMemoryLimiter: newResourceByteLimiter(1 << 20)}
	runtime := &runtimeState{}
	state := &connectionState{runtime: runtime}
	request := ldapwire.SearchRequest{}
	fingerprint := pagedSearchFingerprint("", request, nil)
	context := &pagedSearchContext{
		size:        1,
		fingerprint: fingerprint,
		runtime:     runtime,
		totalLimit:  10,
		sorted: &pagedSortedSearch{items: []pagedSortedItem{
			{route: 0, dn: "uid=one,dc=example,dc=com"},
			{route: 0, dn: "uid=two,dc=example,dc=com"},
		}},
	}
	controls, err := instance.completePagedSearch(
		state,
		context,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		1,
		pagedSearchCursor{},
		true,
	)
	if err != nil {
		t.Fatalf("completePagedSearch(): %v", err)
	}
	if len(controls) != 1 || state.pagedSearch == nil {
		t.Fatalf("paged state = %#v, controls = %#v", state.pagedSearch, controls)
	}
	retained := instance.searchMemoryLimiter.active.Load()
	if retained <= 0 || context.releaseRetained != nil {
		t.Fatalf("retained bytes = %d, context release = %v", retained, context.releaseRetained != nil)
	}

	instance.searchMemoryLimiter.maximum = retained*2 - 1
	continuation, failure := instance.preparePagedSearch(
		state,
		request,
		nil,
		&pagedResultsRequest{size: 1, cookie: state.pagedSearch.cookie},
		databaseSearchExecutionLimits{pageTotal: 10},
	)
	if continuation != nil || failure == nil || failure.Code != ldapwire.ResultAdminLimitExceeded {
		t.Fatalf("continuation = %#v, failure = %#v", continuation, failure)
	}
	if got := instance.searchMemoryLimiter.active.Load(); got != 0 {
		t.Fatalf("retained bytes after rejected clone = %d", got)
	}
}

func TestVirtualListViewPersistentMemoryLeaseLifecycle(t *testing.T) {
	instance := &Server{searchMemoryLimiter: newResourceByteLimiter(1 << 20)}
	runtime := &runtimeState{}
	state := &connectionState{runtime: runtime}
	context := &virtualListViewContext{runtime: runtime}
	candidates := []searchCandidate{{
		dn:          "uid=one,dc=example,dc=com",
		cursorKey:   "cursor-one",
		identityKey: "identity-one",
		values:      []sortValue{{value: []byte("one"), present: true}},
	}}
	view, err := instance.startVirtualListView(state, context, candidates, nil)
	if err != nil {
		t.Fatalf("startVirtualListView(): %v", err)
	}
	if view == nil || instance.searchMemoryLimiter.active.Load() <= 0 {
		t.Fatalf("VLV state = %#v, retained = %d", view, instance.searchMemoryLimiter.active.Load())
	}
	clearVirtualListViews(state)
	if got := instance.searchMemoryLimiter.active.Load(); got != 0 {
		t.Fatalf("retained bytes after VLV clear = %d", got)
	}

	limited := &Server{searchMemoryLimiter: newResourceByteLimiter(1)}
	_, err = limited.startVirtualListView(
		&connectionState{runtime: runtime},
		&virtualListViewContext{runtime: runtime},
		candidates,
		nil,
	)
	if !errors.Is(err, errVirtualListViewMemoryLimit) {
		t.Fatalf("limited startVirtualListView() = %v", err)
	}
	if got := limited.searchMemoryLimiter.active.Load(); got != 0 {
		t.Fatalf("limited VLV retained bytes = %d", got)
	}
}
