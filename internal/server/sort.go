package server

import (
	"sort"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const (
	defaultServerSideSortMax        = 8
	defaultServerSideSortMaxKeys    = 5
	defaultServerSideSortMaxPerConn = 5
)

type serverSideSortLimiter struct {
	mu         sync.Mutex
	max        int
	maxPerConn int
	active     int
}

type serverSideSortLease struct {
	limiters []*serverSideSortLimiter
	released bool
}

type serverSideSortRequest struct {
	keys     []ldapwire.SortKey
	critical bool
}

type resolvedSortKey struct {
	attribute    string
	orderingRule string
	reverse      bool
}

type serverSideSortContext struct {
	keys          []resolvedSortKey
	critical      bool
	result        ldapwire.ResultCode
	attributeType string
	forceResponse bool
}

type searchCandidate struct {
	selected directory.Entry
	readable directory.Entry
	route    int
	dn       string
	values   []sortValue
}

type sortValue struct {
	value   []byte
	present bool
}

func acquireServerSideSortLease(
	state *connectionState,
	databaseIndex int,
) (*serverSideSortLease, bool) {
	limiters := serverSideSortLimitersForDatabase(
		state.runtime.databases,
		databaseIndex,
	)
	if len(limiters) == 0 {
		return nil, true
	}
	for _, limiter := range limiters {
		if state.sortSessionCounts[limiter] >= limiter.maxPerConn {
			return nil, false
		}
	}

	for _, limiter := range limiters {
		limiter.mu.Lock()
	}
	allowed := true
	for _, limiter := range limiters {
		if limiter.active >= limiter.max {
			allowed = false
			break
		}
	}
	if allowed {
		for _, limiter := range limiters {
			limiter.active++
		}
	}
	for index := len(limiters) - 1; index >= 0; index-- {
		limiters[index].mu.Unlock()
	}
	if !allowed {
		return nil, false
	}
	if state.sortSessionCounts == nil {
		state.sortSessionCounts = make(map[*serverSideSortLimiter]int)
	}
	for _, limiter := range limiters {
		state.sortSessionCounts[limiter]++
	}
	return &serverSideSortLease{limiters: limiters}, true
}

func releaseServerSideSortLease(
	state *connectionState,
	lease *serverSideSortLease,
) {
	if lease == nil || lease.released {
		return
	}
	lease.released = true
	for _, limiter := range lease.limiters {
		if count := state.sortSessionCounts[limiter]; count <= 1 {
			delete(state.sortSessionCounts, limiter)
		} else {
			state.sortSessionCounts[limiter] = count - 1
		}
		limiter.mu.Lock()
		limiter.active--
		limiter.mu.Unlock()
	}
	if len(state.sortSessionCounts) == 0 {
		state.sortSessionCounts = nil
	}
}

func serverSideSortBusyResult() ldapwire.Result {
	return ldapwire.ResultError(
		ldapwire.ResultBusy,
		"Other sort requests already in progress",
	)
}

func prepareServerSideSort(
	registry *schema.Registry,
	request *serverSideSortRequest,
	maxKeys int,
) (*serverSideSortContext, *ldapwire.Result) {
	if request == nil {
		return nil, nil
	}
	context := &serverSideSortContext{
		critical: request.critical,
		result:   ldapwire.ResultSuccess,
	}
	if maxKeys >= 0 && len(request.keys) > maxKeys {
		return nil, sortOperationFailure(
			ldapwire.ResultUnwillingToPerform,
			"too many sort keys",
		)
	}

	for _, key := range request.keys {
		if _, ok := registry.AttributeType(key.AttributeType); !ok {
			return nil, sortOperationFailure(
				ldapwire.ResultNoSuchAttribute,
				"unrecognized attribute type in sort key",
			)
		}

		orderingRule, err := registry.OrderingRule(
			key.AttributeType,
			key.OrderingRule,
		)
		if err != nil {
			return nil, sortOperationFailure(
				ldapwire.ResultInappropriateMatching,
				"no ordering rule for sort key",
			)
		}
		context.keys = append(context.keys, resolvedSortKey{
			attribute:    key.AttributeType,
			orderingRule: orderingRule,
			reverse:      key.Reverse,
		})
	}
	return context, nil
}

func sortOperationFailure(
	code ldapwire.ResultCode,
	diagnostic string,
) *ldapwire.Result {
	result := ldapwire.ResultError(code, diagnostic)
	return &result
}

func (context *serverSideSortContext) fail(
	result ldapwire.ResultCode,
	attributeType string,
) {
	context.keys = nil
	context.result = result
	context.attributeType = attributeType
	context.forceResponse = context.forceResponse || context.critical
}

func (context *serverSideSortContext) active() bool {
	return context != nil && context.result == ldapwire.ResultSuccess
}

func sortSearchCandidates(
	registry *schema.Registry,
	context *serverSideSortContext,
	candidates []searchCandidate,
) error {
	if !context.active() {
		return nil
	}
	for candidateIndex := range candidates {
		candidates[candidateIndex].values = make(
			[]sortValue,
			len(context.keys),
		)
		for keyIndex, key := range context.keys {
			value, present, err := leastSortValue(
				registry,
				candidates[candidateIndex].readable,
				key,
			)
			if err != nil {
				return err
			}
			candidates[candidateIndex].values[keyIndex] = sortValue{
				value:   value,
				present: present,
			}
		}
	}
	if len(candidates) < 2 {
		return nil
	}

	var compareErr error
	sort.SliceStable(candidates, func(leftIndex, rightIndex int) bool {
		if compareErr != nil {
			return false
		}
		comparison, err := compareSearchCandidates(
			registry,
			context.keys,
			candidates[leftIndex],
			candidates[rightIndex],
		)
		if err != nil {
			compareErr = err
			return false
		}
		return comparison < 0
	})
	return compareErr
}

func leastSortValue(
	registry *schema.Registry,
	entry directory.Entry,
	key resolvedSortKey,
) ([]byte, bool, error) {
	values := sortAttributeValues(registry, entry, key.attribute)
	if len(values) == 0 {
		return nil, false, nil
	}
	for _, value := range values {
		if _, err := registry.CompareOrdering(
			key.attribute,
			key.orderingRule,
			value,
			value,
		); err != nil {
			return nil, false, err
		}
	}
	least := values[0]
	for _, candidate := range values[1:] {
		comparison, err := registry.CompareOrdering(
			key.attribute,
			key.orderingRule,
			candidate,
			least,
		)
		if err != nil {
			return nil, false, err
		}
		if comparison < 0 {
			least = candidate
		}
	}
	return least, true, nil
}

func sortAttributeValues(
	registry *schema.Registry,
	entry directory.Entry,
	description string,
) [][]byte {
	if values := entry.Values(description); len(values) > 0 {
		return values
	}
	if strings.Contains(description, ";") {
		return nil
	}
	target, ok := registry.AttributeType(description)
	if !ok {
		return nil
	}
	var values [][]byte
	for _, attribute := range entry.Attributes {
		if strings.Contains(attribute.Description, ";") {
			continue
		}
		candidate, ok := registry.AttributeType(attribute.Description)
		if ok && strings.EqualFold(candidate.OID, target.OID) {
			values = append(values, attribute.Values...)
		}
	}
	return values
}

func compareSearchCandidates(
	registry *schema.Registry,
	keys []resolvedSortKey,
	left,
	right searchCandidate,
) (int, error) {
	for index, key := range keys {
		leftValue := left.values[index]
		rightValue := right.values[index]
		var comparison int
		switch {
		case !leftValue.present && !rightValue.present:
			continue
		case !leftValue.present:
			comparison = 1
		case !rightValue.present:
			comparison = -1
		default:
			var err error
			comparison, err = registry.CompareOrdering(
				key.attribute,
				key.orderingRule,
				leftValue.value,
				rightValue.value,
			)
			if err != nil {
				return 0, err
			}
		}
		if comparison != 0 {
			if key.reverse {
				comparison = -comparison
			}
			return comparison, nil
		}
	}
	return 0, nil
}

func serverSideSortResponseControl(
	context *serverSideSortContext,
	searchResult ldapwire.Result,
	entryCount int,
) []ldapwire.Control {
	if context == nil {
		return nil
	}
	if context.result == ldapwire.ResultSuccess {
		if !context.forceResponse &&
			(searchResult.Code != ldapwire.ResultSuccess || entryCount == 0) {
			return nil
		}
	} else if !context.forceResponse &&
		(searchResult.Code != ldapwire.ResultSuccess || entryCount == 0) {
		return nil
	}
	return []ldapwire.Control{{
		OID: sortResponseControlOID,
		Value: ldapwire.EncodeSortResultValue(
			context.result,
			context.attributeType,
		),
		HasValue: true,
	}}
}
