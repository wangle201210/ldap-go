package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type metaSearchTargetOutcome struct {
	attempt chainAttempt
}

type metaSearchEvent struct {
	target        int
	entryObserved bool
	packet        *ber.Packet
	outcome       *metaSearchTargetOutcome
}

var errMetaSearchStartupStopped = errors.New("back-meta search stopped during target startup")

type metaSearchStartup struct {
	mu           sync.Mutex
	remaining    int
	stopOnError  bool
	failureIndex int
	ready        chan struct{}
}

func newMetaSearchStartup(targets int, stopOnError bool) *metaSearchStartup {
	return &metaSearchStartup{
		remaining:    targets,
		stopOnError:  stopOnError,
		failureIndex: -1,
		ready:        make(chan struct{}),
	}
}

func (startup *metaSearchStartup) arrive(target int, failed bool) {
	startup.mu.Lock()
	defer startup.mu.Unlock()
	if failed && (startup.failureIndex < 0 || target < startup.failureIndex) {
		startup.failureIndex = target
	}
	startup.remaining--
	if startup.remaining == 0 {
		close(startup.ready)
	}
}

func (startup *metaSearchStartup) wait(ctx context.Context) error {
	select {
	case <-startup.ready:
		startup.mu.Lock()
		failed := startup.failureIndex >= 0
		startup.mu.Unlock()
		if startup.stopOnError && failed {
			return errMetaSearchStartupStopped
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (startup *metaSearchStartup) reportsFailure(target int) bool {
	startup.mu.Lock()
	defer startup.mu.Unlock()
	return !startup.stopOnError || startup.failureIndex == target
}

func (server *Server) runMetaBackendSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	plans []metaSearchPlan,
	limit int,
) (bool, error) {
	searchCtx, cancel := context.WithCancel(ctx)
	if request.TimeLimit > 0 {
		searchCtx, cancel = context.WithTimeout(
			ctx,
			time.Duration(request.TimeLimit)*time.Second,
		)
	}
	defer cancel()

	events := make(chan metaSearchEvent)
	startup := newMetaSearchStartup(
		len(plans),
		database.metaBackend.onError == "stop",
	)
	var workers sync.WaitGroup
	workers.Add(len(plans))
	for index, plan := range plans {
		index := index
		plan := plan
		go func() {
			defer workers.Done()
			server.runMetaSearchTarget(
				searchCtx,
				state,
				database,
				request.TypesOnly,
				message,
				index,
				plan,
				startup,
				events,
			)
		}()
	}
	go func() {
		workers.Wait()
		close(events)
	}()

	combined := ldapwire.Result{Code: ldapwire.ResultNoSuchObject}
	validResult := false
	entryCount := 0
	limitReached := false
	stopFailed := false
	var stopFailure *ldapwire.Result
	outcomes := make([]*chainAttempt, len(plans))
	var writeErr error

	for event := range events {
		if event.packet != nil || event.entryObserved {
			if limitReached || stopFailed || writeErr != nil {
				continue
			}
			if event.entryObserved {
				if limit > 0 && entryCount >= limit {
					limitReached = true
					cancel()
					continue
				}
				entryCount++
			}
			if event.packet == nil {
				continue
			}
			if metaPacketTag(event.packet) == ldapwire.ApplicationSearchResultEntry {
				validResult = true
			}
			writeErr = server.writeChainedPackets(
				connection,
				message,
				[]*ber.Packet{event.packet},
			)
			if writeErr != nil {
				cancel()
			} else if tracker, ok := connection.(interface {
				observeMetaBackendResponse()
			}); ok {
				tracker.observeMetaBackendResponse()
			}
			continue
		}
		if event.outcome == nil || limitReached || stopFailed || writeErr != nil {
			continue
		}
		if metaBackendCancelCompletesNormally(connection) {
			continue
		}
		attempt := event.outcome.attempt
		outcomes[event.target] = &attempt
		if limit > 0 && entryCount >= limit &&
			attempt.result.Code == ldapwire.ResultSizeLimitExceeded {
			limitReached = true
			cancel()
			continue
		}
		if !metaSearchResultIsError(attempt.result.Code) {
			continue
		}
		if database.metaBackend.onError == "stop" {
			stopFailed = true
			failure := attempt.result
			stopFailure = &failure
			cancel()
		}
	}

	if writeErr != nil {
		return true, writeErr
	}
	if ctx.Err() != nil && !metaBackendCancelCompletesNormally(connection) {
		return true, nil
	}
	timeLimitReached := errors.Is(searchCtx.Err(), context.DeadlineExceeded)
	terminalLimit := limitReached || timeLimitReached
	lateCancel := metaBackendCancelCompletesNormally(connection)
	if lateCancel {
		combined = ldapwire.Result{Code: ldapwire.ResultNoSuchObject}
		stopFailed = false
		stopFailure = nil
		outcomes = nil
	}
	var reportFailure *ldapwire.Result
	if !stopFailed {
		for _, attempt := range outcomes {
			if attempt == nil {
				continue
			}
			mergeMetaSearchResult(&combined, attempt.result, &validResult)
			if reportFailure == nil && metaSearchResultIsError(attempt.result.Code) {
				failure := attempt.result
				reportFailure = &failure
			}
		}
	}
	switch {
	case limitReached:
		combined.Code = ldapwire.ResultSizeLimitExceeded
	case timeLimitReached:
		combined.Code = ldapwire.ResultTimeLimitExceeded
	case stopFailed && stopFailure != nil:
		combined = *stopFailure
	default:
		finalizeMetaSearchResult(
			&combined,
			validResult,
			database.metaBackend.onError,
			reportFailure,
			terminalLimit,
		)
	}
	done, err := metaSearchDonePacket(combined)
	if err != nil {
		return true, err
	}
	return true, server.writeChainedPackets(connection, message, []*ber.Packet{done})
}

func metaBackendCancelCompletesNormally(connection net.Conn) bool {
	tracker, ok := connection.(interface {
		metaBackendCancelCompletesNormally() bool
	})
	return ok && tracker.metaBackendCancelCompletesNormally()
}

func (server *Server) runMetaSearchTarget(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	typesOnly bool,
	message ldapwire.Message,
	targetIndex int,
	plan metaSearchPlan,
	startup *metaSearchStartup,
	events chan<- metaSearchEvent,
) {
	var startupOnce sync.Once
	started := false
	arrive := func(failed bool) {
		startupOnce.Do(func() {
			started = !failed
			startup.arrive(targetIndex, failed)
		})
	}
	reportStartupFailure := func(attempt chainAttempt) bool {
		arrive(true)
		if startup.wait(ctx) != nil && !startup.reportsFailure(targetIndex) {
			return false
		}
		server.sendMetaSearchOutcome(ctx, events, targetIndex, attempt)
		return true
	}
	candidate := message
	candidate.Request = plan.request
	mapped, err := mapMetaRequestToRemote(plan.target.rwm, candidate)
	if err != nil {
		reportStartupFailure(chainAttempt{
			result:    metaBackendMappingFailure(err),
			hasResult: true,
		})
		return
	}
	mapped.Controls = metaSearchControlsWithoutPaging(mapped.Controls)
	pageSize := plan.target.clientPr
	nextPageSize := pageSize
	requestPage := pageSize > 0
	var pageCookie []byte
	var attempt chainAttempt
	for {
		candidate := mapped
		candidate.Controls = cloneLDAPControls(mapped.Controls)
		if requestPage {
			candidate.Controls = append(candidate.Controls, ldapwire.Control{
				OID:      pagedResultsControlOID,
				Critical: true,
				Value: ldapwire.EncodePagedResultsValue(
					nextPageSize,
					pageCookie,
				),
				HasValue: true,
			})
		}

		pageEntries := 0
		sink := func(packet *ber.Packet) error {
			entryObserved := metaPacketTag(packet) == ldapwire.ApplicationSearchResultEntry
			if entryObserved {
				pageEntries++
			}
			mappedPacket, mapErr := mapMetaResponsePacket(
				plan.target.rwm,
				packet,
				ldapwire.Result{},
			)
			if mapErr != nil {
				return mapErr
			}
			server.cacheMetaSearchEntries(
				database.metaBackend,
				plan.target,
				[]*ber.Packet{mappedPacket},
			)
			packets, filterErr := server.filterMetaSearchPackets(
				ctx,
				state,
				database,
				[]*ber.Packet{mappedPacket},
				typesOnly,
			)
			if filterErr != nil {
				return filterErr
			}
			if entryObserved && len(packets) == 0 {
				select {
				case events <- metaSearchEvent{
					target:        targetIndex,
					entryObserved: true,
				}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			for index, filtered := range packets {
				select {
				case events <- metaSearchEvent{
					target:        targetIndex,
					entryObserved: entryObserved && index == 0,
					packet:        filtered,
				}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}
		var failure *ldapwire.Result
		attempt, _, failure = server.executeMetaBackendOperationWithHooks(
			ctx,
			state,
			database,
			plan.target,
			candidate,
			sink,
			func() error {
				arrive(false)
				return startup.wait(ctx)
			},
		)
		if !started {
			if failure != nil {
				attempt = chainAttempt{result: *failure, hasResult: true}
			} else if !attempt.hasResult && attempt.transportErr != nil {
				attempt.result = ldapwire.ResultError(
					ldapwire.ResultUnavailable,
					ldapBackendUnavailableDiagnostic,
				)
				attempt.hasResult = true
			}
			reportStartupFailure(attempt)
			return
		}
		if errors.Is(attempt.transportErr, errMetaSearchStartupStopped) {
			return
		}
		if failure != nil {
			attempt = chainAttempt{result: *failure, hasResult: true}
			break
		}

		paged, pagingErr := metaSearchPagedResponse(attempt)
		if pagingErr != nil {
			attempt.result = ldapwire.ResultError(
				ldapwire.ResultOther,
				pagingErr.Error(),
			)
			attempt.hasResult = true
			break
		}
		if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess && paged != nil {
			if pageSize == 0 {
				attempt.result = ldapwire.ResultError(
					ldapwire.ResultOther,
					"unsolicited paged results response",
				)
				break
			}
			responseSize, cookie, decodeErr := ldapwire.DecodePagedResultsValue(paged.Value)
			if decodeErr != nil {
				attempt.result = ldapwire.ResultError(
					ldapwire.ResultOther,
					"invalid paged results response",
				)
				break
			}
			if len(cookie) > 0 {
				pageCookie = bytes.Clone(cookie)
				nextPageSize = pageSize
				if pageSize < 0 {
					nextPageSize = responseSize
					if nextPageSize == 0 {
						nextPageSize = pageEntries
					}
				}
				requestPage = true
				continue
			}
		}
		break
	}
	if err == nil {
		attempt, err = mapMetaAttemptToLocal(plan.target.rwm, attempt)
	}
	if err != nil {
		attempt = chainAttempt{
			result:    metaBackendMappingFailure(err),
			hasResult: true,
		}
	}
	if !attempt.hasResult {
		attempt.result = ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			ldapBackendUnavailableDiagnostic,
		)
		attempt.hasResult = true
	}
	server.sendMetaSearchOutcome(ctx, events, targetIndex, attempt)
}

func metaSearchControlsWithoutPaging(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID == pagedResultsControlOID {
			continue
		}
		control.Value = bytes.Clone(control.Value)
		filtered = append(filtered, control)
	}
	return filtered
}

func metaSearchPagedResponse(attempt chainAttempt) (*ldapwire.Control, error) {
	for index := len(attempt.packets) - 1; index >= 0; index-- {
		packet := attempt.packets[index]
		if metaPacketTag(packet) != ldapwire.ApplicationSearchResultDone {
			continue
		}
		controls, err := decodePBindResponseControls(packet)
		if err != nil {
			return nil, err
		}
		var paged *ldapwire.Control
		for _, control := range controls {
			if control.OID != pagedResultsControlOID {
				continue
			}
			if paged != nil {
				return nil, fmt.Errorf("duplicate paged results response control")
			}
			copy := control
			copy.Value = bytes.Clone(control.Value)
			paged = &copy
		}
		return paged, nil
	}
	return nil, nil
}

func (server *Server) sendMetaSearchOutcome(
	ctx context.Context,
	events chan<- metaSearchEvent,
	target int,
	attempt chainAttempt,
) {
	select {
	case events <- metaSearchEvent{
		target:  target,
		outcome: &metaSearchTargetOutcome{attempt: attempt},
	}:
	case <-ctx.Done():
	}
}
