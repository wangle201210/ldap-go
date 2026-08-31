package lloadd

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	MonitorBaseDN          = "cn=Monitor"
	MonitorLoadBalancerDN  = "cn=Load Balancer," + MonitorBaseDN
	monitorIncomingDN      = "cn=Incoming Connections," + MonitorLoadBalancerDN
	monitorOperationsDN    = "cn=Operations," + MonitorLoadBalancerDN
	monitorBackendTiersDN  = "cn=Backend Tiers," + MonitorLoadBalancerDN
	monitorPagedResultsOID = "1.2.840.113556.1.4.319"
	monitorManageDsaITOID  = "2.16.840.1.113730.3.4.2"
	monitorAssertionOID    = "1.3.6.1.1.12"
	monitorSortRequestOID  = "1.2.840.113556.1.4.473"
	monitorSortResponseOID = "1.2.840.113556.1.4.474"
	monitorVLVRequestOID   = "2.16.840.1.113730.3.4.9"
	monitorVLVResponseOID  = "2.16.840.1.113730.3.4.10"

	monitorSnapshotIDLength        = 16
	monitorPagingCookieLength      = monitorSnapshotIDLength + 4
	monitorSnapshotLimit           = 4
	monitorSnapshotEntryLimit      = 2048
	monitorSnapshotByteLimit       = int64(4 << 20)
	monitorProxySnapshotLimit      = int64(32 << 20)
	monitorSnapshotTTL             = time.Minute
	monitorSnapshotCleanupInterval = 15 * time.Second
)

const (
	monitorVLVSortControlMissing ldapwire.ResultCode = 76
	monitorVLVOffsetRangeError   ldapwire.ResultCode = 77
)

type monitorRuntimeState struct {
	generation uint64
	startedAt  time.Time
}

var monitorGenerationSequence atomic.Uint64

type monitorSnapshot struct {
	id          []byte
	fingerprint [sha256.Size]byte
	entries     []directory.Entry
	sortEntries []directory.Entry
	sortKeys    []monitorSortKey
	sortResult  ldapwire.ResultCode
	result      ldapwire.ResultCode
	expires     time.Time
	sizeBytes   int64
}

type monitorSortKey struct {
	attribute    string
	orderingRule string
	reverse      bool
}

type monitorSearchControls struct {
	assertion *directory.Filter
	paging    *monitorPagingRequest
	sort      *monitorSortRequest
	vlv       *monitorVLVRequest
}

type monitorPagingRequest struct {
	size   int
	cookie []byte
}

type monitorSortRequest struct {
	keys     []ldapwire.SortKey
	critical bool
}

type monitorVLVRequest struct {
	request  ldapwire.VirtualListViewRequest
	critical bool
}

type monitorCounters struct {
	mu        sync.Mutex
	received  atomic.Uint64
	forwarded atomic.Uint64
	rejected  atomic.Uint64
	completed atomic.Uint64
	failed    atomic.Uint64
	pending   atomic.Uint64
	abandoned atomic.Uint64
}

type ProxyMonitorCounters struct {
	Received  uint64
	Forwarded uint64
	Rejected  uint64
	Completed uint64
	Failed    uint64
	Pending   uint64
}

func (counters *monitorCounters) snapshotWithAbandoned() (
	ProxyMonitorCounters,
	uint64,
) {
	if counters == nil {
		return ProxyMonitorCounters{}, 0
	}
	counters.mu.Lock()
	defer counters.mu.Unlock()
	return ProxyMonitorCounters{
		Received:  counters.received.Load(),
		Forwarded: counters.forwarded.Load(),
		Rejected:  counters.rejected.Load(),
		Completed: counters.completed.Load(),
		Failed:    counters.failed.Load(),
		Pending:   counters.pending.Load(),
	}, counters.abandoned.Load()
}

func (counters *monitorCounters) begin() {
	counters.mu.Lock()
	counters.received.Add(1)
	counters.pending.Add(1)
	counters.mu.Unlock()
}

func (counters *monitorCounters) forwardedOperation() {
	counters.mu.Lock()
	counters.forwarded.Add(1)
	counters.mu.Unlock()
}

func (counters *monitorCounters) complete(abandoned bool) {
	counters.terminal(&counters.completed, abandoned)
}

func (counters *monitorCounters) fail() {
	counters.terminal(&counters.failed, false)
}

func (counters *monitorCounters) reject() {
	counters.terminal(&counters.rejected, false)
}

func (counters *monitorCounters) terminal(result *atomic.Uint64, abandoned bool) {
	counters.mu.Lock()
	if counters.pending.Load() == 0 {
		counters.mu.Unlock()
		return
	}
	counters.pending.Add(^uint64(0))
	result.Add(1)
	if abandoned {
		counters.abandoned.Add(1)
	}
	counters.mu.Unlock()
}

func monitorOperationIndex(tag uint64) int {
	if tag == ldapwire.ApplicationBindRequest {
		return 0
	}
	return 1
}

func (client *clientConnection) recordMonitorReceived(tag uint64) {
	client.monitor.begin()
	client.proxy.operations[monitorOperationIndex(tag)].begin()
}

func (client *clientConnection) recordMonitorRejected(tag uint64) {
	client.monitor.fail()
	client.proxy.operations[monitorOperationIndex(tag)].reject()
}

func (client *clientConnection) recordMonitorCompleted(tag uint64) {
	client.monitor.complete(false)
	client.proxy.operations[monitorOperationIndex(tag)].complete(false)
}

func (client *clientConnection) recordMonitorFailed(tag uint64) {
	client.monitor.fail()
	client.proxy.operations[monitorOperationIndex(tag)].fail()
}

func (operation *proxyOperation) recordMonitorForwarded() {
	index := monitorOperationIndex(operation.requestTag)
	operation.client.monitor.forwardedOperation()
	operation.client.proxy.operations[index].forwardedOperation()
	if operation.upstream != nil {
		operation.upstream.monitor.begin()
		operation.upstream.backend.monitor.begin()
	}
}

func (operation *proxyOperation) recordMonitorFinished(forwarded, response bool) {
	index := monitorOperationIndex(operation.requestTag)
	if !forwarded {
		operation.client.monitor.fail()
		operation.client.proxy.operations[index].reject()
		return
	}
	if response {
		operation.mu.Lock()
		abandoned := operation.abandoning
		operation.mu.Unlock()
		operation.client.monitor.complete(abandoned)
		operation.client.proxy.operations[index].complete(abandoned)
		operation.upstream.monitor.complete(abandoned)
		operation.upstream.backend.monitor.complete(abandoned)
		return
	}
	operation.client.monitor.fail()
	operation.client.proxy.operations[index].fail()
	operation.upstream.monitor.fail()
	operation.upstream.backend.monitor.fail()
}

type ProxyMonitorSnapshot struct {
	Generation          uint64
	StartedAt           time.Time
	Uptime              time.Duration
	IncomingConnections int
	OutgoingConnections int
	PendingOperations   int
	Operations          []ProxyMonitorOperation
	Incoming            []ProxyMonitorConnection
	Backends            []ProxyMonitorBackend
}

type ProxyMonitorOperation struct {
	Name      string
	Counters  ProxyMonitorCounters
	Abandoned uint64
}

type ProxyMonitorConnection struct {
	ID        string
	Type      string
	State     string
	Pending   int
	Created   time.Time
	Counters  ProxyMonitorCounters
	Abandoned uint64
}

type ProxyMonitorBackend struct {
	TierID             string
	BackendID          string
	URI                string
	PendingOperations  int
	ActiveConnections  int
	PendingConnections int
	Counters           ProxyMonitorCounters
	Abandoned          uint64
	Connections        []ProxyMonitorConnection
}

// MonitorSnapshot returns a credential-free point-in-time topology view.
func (proxy *Proxy) MonitorSnapshot() ProxyMonitorSnapshot {
	if proxy == nil {
		return ProxyMonitorSnapshot{}
	}
	proxy.mu.Lock()
	clients := make([]*clientConnection, 0, len(proxy.clients))
	for client := range proxy.clients {
		clients = append(clients, client)
	}
	upstreams := make(map[string]*upstreamConnection, len(proxy.upstreams))
	for id, upstream := range proxy.upstreams {
		upstreams[id] = upstream
	}
	proxy.mu.Unlock()

	scheduler := proxy.scheduler.Snapshot()
	runtimeState := proxy.monitorRuntimeState()
	bindCounters, bindAbandoned := proxy.operations[0].snapshotWithAbandoned()
	otherCounters, otherAbandoned := proxy.operations[1].snapshotWithAbandoned()
	result := ProxyMonitorSnapshot{
		Generation:          runtimeState.generation,
		StartedAt:           runtimeState.startedAt,
		Uptime:              max(time.Since(runtimeState.startedAt), 0),
		IncomingConnections: len(clients),
		Operations: []ProxyMonitorOperation{
			{Name: "Bind", Counters: bindCounters, Abandoned: bindAbandoned},
			{Name: "Other", Counters: otherCounters, Abandoned: otherAbandoned},
		},
	}
	for _, client := range clients {
		client.mu.Lock()
		if !client.closed {
			counters, abandoned := client.monitor.snapshotWithAbandoned()
			state := "ready"
			if client.draining {
				state = "closing"
			} else if client.binding {
				state = "binding"
			} else if len(client.ops) != 0 {
				state = "active"
			}
			result.Incoming = append(result.Incoming, ProxyMonitorConnection{
				ID:        strconv.FormatUint(client.id, 10),
				Type:      "regular",
				State:     state,
				Pending:   int(counters.Pending),
				Created:   client.created,
				Counters:  counters,
				Abandoned: abandoned,
			})
		}
		client.mu.Unlock()
	}
	sort.Slice(result.Incoming, func(i, j int) bool { return result.Incoming[i].ID < result.Incoming[j].ID })
	byID := make(map[string]*ProxyMonitorBackend, len(scheduler.Backends))
	for tierIndex, tier := range proxy.config.Tiers {
		for backendIndex, backend := range tier.Backends {
			id := fmt.Sprintf("tier-%d-backend-%d", tierIndex, backendIndex)
			counters, abandoned := proxy.tiers[tierIndex].backends[backendIndex].monitor.snapshotWithAbandoned()
			result.Backends = append(result.Backends, ProxyMonitorBackend{
				TierID:    fmt.Sprintf("tier-%d", tierIndex),
				BackendID: id,
				URI:       backend.URI,
				Counters:  counters,
				Abandoned: abandoned,
			})
			byID[id] = &result.Backends[len(result.Backends)-1]
		}
	}
	for _, backend := range scheduler.Backends {
		if monitored := byID[backend.BackendID]; monitored != nil {
			monitored.PendingOperations = int(monitored.Counters.Pending)
			result.PendingOperations += monitored.PendingOperations
		}
	}
	for _, connection := range scheduler.Connections {
		monitored := byID[connection.BackendID]
		if monitored == nil {
			continue
		}
		if connection.State == ConnectionUnavailable {
			monitored.PendingConnections++
			continue
		}
		monitored.ActiveConnections++
		result.OutgoingConnections++
		kind := "regular"
		if connection.Pool == PoolBind {
			kind = "bind"
		}
		state := "ready"
		if connection.Pending != 0 {
			state = "active"
		}
		created := time.Time{}
		counters := ProxyMonitorCounters{}
		abandoned := uint64(0)
		if upstream := upstreams[connection.ID]; upstream != nil {
			upstream.mu.Lock()
			if upstream.closed {
				state = "closing"
			}
			created = upstream.created
			counters, abandoned = upstream.monitor.snapshotWithAbandoned()
			upstream.mu.Unlock()
		}
		monitored.Connections = append(monitored.Connections, ProxyMonitorConnection{
			ID:        connection.ID,
			Type:      kind,
			State:     state,
			Pending:   int(counters.Pending),
			Created:   created,
			Counters:  counters,
			Abandoned: abandoned,
		})
	}
	return result
}

func (proxy *Proxy) monitorRuntimeState() monitorRuntimeState {
	if proxy != nil {
		return proxy.monitorRuntime
	}
	return monitorRuntimeState{}
}

func (client *clientConnection) handleMonitorSearch(frame proxyFrame) (bool, bool) {
	if frame.ProtocolTag != ldapwire.ApplicationSearchRequest {
		return false, false
	}
	message, err := ldapwire.ReadMessage(
		bytes.NewReader(frame.Raw),
		client.proxy.config.ClientMaxMessageSize,
	)
	if err != nil {
		return false, false
	}
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok || !isMonitorSearchBase(request.BaseDN) {
		return false, false
	}

	controls, result := parseMonitorSearchControls(message.Controls)
	if result != nil {
		return true, client.sendMonitorDone(
			message.ID,
			*result,
			monitorFailureControls(controls, result.Code)...,
		)
	}
	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return true, client.sendMonitorDone(message.ID, ldapwire.Result{
			Code:              ldapwire.ResultInvalidDNSyntax,
			DiagnosticMessage: "invalid monitor search base",
		})
	}

	entries := client.proxy.monitorEntries()
	reader := newMonitorEntryReader(entries)
	baseEntry, baseExists := reader.lookup(base)
	if !baseExists {
		return true, client.sendMonitorDone(message.ID, monitorMissingBaseResult(base, entries))
	}
	subject := client.monitorACLSubject()
	if !client.monitorAllowed(reader, subject, baseEntry, "entry", nil, acl.Search) {
		code := ldapwire.ResultNoSuchObject
		if client.monitorAllowed(reader, subject, baseEntry, "entry", nil, acl.Disclose) {
			code = ldapwire.ResultInsufficientAccessRights
		}
		return true, client.sendMonitorDone(message.ID, ldapwire.Result{Code: code})
	}
	if controls.assertion != nil {
		matches, matchErr := client.monitorFilterMatches(
			reader,
			subject,
			baseEntry,
			*controls.assertion,
		)
		if matchErr != nil || !matches {
			return true, client.sendMonitorDone(message.ID, ldapwire.Result{
				Code: ldapwire.ResultAssertionFailed,
			})
		}
	}

	fingerprint := monitorSearchFingerprint(subject, request, message.Controls)
	var snapshot *monitorSnapshot
	switch {
	case controls.paging != nil && len(controls.paging.cookie) != 0:
		snapshot, result = client.monitorPagingSnapshot(
			controls.paging.cookie,
			fingerprint,
		)
	case controls.vlv != nil && controls.vlv.request.HasContextID:
		snapshot, result = client.monitorVLVSnapShot(
			controls.vlv.request.ContextID,
			fingerprint,
		)
	default:
		snapshot, result = client.buildMonitorSnapshot(
			reader,
			subject,
			base,
			request,
			controls,
			fingerprint,
		)
	}
	if result != nil {
		responseControls := monitorFailureControls(controls, result.Code)
		return true, client.sendMonitorDone(message.ID, *result, responseControls...)
	}

	selected := snapshot.entries
	responseControls := make([]ldapwire.Control, 0, 3)
	if controls.sort != nil && controls.vlv == nil {
		sortCode := snapshot.sortResult
		if sortCode == ldapwire.ResultSuccess && snapshot.result != ldapwire.ResultSuccess {
			sortCode = snapshot.result
		}
		responseControls = append(responseControls, ldapwire.Control{
			OID:      monitorSortResponseOID,
			Value:    ldapwire.EncodeSortResultValue(sortCode, ""),
			HasValue: true,
		})
	}
	if controls.vlv != nil {
		var response ldapwire.VirtualListViewResponse
		selected, response, result = client.monitorVLVWindow(snapshot, controls.vlv)
		if controls.sort != nil {
			sortCode := snapshot.sortResult
			if result != nil && sortCode == ldapwire.ResultSuccess {
				sortCode = result.Code
			}
			responseControls = append(responseControls, ldapwire.Control{
				OID:      monitorSortResponseOID,
				Value:    ldapwire.EncodeSortResultValue(sortCode, ""),
				HasValue: true,
			})
		}
		if result != nil {
			responseControls = append(responseControls, monitorVLVResponseControl(response))
			return true, client.sendMonitorDone(message.ID, *result, responseControls...)
		}
		if result == nil && len(responseControls) == 0 ||
			(len(responseControls) != 0 && responseControls[len(responseControls)-1].OID != monitorVLVResponseOID) {
			responseControls = append(responseControls, monitorVLVResponseControl(response))
		}
	}
	if controls.paging != nil {
		selected, responseControls, result = client.monitorPage(
			snapshot,
			controls.paging,
			responseControls,
		)
		if result != nil {
			return true, client.sendMonitorDone(
				message.ID,
				*result,
				monitorFailureControls(controls, result.Code)...,
			)
		}
	}

	for _, selectedEntry := range selected {
		if err := client.write(
			ldapwire.EncodeSearchResultEntry(message.ID, selectedEntry, nil),
		); err != nil {
			client.close()
			return true, false
		}
	}
	return true, client.sendMonitorDone(
		message.ID,
		ldapwire.Result{Code: snapshot.result},
		responseControls...,
	)
}

func parseMonitorSearchControls(
	controls []ldapwire.Control,
) (monitorSearchControls, *ldapwire.Result) {
	var parsed monitorSearchControls
	manageDsaIT := false
	for _, control := range controls {
		switch control.OID {
		case monitorManageDsaITOID:
			if manageDsaIT || control.HasValue {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid manageDSAit control",
				)
			}
			manageDsaIT = true
		case monitorAssertionOID:
			if parsed.assertion != nil || !control.HasValue || len(control.Value) == 0 {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid assertion control",
				)
			}
			filter, err := ldapwire.DecodeFilter(control.Value)
			if err != nil {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid assertion control filter",
				)
			}
			parsed.assertion = &filter
		case monitorPagedResultsOID:
			if parsed.paging != nil || !control.HasValue {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid paged results control",
				)
			}
			size, cookie, err := ldapwire.DecodePagedResultsValue(control.Value)
			if err != nil {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid paged results control",
				)
			}
			parsed.paging = &monitorPagingRequest{size: size, cookie: bytes.Clone(cookie)}
		case monitorSortRequestOID:
			if parsed.sort != nil || !control.HasValue || len(control.Value) == 0 {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid server-side sort control",
				)
			}
			keys, err := ldapwire.DecodeSortRequestValue(control.Value)
			if err != nil {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid server-side sort control",
				)
			}
			parsed.sort = &monitorSortRequest{keys: keys, critical: control.Critical}
		case monitorVLVRequestOID:
			if parsed.vlv != nil || !control.HasValue || len(control.Value) == 0 {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid VLV control",
				)
			}
			request, err := ldapwire.DecodeVirtualListViewRequestValue(control.Value)
			if err != nil {
				return parsed, monitorControlError(
					ldapwire.ResultProtocolError,
					"invalid VLV control",
				)
			}
			parsed.vlv = &monitorVLVRequest{request: request, critical: control.Critical}
		default:
			if control.Critical {
				return parsed, monitorControlError(
					ldapwire.ResultUnavailableCriticalExtension,
					"critical control is not supported by the lloadd monitor",
				)
			}
		}
	}
	if parsed.vlv != nil && parsed.paging != nil {
		return parsed, monitorControlError(
			ldapwire.ResultUnwillingToPerform,
			"VLV and paged results cannot be combined",
		)
	}
	if parsed.vlv != nil && !validMonitorVLVRange(parsed.vlv.request) {
		return parsed, monitorControlError(
			ldapwire.ResultVirtualListViewError,
			"VLV request range is invalid",
		)
	}
	return parsed, nil
}

func monitorControlError(code ldapwire.ResultCode, diagnostic string) *ldapwire.Result {
	result := ldapwire.Result{Code: code, DiagnosticMessage: diagnostic}
	return &result
}

func validMonitorVLVRange(request ldapwire.VirtualListViewRequest) bool {
	if request.BeforeCount < 0 || request.BeforeCount > math.MaxInt32 ||
		request.AfterCount < 0 || request.AfterCount > math.MaxInt32 ||
		request.BeforeCount+request.AfterCount+1 > math.MaxInt32 {
		return false
	}
	if !request.ByOffset {
		return true
	}
	return request.Offset >= 1 && request.Offset <= math.MaxInt32 &&
		request.ContentCount >= 0 && request.ContentCount <= math.MaxInt32
}

func monitorFailureControls(
	controls monitorSearchControls,
	code ldapwire.ResultCode,
) []ldapwire.Control {
	var result []ldapwire.Control
	if controls.sort != nil {
		result = append(result, ldapwire.Control{
			OID:      monitorSortResponseOID,
			Value:    ldapwire.EncodeSortResultValue(code, ""),
			HasValue: true,
		})
	}
	if controls.vlv != nil {
		vlvCode := code
		if code == ldapwire.ResultVirtualListViewError {
			vlvCode = monitorVLVSortControlMissing
		}
		result = append(result, monitorVLVResponseControl(
			ldapwire.VirtualListViewResponse{Result: vlvCode},
		))
	}
	return result
}

func monitorMissingBaseResult(
	base directory.DN,
	entries []directory.Entry,
) ldapwire.Result {
	matched := ""
	for _, entry := range entries {
		candidate, err := directory.ParseDN(entry.DN)
		if err == nil && candidate.AncestorOf(base) && len(candidate.String()) > len(matched) {
			matched = candidate.String()
		}
	}
	return ldapwire.Result{
		Code:              ldapwire.ResultNoSuchObject,
		MatchedDN:         matched,
		DiagnosticMessage: "monitor entry does not exist",
	}
}

type monitorEntryReader struct {
	entries map[string]directory.Entry
	ordered []directory.Entry
}

func newMonitorEntryReader(entries []directory.Entry) monitorEntryReader {
	reader := monitorEntryReader{
		entries: make(map[string]directory.Entry, len(entries)),
		ordered: make([]directory.Entry, 0, len(entries)),
	}
	for _, entry := range entries {
		dn, err := directory.ParseDN(entry.DN)
		if err == nil {
			reader.entries[dn.Key()] = entry.Clone()
			reader.ordered = append(reader.ordered, entry.Clone())
		}
	}
	return reader
}

func (reader monitorEntryReader) lookup(dn directory.DN) (directory.Entry, bool) {
	entry, ok := reader.entries[dn.Key()]
	return entry.Clone(), ok
}

func (reader monitorEntryReader) Get(dn directory.DN) (directory.Entry, error) {
	entry, ok := reader.lookup(dn)
	if !ok {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	return entry, nil
}

func newMonitorRuntime(access []string) (*schema.Registry, *acl.Policy, error) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		return nil, nil, fmt.Errorf("build lloadd monitor schema: %w", err)
	}
	for _, description := range monitorAttributeTypes {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			return nil, nil, fmt.Errorf("register lloadd monitor attribute: %w", err)
		}
	}
	for _, description := range monitorObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			return nil, nil, fmt.Errorf("register lloadd monitor object class: %w", err)
		}
	}
	rules := make([]acl.Rule, 0, len(access))
	for index, raw := range access {
		rule, err := acl.ParseRule(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse lloadd monitor access rule %d: %w", index, err)
		}
		rules = append(rules, rule)
	}
	policy, err := acl.NewPolicy(rules, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build lloadd monitor access policy: %w", err)
	}
	if err := policy.Validate(registry); err != nil {
		return nil, nil, fmt.Errorf("validate lloadd monitor access policy: %w", err)
	}
	return registry, policy, nil
}

var monitorAttributeTypes = []string{
	"( 1.3.6.1.4.1.4203.666.100.1 NAME 'olmServerURI' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SYNTAX " + schema.SyntaxDirectoryString + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.2 NAME 'olmReceivedOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.3 NAME 'olmForwardedOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.4 NAME 'olmRejectedOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.5 NAME 'olmCompletedOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.6 NAME 'olmFailedOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.7 NAME 'olmPendingOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.8 NAME 'olmPendingConnections' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.9 NAME 'olmActiveConnections' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.10 NAME 'olmConnectionType' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SYNTAX " + schema.SyntaxDirectoryString + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.11 NAME 'olmIncomingConnections' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.12 NAME 'olmOutgoingConnections' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.13 NAME 'olmConnectionState' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SYNTAX " + schema.SyntaxDirectoryString + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.14 NAME 'olmAbandonedOps' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.15 NAME 'olmGeneration' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.100.16 NAME 'olmUptime' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
}

var monitorObjectClasses = []string{
	"( 1.3.6.1.4.1.4203.666.101.1 NAME 'olmBalancer' SUP top STRUCTURAL MAY ( olmIncomingConnections $ olmOutgoingConnections $ olmGeneration $ olmUptime ) )",
	"( 1.3.6.1.4.1.4203.666.101.2 NAME 'olmBalancerServer' SUP top STRUCTURAL MAY ( olmServerURI $ olmActiveConnections $ olmPendingConnections $ olmPendingOps $ olmReceivedOps $ olmCompletedOps $ olmFailedOps $ olmAbandonedOps ) )",
	"( 1.3.6.1.4.1.4203.666.101.3 NAME 'olmBalancerOperation' SUP top STRUCTURAL MAY ( olmReceivedOps $ olmForwardedOps $ olmRejectedOps $ olmCompletedOps $ olmFailedOps $ olmPendingOps $ olmAbandonedOps ) )",
	"( 1.3.6.1.4.1.4203.666.101.4 NAME 'olmBalancerConnection' SUP top STRUCTURAL MAY ( olmConnectionType $ olmConnectionState $ olmPendingOps $ olmReceivedOps $ olmCompletedOps $ olmFailedOps $ olmAbandonedOps ) )",
}

func (client *clientConnection) monitorACLSubject() acl.Subject {
	client.refreshTLSSecurityStrength()
	client.mu.Lock()
	authzID := string(client.authzID)
	authcID := string(client.authcID)
	saslMechanism := client.saslMech
	metadata := cloneConnectionMetadata(client.metadata)
	tlsActive := client.tlsActive
	tlsSSF := client.tlsSSF
	transportSSF := client.transportSSF
	saslSSF := client.saslSSF
	client.mu.Unlock()
	dn := monitorAuthorizationDN(authzID, saslMechanism)
	realDN := monitorAuthorizationDN(authcID, saslMechanism)
	if realDN == "" {
		realDN = dn
	}
	subject := acl.Subject{
		DN:           dn,
		RealDN:       realDN,
		PeerName:     monitorConnectionName(metadata.SourceAddress),
		SockName:     monitorConnectionName(metadata.DestinationAddress),
		SockURL:      monitorSocketURL(metadata.DestinationAddress, tlsActive),
		TransportSSF: transportSSF,
		SASLSSF:      saslSSF,
	}
	if tlsActive && tlsSSF > 0 {
		subject.TLSSSF = tlsSSF
	}
	subject.SSF = max(subject.TransportSSF, subject.TLSSSF, subject.SASLSSF)
	return subject
}

func connectionTransportSSF(address net.Addr) int {
	if address == nil {
		return 0
	}
	switch address.Network() {
	case "unix", "unixpacket":
		return 71
	default:
		return 0
	}
}

func monitorAuthorizationDN(identity, mechanism string) string {
	identity = strings.TrimSpace(identity)
	switch {
	case len(identity) >= 3 && strings.EqualFold(identity[:3], "dn:"):
		dn, err := directory.ParseDN(identity[3:])
		if err != nil {
			return ""
		}
		return dn.String()
	case len(identity) >= 2 && strings.EqualFold(identity[:2], "u:"):
		user := identity[2:]
		if user == "" || mechanism == "" {
			return ""
		}
		dn, err := directory.ParseDN(
			"uid=" + ldap.EscapeDN(user) +
				",cn=" + ldap.EscapeDN(strings.ToLower(mechanism)) +
				",cn=auth",
		)
		if err != nil {
			return ""
		}
		return dn.String()
	default:
		return ""
	}
}

func monitorConnectionName(address net.Addr) string {
	if address == nil {
		return ""
	}
	if address.Network() == "unix" || address.Network() == "unixpacket" {
		return "PATH=" + address.String()
	}
	return "IP=" + address.String()
}

func monitorSocketURL(address net.Addr, tlsActive bool) string {
	if address == nil {
		return ""
	}
	if address.Network() == "unix" || address.Network() == "unixpacket" {
		return "ldapi://" + address.String()
	}
	scheme := "ldap://"
	if tlsActive {
		scheme = "ldaps://"
	}
	return scheme + address.String()
}

func (client *clientConnection) monitorAllowed(
	reader monitorEntryReader,
	subject acl.Subject,
	entry directory.Entry,
	attribute string,
	value []byte,
	privilege acl.Privilege,
) bool {
	return client.proxy.monitorAccess.Allowed(subject, acl.Target{
		Entry:        entry,
		Attribute:    attribute,
		Value:        value,
		DNValued:     client.proxy.monitorSchema.IsDNValued(attribute),
		Schema:       client.proxy.monitorSchema,
		DNNormalizer: client.proxy.monitorSchema,
	}, privilege, reader)
}

type monitorFilterResult uint8

const (
	monitorFilterFalse monitorFilterResult = iota
	monitorFilterTrue
	monitorFilterUndefined
)

func (client *clientConnection) monitorFilterMatches(
	reader monitorEntryReader,
	subject acl.Subject,
	entry directory.Entry,
	filter directory.Filter,
) (bool, error) {
	result, err := client.monitorEvaluateFilter(reader, subject, entry, filter)
	return result == monitorFilterTrue, err
}

func (client *clientConnection) monitorEvaluateFilter(
	reader monitorEntryReader,
	subject acl.Subject,
	entry directory.Entry,
	filter directory.Filter,
) (monitorFilterResult, error) {
	switch filter.Kind {
	case directory.FilterAnd:
		result := monitorFilterTrue
		for _, child := range filter.Children {
			candidate, err := client.monitorEvaluateFilter(reader, subject, entry, child)
			if err != nil || candidate == monitorFilterFalse {
				return candidate, err
			}
			if candidate == monitorFilterUndefined {
				result = monitorFilterUndefined
			}
		}
		return result, nil
	case directory.FilterOr:
		result := monitorFilterFalse
		for _, child := range filter.Children {
			candidate, err := client.monitorEvaluateFilter(reader, subject, entry, child)
			if err != nil || candidate == monitorFilterTrue {
				return candidate, err
			}
			if candidate == monitorFilterUndefined {
				result = monitorFilterUndefined
			}
		}
		return result, nil
	case directory.FilterNot:
		if len(filter.Children) != 1 {
			return monitorFilterUndefined, errors.New("not filter requires exactly one child")
		}
		candidate, err := client.monitorEvaluateFilter(
			reader,
			subject,
			entry,
			filter.Children[0],
		)
		switch candidate {
		case monitorFilterTrue:
			return monitorFilterFalse, err
		case monitorFilterFalse:
			return monitorFilterTrue, err
		default:
			return monitorFilterUndefined, err
		}
	case directory.FilterExtensible:
		if filter.Attribute == "" {
			filtered := directory.Entry{DN: entry.DN}
			for _, attribute := range entry.Attributes {
				if client.monitorAllowed(
					reader,
					subject,
					entry,
					attribute.Description,
					filter.Assertion,
					acl.Search,
				) {
					filtered.Attributes = append(filtered.Attributes, attribute)
				}
			}
			matches, err := filter.MatchWith(filtered, client.proxy.monitorSchema)
			return monitorBooleanFilterResult(matches), err
		}
	}

	assertion := filter.Assertion
	switch filter.Kind {
	case directory.FilterPresent, directory.FilterSubstrings:
		assertion = nil
	}
	if !client.monitorAllowed(
		reader,
		subject,
		entry,
		filter.Attribute,
		assertion,
		acl.Search,
	) {
		return monitorFilterUndefined, nil
	}
	matches, err := filter.MatchWith(entry, client.proxy.monitorSchema)
	return monitorBooleanFilterResult(matches), err
}

func monitorBooleanFilterResult(value bool) monitorFilterResult {
	if value {
		return monitorFilterTrue
	}
	return monitorFilterFalse
}

func (client *clientConnection) monitorReadableEntry(
	reader monitorEntryReader,
	subject acl.Subject,
	entry directory.Entry,
	typesOnly bool,
) (directory.Entry, bool) {
	if !client.monitorAllowed(reader, subject, entry, "entry", nil, acl.Read) {
		return directory.Entry{}, false
	}
	readable := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		selected := directory.Attribute{Description: attribute.Description}
		if typesOnly {
			if client.monitorAllowed(
				reader,
				subject,
				entry,
				attribute.Description,
				nil,
				acl.Read,
			) {
				readable.Attributes = append(readable.Attributes, selected)
			}
			continue
		}
		for _, value := range attribute.Values {
			if client.monitorAllowed(
				reader,
				subject,
				entry,
				attribute.Description,
				value,
				acl.Read,
			) {
				selected.Values = append(selected.Values, bytes.Clone(value))
			}
		}
		if len(selected.Values) != 0 ||
			(len(attribute.Values) == 0 && client.monitorAllowed(
				reader,
				subject,
				entry,
				attribute.Description,
				nil,
				acl.Read,
			)) {
			readable.Attributes = append(readable.Attributes, selected)
		}
	}
	return readable, true
}

type monitorSearchCandidate struct {
	readable directory.Entry
	selected directory.Entry
}

func (client *clientConnection) buildMonitorSnapshot(
	reader monitorEntryReader,
	subject acl.Subject,
	base directory.DN,
	request ldapwire.SearchRequest,
	controls monitorSearchControls,
	fingerprint [sha256.Size]byte,
) (*monitorSnapshot, *ldapwire.Result) {
	entries := reader.ordered
	candidates := make([]monitorSearchCandidate, 0, len(entries))
	resultCode := ldapwire.ResultSuccess
	deadline := time.Time{}
	if request.TimeLimit > 0 {
		deadline = time.Now().Add(time.Duration(request.TimeLimit) * time.Second)
	}
	for _, entry := range entries {
		if !deadline.IsZero() && time.Now().After(deadline) {
			resultCode = ldapwire.ResultTimeLimitExceeded
			break
		}
		candidateDN, err := directory.ParseDN(entry.DN)
		if err != nil || !directory.InScope(base, candidateDN, request.Scope) {
			continue
		}
		if !client.monitorAllowed(reader, subject, entry, "entry", nil, acl.Search) {
			continue
		}
		matches, err := client.monitorFilterMatches(reader, subject, entry, request.Filter)
		if err != nil {
			return nil, monitorControlError(
				ldapwire.ResultInappropriateMatching,
				err.Error(),
			)
		}
		if !matches {
			continue
		}
		readable, allowed := client.monitorReadableEntry(
			reader,
			subject,
			entry,
			request.TypesOnly,
		)
		if !allowed {
			continue
		}
		selected := readable.SelectWithMatcher(
			request.Attributes,
			request.TypesOnly,
			client.proxy.monitorSchema.IsOperational,
			client.proxy.monitorSchema.AttributeDescriptionSubtype,
		)
		if request.SizeLimit > 0 && len(candidates) >= request.SizeLimit {
			resultCode = ldapwire.ResultSizeLimitExceeded
			break
		}
		candidates = append(candidates, monitorSearchCandidate{
			readable: readable,
			selected: selected,
		})
		if len(candidates) > monitorSnapshotEntryLimit {
			return nil, monitorControlError(
				ldapwire.ResultAdminLimitExceeded,
				"lloadd monitor snapshot entry limit exceeded",
			)
		}
	}
	sortCode := ldapwire.ResultSuccess
	resolvedKeys, result := client.resolveMonitorSortKeys(controls.sort)
	if result != nil {
		if controls.sort == nil || controls.sort.critical {
			return nil, result
		}
		sortCode = result.Code
		resolvedKeys = nil
	}
	if len(resolvedKeys) != 0 {
		if err := client.sortMonitorCandidates(candidates, resolvedKeys); err != nil {
			if controls.sort.critical {
				return nil, monitorControlError(
					ldapwire.ResultInappropriateMatching,
					"monitor server-side sort comparison failed",
				)
			}
			sortCode = ldapwire.ResultInappropriateMatching
			resolvedKeys = nil
		}
	}
	snapshot := &monitorSnapshot{
		fingerprint: fingerprint,
		entries:     make([]directory.Entry, len(candidates)),
		sortEntries: make([]directory.Entry, len(candidates)),
		sortKeys:    append([]monitorSortKey(nil), resolvedKeys...),
		sortResult:  sortCode,
		result:      resultCode,
		expires:     time.Now().Add(monitorSnapshotTTL),
	}
	for index := range candidates {
		snapshot.entries[index] = candidates[index].selected.Clone()
		snapshot.sortEntries[index] = candidates[index].readable.Clone()
	}
	return snapshot, nil
}

func (client *clientConnection) resolveMonitorSortKeys(
	request *monitorSortRequest,
) ([]monitorSortKey, *ldapwire.Result) {
	if request == nil {
		return nil, nil
	}
	if len(request.keys) > 5 {
		return nil, monitorControlError(
			ldapwire.ResultUnwillingToPerform,
			"too many monitor sort keys",
		)
	}
	keys := make([]monitorSortKey, 0, len(request.keys))
	for _, key := range request.keys {
		if _, ok := client.proxy.monitorSchema.AttributeType(key.AttributeType); !ok {
			return nil, monitorControlError(
				ldapwire.ResultNoSuchAttribute,
				"unrecognized monitor sort attribute",
			)
		}
		rule, err := client.proxy.monitorSchema.OrderingRule(
			key.AttributeType,
			key.OrderingRule,
		)
		if err != nil {
			return nil, monitorControlError(
				ldapwire.ResultInappropriateMatching,
				"monitor sort attribute has no ordering rule",
			)
		}
		keys = append(keys, monitorSortKey{
			attribute:    key.AttributeType,
			orderingRule: rule,
			reverse:      key.Reverse,
		})
	}
	return keys, nil
}

func (client *clientConnection) sortMonitorCandidates(
	candidates []monitorSearchCandidate,
	keys []monitorSortKey,
) error {
	var compareErr error
	sort.SliceStable(candidates, func(left, right int) bool {
		if compareErr != nil {
			return false
		}
		comparison, err := client.compareMonitorEntries(
			candidates[left].readable,
			candidates[right].readable,
			keys,
		)
		if err != nil {
			compareErr = err
			return false
		}
		return comparison < 0
	})
	return compareErr
}

func (client *clientConnection) compareMonitorEntries(
	left directory.Entry,
	right directory.Entry,
	keys []monitorSortKey,
) (int, error) {
	for _, key := range keys {
		leftValue, leftPresent, err := client.leastMonitorSortValue(left, key)
		if err != nil {
			return 0, err
		}
		rightValue, rightPresent, err := client.leastMonitorSortValue(right, key)
		if err != nil {
			return 0, err
		}
		comparison := 0
		switch {
		case !leftPresent && !rightPresent:
			continue
		case !leftPresent:
			comparison = 1
		case !rightPresent:
			comparison = -1
		default:
			comparison, err = client.proxy.monitorSchema.CompareOrdering(
				key.attribute,
				key.orderingRule,
				leftValue,
				rightValue,
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
	leftDN, leftErr := client.proxy.monitorSchema.NormalizeDN(left.DN)
	rightDN, rightErr := client.proxy.monitorSchema.NormalizeDN(right.DN)
	if leftErr != nil || rightErr != nil {
		return strings.Compare(left.DN, right.DN), nil
	}
	return strings.Compare(leftDN.Key(), rightDN.Key()), nil
}

func (client *clientConnection) leastMonitorSortValue(
	entry directory.Entry,
	key monitorSortKey,
) ([]byte, bool, error) {
	values := client.proxy.monitorSchema.AttributeValues(entry, key.attribute)
	if len(values) == 0 {
		return nil, false, nil
	}
	least := values[0]
	for _, value := range values {
		comparison, err := client.proxy.monitorSchema.CompareOrdering(
			key.attribute,
			key.orderingRule,
			value,
			least,
		)
		if err != nil {
			return nil, false, err
		}
		if comparison < 0 {
			least = value
		}
	}
	return bytes.Clone(least), true, nil
}

func monitorSearchFingerprint(
	subject acl.Subject,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
) [sha256.Size]byte {
	normalized := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		copy := control
		switch copy.OID {
		case monitorPagedResultsOID, monitorVLVRequestOID:
			copy.Value = nil
			copy.HasValue = true
		}
		normalized = append(normalized, copy)
	}
	encoded, _ := json.Marshal(struct {
		Subject  acl.Subject
		Request  ldapwire.SearchRequest
		Controls []ldapwire.Control
	}{
		Subject:  subject,
		Request:  request,
		Controls: normalized,
	})
	return sha256.Sum256(encoded)
}

func (client *clientConnection) monitorPagingSnapshot(
	cookie []byte,
	fingerprint [sha256.Size]byte,
) (*monitorSnapshot, *ldapwire.Result) {
	if len(cookie) != monitorPagingCookieLength {
		return nil, monitorControlError(
			ldapwire.ResultUnwillingToPerform,
			"invalid monitor paging cookie",
		)
	}
	return client.lookupMonitorSnapshot(cookie[:monitorSnapshotIDLength], fingerprint)
}

func (client *clientConnection) monitorVLVSnapShot(
	contextID []byte,
	fingerprint [sha256.Size]byte,
) (*monitorSnapshot, *ldapwire.Result) {
	if len(contextID) != monitorSnapshotIDLength {
		return nil, monitorControlError(
			ldapwire.ResultProtocolError,
			"invalid monitor VLV contextID",
		)
	}
	return client.lookupMonitorSnapshot(contextID, fingerprint)
}

func (client *clientConnection) lookupMonitorSnapshot(
	id []byte,
	fingerprint [sha256.Size]byte,
) (*monitorSnapshot, *ldapwire.Result) {
	now := time.Now()
	client.mu.Lock()
	client.expireMonitorSnapshotsLocked(now)
	snapshot := client.monitorSnapshots[string(id)]
	if snapshot == nil || snapshot.fingerprint != fingerprint {
		client.mu.Unlock()
		return nil, monitorControlError(
			ldapwire.ResultUnwillingToPerform,
			"monitor snapshot context is invalid",
		)
	}
	snapshot.expires = now.Add(monitorSnapshotTTL)
	client.mu.Unlock()
	return snapshot, nil
}

func (client *clientConnection) storeMonitorSnapshot(
	snapshot *monitorSnapshot,
) *ldapwire.Result {
	if snapshot == nil || len(snapshot.entries) > monitorSnapshotEntryLimit {
		return monitorControlError(
			ldapwire.ResultAdminLimitExceeded,
			"lloadd monitor snapshot entry limit exceeded",
		)
	}
	now := time.Now()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return monitorControlError(
			ldapwire.ResultUnavailable,
			"lloadd monitor connection is closed",
		)
	}
	if client.monitorSnapshots == nil {
		client.monitorSnapshots = make(map[string]*monitorSnapshot)
	}
	client.expireMonitorSnapshotsLocked(now)
	if len(client.monitorSnapshots) >= monitorSnapshotLimit {
		return monitorControlError(
			ldapwire.ResultBusy,
			"too many monitor snapshots are active on this connection",
		)
	}
	snapshot.sizeBytes = monitorSnapshotSize(snapshot)
	if snapshot.sizeBytes > monitorSnapshotByteLimit ||
		client.monitorSnapshotBytes > monitorSnapshotByteLimit-snapshot.sizeBytes {
		return monitorControlError(
			ldapwire.ResultAdminLimitExceeded,
			"lloadd monitor snapshot memory limit exceeded",
		)
	}
	if !client.proxy.reserveMonitorSnapshotBytes(snapshot.sizeBytes) {
		return monitorControlError(
			ldapwire.ResultBusy,
			"lloadd monitor snapshot capacity is exhausted",
		)
	}
	reserved := true
	defer func() {
		if reserved {
			client.proxy.releaseMonitorSnapshotBytes(snapshot.sizeBytes)
		}
	}()
	for {
		id := make([]byte, monitorSnapshotIDLength)
		if _, err := rand.Read(id); err != nil {
			return monitorControlError(
				ldapwire.ResultOther,
				"could not allocate monitor snapshot context",
			)
		}
		if client.monitorSnapshots[string(id)] != nil {
			continue
		}
		snapshot.id = id
		snapshot.expires = now.Add(monitorSnapshotTTL)
		client.monitorSnapshots[string(id)] = snapshot
		client.monitorSnapshotBytes += snapshot.sizeBytes
		reserved = false
		return nil
	}
}

func (client *clientConnection) expireMonitorSnapshotsLocked(now time.Time) {
	for key, snapshot := range client.monitorSnapshots {
		if snapshot == nil || !snapshot.expires.After(now) {
			client.removeMonitorSnapshotLocked(key, snapshot)
		}
	}
}

func (client *clientConnection) removeMonitorSnapshot(snapshot *monitorSnapshot) {
	if snapshot == nil || len(snapshot.id) == 0 {
		return
	}
	client.mu.Lock()
	if client.monitorSnapshots[string(snapshot.id)] == snapshot {
		client.removeMonitorSnapshotLocked(string(snapshot.id), snapshot)
	}
	client.mu.Unlock()
}

func (client *clientConnection) removeMonitorSnapshotLocked(
	key string,
	snapshot *monitorSnapshot,
) {
	delete(client.monitorSnapshots, key)
	if snapshot == nil || snapshot.sizeBytes <= 0 {
		return
	}
	client.monitorSnapshotBytes -= snapshot.sizeBytes
	if client.monitorSnapshotBytes < 0 {
		client.monitorSnapshotBytes = 0
	}
	client.proxy.releaseMonitorSnapshotBytes(snapshot.sizeBytes)
	snapshot.sizeBytes = 0
}

func (client *clientConnection) clearMonitorSnapshotsLocked() {
	for key, snapshot := range client.monitorSnapshots {
		client.removeMonitorSnapshotLocked(key, snapshot)
	}
	if client.monitorSnapshots == nil {
		client.monitorSnapshots = make(map[string]*monitorSnapshot)
	}
}

func (client *clientConnection) runMonitorSnapshotJanitor(interval time.Duration) {
	if interval <= 0 {
		interval = monitorSnapshotCleanupInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			client.mu.Lock()
			client.expireMonitorSnapshotsLocked(now)
			client.mu.Unlock()
		case <-client.done:
			return
		}
	}
}

func (proxy *Proxy) reserveMonitorSnapshotBytes(size int64) bool {
	if size <= 0 {
		return true
	}
	for {
		current := proxy.monitorSnapshotBytes.Load()
		if current > monitorProxySnapshotLimit-size {
			return false
		}
		if proxy.monitorSnapshotBytes.CompareAndSwap(current, current+size) {
			return true
		}
	}
}

func (proxy *Proxy) releaseMonitorSnapshotBytes(size int64) {
	if size > 0 {
		proxy.monitorSnapshotBytes.Add(-size)
	}
}

func monitorSnapshotSize(snapshot *monitorSnapshot) int64 {
	if snapshot == nil {
		return 0
	}
	size := int64(len(snapshot.id) + len(snapshot.sortKeys)*64 + 128)
	for _, entries := range [][]directory.Entry{snapshot.entries, snapshot.sortEntries} {
		for _, entry := range entries {
			size += int64(len(entry.DN) + 64)
			for _, attribute := range entry.Attributes {
				size += int64(len(attribute.Description) + 32)
				for _, value := range attribute.Values {
					size += int64(len(value) + 24)
				}
			}
		}
	}
	return size
}

func (client *clientConnection) monitorPage(
	snapshot *monitorSnapshot,
	request *monitorPagingRequest,
	controls []ldapwire.Control,
) ([]directory.Entry, []ldapwire.Control, *ldapwire.Result) {
	if request.size < 0 {
		return nil, nil, monitorControlError(
			ldapwire.ResultProtocolError,
			"invalid monitor page size",
		)
	}
	if request.size == 0 {
		if len(request.cookie) != 0 {
			client.removeMonitorSnapshot(snapshot)
		}
		controls = append(controls, ldapwire.Control{
			OID:      monitorPagedResultsOID,
			Value:    ldapwire.EncodePagedResultsValue(len(snapshot.entries), nil),
			HasValue: true,
		})
		return nil, controls, nil
	}
	offset := 0
	if len(request.cookie) != 0 {
		offset = int(binary.BigEndian.Uint32(request.cookie[monitorSnapshotIDLength:]))
	} else if result := client.storeMonitorSnapshot(snapshot); result != nil {
		return nil, nil, result
	}
	if offset < 0 || offset > len(snapshot.entries) {
		client.removeMonitorSnapshot(snapshot)
		return nil, nil, monitorControlError(
			ldapwire.ResultUnwillingToPerform,
			"monitor paging cookie is out of range",
		)
	}
	end := min(len(snapshot.entries), offset+request.size)
	nextCookie := []byte(nil)
	if end < len(snapshot.entries) {
		nextCookie = make([]byte, monitorPagingCookieLength)
		copy(nextCookie, snapshot.id)
		binary.BigEndian.PutUint32(nextCookie[monitorSnapshotIDLength:], uint32(end))
	} else {
		client.removeMonitorSnapshot(snapshot)
	}
	controls = append(controls, ldapwire.Control{
		OID:      monitorPagedResultsOID,
		Value:    ldapwire.EncodePagedResultsValue(len(snapshot.entries), nextCookie),
		HasValue: true,
	})
	return snapshot.entries[offset:end], controls, nil
}

func (client *clientConnection) monitorVLVWindow(
	snapshot *monitorSnapshot,
	request *monitorVLVRequest,
) ([]directory.Entry, ldapwire.VirtualListViewResponse, *ldapwire.Result) {
	if len(snapshot.sortKeys) == 0 {
		response := ldapwire.VirtualListViewResponse{Result: monitorVLVSortControlMissing}
		return nil, response, monitorControlError(
			ldapwire.ResultVirtualListViewError,
			"VLV requires server-side sorting",
		)
	}
	if !request.request.HasContextID {
		if result := client.storeMonitorSnapshot(snapshot); result != nil {
			response := ldapwire.VirtualListViewResponse{Result: result.Code}
			return nil, response, result
		}
	}
	start, end, target, code, err := client.monitorVLVRange(
		snapshot,
		request.request,
	)
	response := ldapwire.VirtualListViewResponse{
		TargetPosition: int64(target),
		ContentCount:   int64(len(snapshot.entries)),
		Result:         code,
		ContextID:      bytes.Clone(snapshot.id),
		HasContextID:   true,
	}
	if err != nil {
		return nil, response, monitorControlError(
			ldapwire.ResultVirtualListViewError,
			err.Error(),
		)
	}
	if code != ldapwire.ResultSuccess {
		return nil, response, monitorControlError(
			ldapwire.ResultVirtualListViewError,
			"VLV target is outside the monitor result set",
		)
	}
	return snapshot.entries[start:end], response, nil
}

func (client *clientConnection) monitorVLVRange(
	snapshot *monitorSnapshot,
	request ldapwire.VirtualListViewRequest,
) (int, int, int, ldapwire.ResultCode, error) {
	count := len(snapshot.entries)
	if count == 0 {
		return 0, 0, 0, ldapwire.ResultSuccess, nil
	}
	target := 0
	if request.ByOffset {
		switch {
		case request.ContentCount > 0 && request.Offset > request.ContentCount:
			return 0, 0, 0, monitorVLVOffsetRangeError, nil
		case request.Offset == request.ContentCount:
			target = count
		case request.Offset == 1:
			target = 1
		case request.ContentCount > 0 && request.ContentCount != int64(count):
			count64 := int64(count)
			target = int(
				count64/request.ContentCount*request.Offset +
					count64%request.ContentCount*request.Offset/request.ContentCount,
			)
		default:
			if request.Offset > int64(count) {
				return 0, 0, 0, monitorVLVOffsetRangeError, nil
			}
			target = int(request.Offset)
		}
	} else {
		target = count + 1
		key := snapshot.sortKeys[0]
		for index, entry := range snapshot.sortEntries {
			value, present, err := client.leastMonitorSortValue(entry, key)
			if err != nil {
				return 0, 0, 0, ldapwire.ResultInappropriateMatching, err
			}
			comparison := 1
			if present {
				comparison, err = client.proxy.monitorSchema.CompareOrdering(
					key.attribute,
					key.orderingRule,
					value,
					request.AssertionValue,
				)
				if err != nil {
					return 0, 0, 0, ldapwire.ResultInappropriateMatching, err
				}
			}
			if key.reverse {
				comparison = -comparison
			}
			if comparison >= 0 {
				target = index + 1
				break
			}
		}
	}
	if target == count+1 {
		before := max(int(request.BeforeCount), 1)
		return max(0, count-before), count, target, ldapwire.ResultSuccess, nil
	}
	start := max(0, target-1-int(request.BeforeCount))
	end := min(count, target+int(request.AfterCount))
	return start, end, target, ldapwire.ResultSuccess, nil
}

func monitorVLVResponseControl(response ldapwire.VirtualListViewResponse) ldapwire.Control {
	return ldapwire.Control{
		OID:      monitorVLVResponseOID,
		Value:    ldapwire.EncodeVirtualListViewResponseValue(response),
		HasValue: true,
	}
}
func isMonitorSearchBase(raw string) bool {
	base, err := directory.ParseDN(raw)
	if err != nil {
		return strings.EqualFold(strings.TrimSpace(raw), MonitorBaseDN)
	}
	monitor, err := directory.ParseDN(MonitorBaseDN)
	return err == nil && (monitor.Equal(base) || monitor.AncestorOf(base))
}

func (client *clientConnection) sendMonitorDone(
	messageID int64,
	result ldapwire.Result,
	controls ...ldapwire.Control,
) bool {
	if err := client.write(ldapwire.EncodeSearchResultDone(messageID, result, controls)); err != nil {
		client.close()
		return false
	}
	return true
}

func (proxy *Proxy) monitorEntries() []directory.Entry {
	snapshot := proxy.MonitorSnapshot()
	pendingOperations := uint64(0)
	for _, operation := range snapshot.Operations {
		pendingOperations += operation.Counters.Pending
	}
	entries := []directory.Entry{
		monitorEntry(MonitorBaseDN, "Monitor", []string{"top", "monitorServer"},
			monitorAttribute("description", "LDAP load balancer monitor")),
		monitorEntry(MonitorLoadBalancerDN, "Load Balancer", []string{"top", "olmBalancer"},
			monitorAttribute("description", "Load Balancer information"),
			monitorInteger64("olmGeneration", snapshot.Generation),
			monitorInteger64("olmUptime", uint64(snapshot.Uptime/time.Second)),
			monitorInteger("olmIncomingConnections", snapshot.IncomingConnections),
			monitorInteger("olmOutgoingConnections", snapshot.OutgoingConnections)),
		monitorEntry(monitorIncomingDN, "Incoming Connections", []string{"top", "monitorContainer"},
			monitorAttribute("description", "Load Balancer incoming connections"),
			monitorInteger("monitorCounter", snapshot.IncomingConnections)),
		monitorEntry(monitorOperationsDN, "Operations", []string{"top", "monitorContainer"},
			monitorAttribute("description", "Load Balancer global operation statistics"),
			monitorInteger64("olmPendingOps", pendingOperations)),
		monitorEntry(monitorBackendTiersDN, "Backend Tiers", []string{"top", "monitorContainer"},
			monitorAttribute("description", "Load Balancer Backends information")),
	}
	for _, operation := range snapshot.Operations {
		entries = append(entries, monitorEntry(
			"cn="+operation.Name+","+monitorOperationsDN,
			operation.Name,
			[]string{"top", "olmBalancerOperation"},
			monitorCounterAttributes(operation.Counters, operation.Abandoned)...,
		))
	}
	for _, connection := range snapshot.Incoming {
		entries = append(entries, monitorConnectionEntry(
			"cn=Connection "+connection.ID+","+monitorIncomingDN,
			"Connection "+connection.ID,
			connection,
		))
	}

	tierSeen := make(map[string]bool)
	for _, backend := range snapshot.Backends {
		tierIndex, _ := strconv.Atoi(strings.TrimPrefix(backend.TierID, "tier-"))
		tierName := "tier " + strconv.Itoa(tierIndex+1)
		tierDN := "cn=" + tierName + "," + monitorBackendTiersDN
		if !tierSeen[backend.TierID] {
			tierSeen[backend.TierID] = true
			entries = append(entries, monitorEntry(
				tierDN,
				tierName,
				[]string{"top", "monitorContainer"},
			))
		}
		backendIndex, _ := strconv.Atoi(backend.BackendID[strings.LastIndexByte(backend.BackendID, '-')+1:])
		backendName := "server " + strconv.Itoa(backendIndex+1)
		entries = append(entries, monitorEntry(
			"cn="+backendName+","+tierDN,
			backendName,
			[]string{"top", "olmBalancerServer"},
			monitorAttribute("olmServerURI", backend.URI),
			monitorInteger("olmActiveConnections", backend.ActiveConnections),
			monitorInteger("olmPendingConnections", backend.PendingConnections),
			monitorInteger("olmPendingOps", backend.PendingOperations),
			monitorInteger64("olmReceivedOps", backend.Counters.Received),
			monitorInteger64("olmCompletedOps", backend.Counters.Completed),
			monitorInteger64("olmFailedOps", backend.Counters.Failed),
			monitorInteger64("olmAbandonedOps", backend.Abandoned),
		))
		backendDN := "cn=" + backendName + "," + tierDN
		for _, connection := range backend.Connections {
			entries = append(entries, monitorConnectionEntry(
				"cn=Connection "+connection.ID+","+backendDN,
				"Connection "+connection.ID,
				connection,
			))
		}
	}
	return entries
}

func monitorConnectionEntry(dn, cn string, connection ProxyMonitorConnection) directory.Entry {
	entry := monitorEntry(
		dn,
		cn,
		[]string{"top", "olmBalancerConnection"},
		monitorAttribute("olmConnectionType", connection.Type),
		monitorAttribute("olmConnectionState", connection.State),
		monitorInteger("olmPendingOps", connection.Pending),
		monitorInteger64("olmReceivedOps", connection.Counters.Received),
		monitorInteger64("olmCompletedOps", connection.Counters.Completed),
		monitorInteger64("olmFailedOps", connection.Counters.Failed),
		monitorInteger64("olmAbandonedOps", connection.Abandoned),
	)
	if !connection.Created.IsZero() {
		stamp := connection.Created.UTC().Format("20060102150405Z")
		entry.Attributes = append(entry.Attributes,
			monitorAttribute("createTimestamp", stamp),
			monitorAttribute("modifyTimestamp", stamp),
		)
	}
	return entry
}

func monitorCounterAttributes(counters ProxyMonitorCounters, abandoned uint64) []directory.Attribute {
	return []directory.Attribute{
		monitorInteger64("olmReceivedOps", counters.Received),
		monitorInteger64("olmForwardedOps", counters.Forwarded),
		monitorInteger64("olmRejectedOps", counters.Rejected),
		monitorInteger64("olmCompletedOps", counters.Completed),
		monitorInteger64("olmFailedOps", counters.Failed),
		monitorInteger64("olmPendingOps", counters.Pending),
		monitorInteger64("olmAbandonedOps", abandoned),
	}
}

func monitorEntry(
	dn string,
	cn string,
	objectClasses []string,
	attributes ...directory.Attribute,
) directory.Entry {
	objectClassValues := make([][]byte, len(objectClasses))
	for index, objectClass := range objectClasses {
		objectClassValues[index] = []byte(objectClass)
	}
	structural := "top"
	if len(objectClasses) != 0 {
		structural = objectClasses[len(objectClasses)-1]
	}
	return directory.Entry{
		DN: dn,
		Attributes: append([]directory.Attribute{
			{Description: "objectClass", Values: objectClassValues},
			monitorAttribute("cn", cn),
			monitorAttribute("structuralObjectClass", structural),
			monitorAttribute("entryDN", dn),
		}, attributes...),
	}
}

func monitorAttribute(description, value string) directory.Attribute {
	return directory.Attribute{Description: description, Values: [][]byte{[]byte(value)}}
}

func monitorInteger(description string, value int) directory.Attribute {
	return monitorAttribute(description, strconv.Itoa(value))
}

func monitorInteger64(description string, value uint64) directory.Attribute {
	return monitorAttribute(description, strconv.FormatUint(value, 10))
}
