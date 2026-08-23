package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	asyncMetaDefaultMaxPendingOperations = 128
	asyncMetaDefaultMaxTargetConnections = 255
)

// asyncMetaBackendRuntimeConfiguration owns asyncmeta-only scheduling state.
// Target selection, rewriting, authentication, and transports remain in the
// shared meta configuration so both proxy backends use one implementation.
type asyncMetaBackendRuntimeConfiguration struct {
	meta                 *metaBackendRuntimeConfiguration
	maxPendingOperations int
	maxTargetConnections int
	maxTimeoutOperations int
	scheduler            *asyncMetaScheduler
}

type asyncMetaScheduler struct {
	mu          sync.Mutex
	next        int
	connections []asyncMetaConnection
	targets     map[string]*asyncMetaTargetState
}

type asyncMetaConnection struct {
	pending int
}

type asyncMetaTargetState struct {
	consecutiveTimeouts int
	epoch               uint64
}

type asyncMetaOperationLease struct {
	scheduler  *asyncMetaScheduler
	connection int
	released   bool
}

type asyncMetaOperationLeaseContextKey struct{}

func loadAsyncMetaBackendRuntimeConfigurationWithNormalizer(
	reader storage.Reader,
	databaseEntry directory.Entry,
	normalizer directory.DNAttributeNormalizer,
) (*asyncMetaBackendRuntimeConfiguration, error) {
	meta, err := loadMetaBackendRuntimeConfigurationFlavor(
		reader,
		databaseEntry,
		normalizer,
		asyncMetaBackendFlavor,
	)
	if err != nil {
		return nil, err
	}
	maximumPending, err := loadAsyncMetaNonnegativeInteger(
		databaseEntry,
		"olcDbMaxPendingOps",
		asyncMetaDefaultMaxPendingOperations,
	)
	if err != nil {
		return nil, err
	}
	maximumConnections, err := loadAsyncMetaNonnegativeInteger(
		databaseEntry,
		"olcDbMaxTargetConns",
		asyncMetaDefaultMaxTargetConnections,
	)
	if err != nil {
		return nil, err
	}
	maximumTimeouts, err := loadAsyncMetaNonnegativeInteger(
		databaseEntry,
		"olcDbMaxTimeoutOps",
		0,
	)
	if err != nil {
		return nil, err
	}
	if maximumPending == 0 {
		maximumPending = asyncMetaDefaultMaxPendingOperations
	}
	if maximumConnections == 0 {
		maximumConnections = asyncMetaDefaultMaxTargetConnections
	}
	for targetIndex := range meta.targets {
		target := &meta.targets[targetIndex]
		if target.ldapBackend == nil {
			continue
		}
		for remoteIndex := range target.ldapBackend.remotes {
			// One async metaconn owns one multiplexed connection per target.
			target.ldapBackend.remotes[remoteIndex].connectionPoolMax = 1
		}
	}
	return &asyncMetaBackendRuntimeConfiguration{
		meta:                 meta,
		maxPendingOperations: maximumPending,
		maxTargetConnections: maximumConnections,
		maxTimeoutOperations: maximumTimeouts,
		scheduler:            newAsyncMetaScheduler(maximumConnections),
	}, nil
}

func loadAsyncMetaNonnegativeInteger(
	entry directory.Entry,
	description string,
	defaultValue int,
) (int, error) {
	values := entry.Values(description)
	if len(values) == 0 {
		return defaultValue, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("%s %s must be single-valued", entry.DN, description)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(values[0])))
	if err != nil || value < 0 {
		return 0, fmt.Errorf(
			"%s %s has invalid value %q",
			entry.DN,
			description,
			values[0],
		)
	}
	return value, nil
}

func newAsyncMetaScheduler(connections int) *asyncMetaScheduler {
	if connections < 1 {
		connections = 1
	}
	return &asyncMetaScheduler{
		next:        -1,
		connections: make([]asyncMetaConnection, connections),
		targets:     make(map[string]*asyncMetaTargetState),
	}
}

func (configuration *asyncMetaBackendRuntimeConfiguration) acquire() *asyncMetaOperationLease {
	if configuration == nil || configuration.scheduler == nil {
		return nil
	}
	scheduler := configuration.scheduler
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if len(scheduler.connections) == 0 {
		return nil
	}
	scheduler.next = (scheduler.next + 1) % len(scheduler.connections)
	connection := &scheduler.connections[scheduler.next]
	if connection.pending >= configuration.maxPendingOperations {
		return nil
	}
	connection.pending++
	return &asyncMetaOperationLease{
		scheduler:  scheduler,
		connection: scheduler.next,
	}
}

func (lease *asyncMetaOperationLease) release() {
	if lease == nil || lease.scheduler == nil {
		return
	}
	lease.scheduler.mu.Lock()
	defer lease.scheduler.mu.Unlock()
	if lease.released {
		return
	}
	lease.released = true
	if lease.connection < 0 || lease.connection >= len(lease.scheduler.connections) {
		return
	}
	connection := &lease.scheduler.connections[lease.connection]
	if connection.pending > 0 {
		connection.pending--
	}
}

func (lease *asyncMetaOperationLease) transportOwner(base string) string {
	if lease == nil || lease.scheduler == nil || base == "" {
		return base
	}
	lease.scheduler.mu.Lock()
	defer lease.scheduler.mu.Unlock()
	if lease.connection < 0 || lease.connection >= len(lease.scheduler.connections) {
		return base
	}
	if lease.scheduler.targets == nil {
		lease.scheduler.targets = make(map[string]*asyncMetaTargetState)
	}
	target := lease.scheduler.targets[base]
	if target == nil {
		target = &asyncMetaTargetState{}
		lease.scheduler.targets[base] = target
	}
	return asyncMetaDerivedTransportOwner(base, lease.connection, target.epoch)
}

func (lease *asyncMetaOperationLease) observeTarget(
	base string,
	maximumTimeouts int,
	timedOut bool,
	responded bool,
) []string {
	if lease == nil || lease.scheduler == nil || base == "" {
		return nil
	}
	lease.scheduler.mu.Lock()
	defer lease.scheduler.mu.Unlock()
	if lease.connection < 0 || lease.connection >= len(lease.scheduler.connections) {
		return nil
	}
	if lease.scheduler.targets == nil {
		lease.scheduler.targets = make(map[string]*asyncMetaTargetState)
	}
	target := lease.scheduler.targets[base]
	if target == nil {
		target = &asyncMetaTargetState{}
		lease.scheduler.targets[base] = target
	}
	if timedOut {
		target.consecutiveTimeouts++
	} else if responded {
		target.consecutiveTimeouts = 0
		return nil
	}
	if !timedOut {
		return nil
	}
	if maximumTimeouts <= 0 || target.consecutiveTimeouts <= maximumTimeouts {
		return nil
	}
	retired := make([]string, 0, len(lease.scheduler.connections))
	for connection := range lease.scheduler.connections {
		retired = append(retired, asyncMetaDerivedTransportOwner(
			base, connection, target.epoch,
		))
	}
	target.epoch++
	target.consecutiveTimeouts = 0
	return retired
}

func asyncMetaDerivedTransportOwner(base string, connection int, epoch uint64) string {
	return base + asyncMetaTransportOwnerMarker + strconv.Itoa(connection) +
		"\x00target-epoch=" + strconv.FormatUint(epoch, 10)
}

func asyncMetaLeaseFromContext(ctx context.Context) *asyncMetaOperationLease {
	if ctx == nil {
		return nil
	}
	lease, _ := ctx.Value(asyncMetaOperationLeaseContextKey{}).(*asyncMetaOperationLease)
	return lease
}

func asyncMetaContextWithLease(
	ctx context.Context,
	configuration *asyncMetaBackendRuntimeConfiguration,
) (context.Context, *asyncMetaOperationLease) {
	if ctx == nil {
		ctx = context.Background()
	}
	lease := configuration.acquire()
	if lease == nil {
		return ctx, nil
	}
	return context.WithValue(ctx, asyncMetaOperationLeaseContextKey{}, lease), lease
}

func (configuration *asyncMetaBackendRuntimeConfiguration) cloneWithMeta(
	meta *metaBackendRuntimeConfiguration,
) *asyncMetaBackendRuntimeConfiguration {
	if configuration == nil {
		return nil
	}
	clone := *configuration
	clone.meta = meta
	return &clone
}
