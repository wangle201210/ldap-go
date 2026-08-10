// Package lloadd contains the scheduling primitives used by an LDAP-aware
// load-balancing proxy.
package lloadd

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"
)

var (
	// ErrBusy means that a suitable upstream pool exists, but every matching
	// backend or connection is at capacity or temporarily unable to accept work.
	ErrBusy = errors.New("lloadd: upstream busy")
	// ErrUnavailable means that no established connection exists in a suitable
	// pool. Unlike ErrBusy, an unavailable tier permits fallback to the next tier.
	ErrUnavailable = errors.New("lloadd: upstream unavailable")
	// ErrInvalidAffinity means that a request names inconsistent backend and
	// connection affinity targets.
	ErrInvalidAffinity = errors.New("lloadd: invalid affinity")
)

// Policy is the backend selection policy for a tier.
type Policy string

const (
	PolicyRoundRobin Policy = "roundrobin"
	PolicyWeighted   Policy = "weighted"
	PolicyBestOf     Policy = "bestof"
)

// Pool distinguishes ordinary multiplexed upstreams from upstreams reserved
// for client Bind operations.
type Pool uint8

const (
	PoolRegular Pool = iota
	PoolBind
	poolCount
)

// ConnectionState describes whether a configured connection currently belongs
// to its established pool and whether it can accept another operation.
type ConnectionState uint8

const (
	// ConnectionReady is the zero value so configured connections start ready.
	ConnectionReady ConnectionState = iota
	// ConnectionBusy remains a member of the pool and therefore blocks tier
	// fallback, but it cannot currently accept an operation.
	ConnectionBusy
	// ConnectionUnavailable removes the connection from its established pool.
	ConnectionUnavailable
)

// RandomSource is the minimal random interface used by weighted and bestof
// policies. Scheduler serializes calls, so implementations need not be safe for
// concurrent use.
type RandomSource interface {
	Intn(n int) int
}

// SchedulerConfig defines an ordered set of fallback tiers.
type SchedulerConfig struct {
	Tiers  []SchedulerTierConfig
	Random RandomSource
}

// SchedulerTierConfig defines one scheduling tier. Tiers are considered in slice order.
type SchedulerTierConfig struct {
	ID       string
	Policy   Policy
	Backends []SchedulerBackendConfig
}

// SchedulerBackendConfig defines backend-wide capacity and its upstream connections.
// MaxPending and connection limits use zero to mean unlimited. Weight follows
// OpenLDAP semantics: weighted treats larger values as more likely, while
// bestof multiplies latency by Weight, making larger values less favorable.
type SchedulerBackendConfig struct {
	ID          string
	Weight      int
	MaxPending  int
	Connections []SchedulerConnectionConfig
}

// SchedulerConnectionConfig defines one stable upstream identity. A connection starts
// in State; the zero value is ConnectionReady.
type SchedulerConnectionConfig struct {
	ID         string
	Pool       Pool
	State      ConnectionState
	MaxPending int
}

// Affinity restricts a request to a backend or a specific connection. A
// ConnectionID alone implies its owning backend. When both fields are set they
// must refer to the same backend.
type Affinity struct {
	BackendID    string
	ConnectionID string
}

// SelectRequest describes the upstream pool and optional fixed affinity for an
// operation.
type SelectRequest struct {
	Pool     Pool
	Affinity Affinity
}

// Scheduler atomically selects upstreams and reserves both backend and
// connection pending capacity. It is safe for concurrent use.
type Scheduler struct {
	mu          sync.Mutex
	random      RandomSource
	now         func() time.Time
	tiers       []*tierState
	backends    map[string]*backendState
	connections map[string]*connectionState
}

type tierState struct {
	id       string
	policy   Policy
	backends []*backendState
	next     int
}

type backendState struct {
	id             string
	tier           *tierState
	weight         int
	maxPending     int
	pending        int
	connections    []*connectionState
	nextConnection [poolCount]int
	latencySamples uint64
	meanLatencyNS  float64
	fitnessSamples uint64
	fitnessTimeUS  float64
	fitnessUS      float64
	fitnessUpdated int64
	fitnessRolled  int64
}

type connectionState struct {
	id         string
	backend    *backendState
	pool       Pool
	state      ConnectionState
	maxPending int
	pending    int
}

// Lease is an atomic reservation of one backend and connection pending slot.
// Call Release exactly once when the operation is no longer in flight. Release
// is idempotent to make timeout/response races harmless.
type Lease struct {
	TierID       string
	BackendID    string
	ConnectionID string
	Pool         Pool

	token *leaseToken
}

type leaseToken struct {
	scheduler     *Scheduler
	backend       *backendState
	connection    *connectionState
	released      bool
	latencyStored bool
}

// Snapshot is a point-in-time copy of scheduler state.
type Snapshot struct {
	Backends    []BackendSnapshot
	Connections []ConnectionSnapshot
}

// BackendSnapshot exposes capacity and first-response observations for a
// backend.
type BackendSnapshot struct {
	TierID                   string
	BackendID                string
	Pending                  int
	MaxPending               int
	FirstResponseSamples     uint64
	MeanFirstResponseLatency time.Duration
}

// ConnectionSnapshot exposes pool membership and pending capacity for a
// connection.
type ConnectionSnapshot struct {
	BackendID  string
	ID         string
	Pool       Pool
	State      ConnectionState
	Pending    int
	MaxPending int
}

// NewScheduler validates and copies config into a concurrent scheduler.
func NewScheduler(config SchedulerConfig) (*Scheduler, error) {
	return newScheduler(config, time.Now)
}

func newScheduler(
	config SchedulerConfig,
	now func() time.Time,
) (*Scheduler, error) {
	if now == nil {
		now = time.Now
	}
	random := config.Random
	if random == nil {
		random = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	startedAt := now()

	scheduler := &Scheduler{
		random:      random,
		now:         now,
		backends:    make(map[string]*backendState),
		connections: make(map[string]*connectionState),
	}
	tierIDs := make(map[string]struct{}, len(config.Tiers))

	for tierIndex, tierConfig := range config.Tiers {
		if tierConfig.ID == "" {
			return nil, fmt.Errorf("lloadd: tier %d has an empty ID", tierIndex)
		}
		if _, exists := tierIDs[tierConfig.ID]; exists {
			return nil, fmt.Errorf("lloadd: duplicate tier ID %q", tierConfig.ID)
		}
		tierIDs[tierConfig.ID] = struct{}{}
		if !validPolicy(tierConfig.Policy) {
			return nil, fmt.Errorf(
				"lloadd: tier %q has invalid policy %q",
				tierConfig.ID,
				tierConfig.Policy,
			)
		}

		tier := &tierState{id: tierConfig.ID, policy: tierConfig.Policy}
		var totalWeight int
		for backendIndex, backendConfig := range tierConfig.Backends {
			if backendConfig.ID == "" {
				return nil, fmt.Errorf(
					"lloadd: tier %q backend %d has an empty ID",
					tierConfig.ID,
					backendIndex,
				)
			}
			if _, exists := scheduler.backends[backendConfig.ID]; exists {
				return nil, fmt.Errorf(
					"lloadd: duplicate backend ID %q",
					backendConfig.ID,
				)
			}
			if backendConfig.Weight < 0 {
				return nil, fmt.Errorf(
					"lloadd: backend %q has negative weight",
					backendConfig.ID,
				)
			}
			if backendConfig.MaxPending < 0 {
				return nil, fmt.Errorf(
					"lloadd: backend %q has negative MaxPending",
					backendConfig.ID,
				)
			}
			if backendConfig.Weight > math.MaxInt-totalWeight-1 {
				return nil, fmt.Errorf(
					"lloadd: tier %q total backend weight is too large",
					tierConfig.ID,
				)
			}
			totalWeight += backendConfig.Weight

			backend := &backendState{
				id:            backendConfig.ID,
				tier:          tier,
				weight:        backendConfig.Weight,
				maxPending:    backendConfig.MaxPending,
				fitnessRolled: startedAt.Unix(),
			}
			for connectionIndex, connectionConfig := range backendConfig.Connections {
				if connectionConfig.ID == "" {
					return nil, fmt.Errorf(
						"lloadd: backend %q connection %d has an empty ID",
						backendConfig.ID,
						connectionIndex,
					)
				}
				if _, exists := scheduler.connections[connectionConfig.ID]; exists {
					return nil, fmt.Errorf(
						"lloadd: duplicate connection ID %q",
						connectionConfig.ID,
					)
				}
				if !validPool(connectionConfig.Pool) {
					return nil, fmt.Errorf(
						"lloadd: connection %q has invalid pool %d",
						connectionConfig.ID,
						connectionConfig.Pool,
					)
				}
				if !validConnectionState(connectionConfig.State) {
					return nil, fmt.Errorf(
						"lloadd: connection %q has invalid state %d",
						connectionConfig.ID,
						connectionConfig.State,
					)
				}
				if connectionConfig.MaxPending < 0 {
					return nil, fmt.Errorf(
						"lloadd: connection %q has negative MaxPending",
						connectionConfig.ID,
					)
				}

				connection := &connectionState{
					id:         connectionConfig.ID,
					backend:    backend,
					pool:       connectionConfig.Pool,
					state:      connectionConfig.State,
					maxPending: connectionConfig.MaxPending,
				}
				backend.connections = append(backend.connections, connection)
				scheduler.connections[connection.id] = connection
			}

			tier.backends = append(tier.backends, backend)
			scheduler.backends[backend.id] = backend
		}

		scheduler.tiers = append(scheduler.tiers, tier)
	}

	return scheduler, nil
}

// Select chooses an upstream and reserves one pending slot. Without affinity,
// lower tiers are examined only when every backend in the current tier has no
// established connection in the requested pool.
func (scheduler *Scheduler) Select(request SelectRequest) (*Lease, error) {
	if scheduler == nil {
		return nil, ErrUnavailable
	}
	if !validPool(request.Pool) {
		return nil, fmt.Errorf("lloadd: invalid pool %d", request.Pool)
	}

	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()

	if request.Affinity.ConnectionID != "" {
		return scheduler.selectConnectionAffinityLocked(request)
	}
	if request.Affinity.BackendID != "" {
		backend := scheduler.backends[request.Affinity.BackendID]
		if backend == nil {
			return nil, ErrUnavailable
		}
		lease, result := scheduler.tryBackendLocked(backend, request.Pool)
		return selectionResult(lease, result)
	}

	for _, tier := range scheduler.tiers {
		lease, result := scheduler.selectTierLocked(tier, request.Pool)
		switch result {
		case resultSelected:
			return lease, nil
		case resultBusy:
			return nil, ErrBusy
		case resultUnavailable:
			continue
		}
	}
	return nil, ErrUnavailable
}

// reserveOwnedConnection reserves a connection that is busy only because it
// is exclusively owned by the requesting client. The caller proves ownership;
// backend capacity and the supplied per-connection limit still apply.
func (scheduler *Scheduler) reserveOwnedConnection(
	connectionID string,
	maxPending int,
) (*Lease, error) {
	if scheduler == nil {
		return nil, ErrUnavailable
	}
	if maxPending < 0 {
		return nil, fmt.Errorf("lloadd: negative owned-connection pending limit")
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	connection := scheduler.connections[connectionID]
	if connection == nil || connection.state == ConnectionUnavailable {
		return nil, ErrUnavailable
	}
	if atCapacity(connection.backend.pending, connection.backend.maxPending) ||
		atCapacity(connection.pending, maxPending) {
		return nil, ErrBusy
	}
	return scheduler.reserveLocked(connection.backend, connection), nil
}

// reserveSignalingConnection accounts for a protocol operation that must use
// an exact live connection even when the target operation already fills its
// configured capacity. The caller is responsible for proving that relationship.
func (scheduler *Scheduler) reserveSignalingConnection(connectionID string) (*Lease, error) {
	if scheduler == nil {
		return nil, ErrUnavailable
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	connection := scheduler.connections[connectionID]
	if connection == nil || connection.state == ConnectionUnavailable {
		return nil, ErrUnavailable
	}
	return scheduler.reserveLocked(connection.backend, connection), nil
}

// SetConnectionState updates established-pool membership or temporary busy
// state without disturbing existing leases.
func (scheduler *Scheduler) SetConnectionState(
	connectionID string,
	state ConnectionState,
) error {
	if scheduler == nil {
		return ErrUnavailable
	}
	if !validConnectionState(state) {
		return fmt.Errorf("lloadd: invalid connection state %d", state)
	}

	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	connection := scheduler.connections[connectionID]
	if connection == nil {
		return fmt.Errorf("lloadd: unknown connection %q", connectionID)
	}
	connection.state = state
	return nil
}

// Snapshot returns stable, configuration-order scheduler statistics.
func (scheduler *Scheduler) Snapshot() Snapshot {
	if scheduler == nil {
		return Snapshot{}
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.rollBestOfFitnessLocked(scheduler.now())

	var snapshot Snapshot
	for _, tier := range scheduler.tiers {
		for _, backend := range tier.backends {
			snapshot.Backends = append(snapshot.Backends, BackendSnapshot{
				TierID:                   tier.id,
				BackendID:                backend.id,
				Pending:                  backend.pending,
				MaxPending:               backend.maxPending,
				FirstResponseSamples:     backend.latencySamples,
				MeanFirstResponseLatency: durationFromFloat(backend.meanLatencyNS),
			})
			for _, connection := range backend.connections {
				snapshot.Connections = append(snapshot.Connections, ConnectionSnapshot{
					BackendID:  backend.id,
					ID:         connection.id,
					Pool:       connection.pool,
					State:      connection.state,
					Pending:    connection.pending,
					MaxPending: connection.maxPending,
				})
			}
		}
	}
	return snapshot
}

// BackendAffinity returns an affinity that keeps future operations on the
// selected backend while allowing connection-level round robin.
func (lease *Lease) BackendAffinity() Affinity {
	if lease == nil {
		return Affinity{}
	}
	return Affinity{BackendID: lease.BackendID}
}

// ConnectionAffinity returns an affinity that fixes future operations to the
// selected connection.
func (lease *Lease) ConnectionAffinity() Affinity {
	if lease == nil {
		return Affinity{}
	}
	return Affinity{
		BackendID:    lease.BackendID,
		ConnectionID: lease.ConnectionID,
	}
}

// RecordFirstResponse records this operation's first-response latency once.
// It may race with Release; a valid first response is retained in either order.
func (lease *Lease) RecordFirstResponse(latency time.Duration) bool {
	if lease == nil || lease.token == nil || lease.token.scheduler == nil ||
		latency < 0 {
		return false
	}
	token := lease.token
	scheduler := token.scheduler
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if token.latencyStored {
		return false
	}
	token.latencyStored = true
	backend := token.backend
	if backend.tier.policy == PolicyBestOf {
		scheduler.rollBackendFitnessLocked(backend, scheduler.now())
		backend.fitnessSamples++
		backend.fitnessTimeUS += float64(latency / time.Microsecond)
	}
	backend.latencySamples++
	sample := float64(latency)
	backend.meanLatencyNS += (sample - backend.meanLatencyNS) /
		float64(backend.latencySamples)
	return true
}

// Release frees both pending slots. It reports whether this call performed the
// release; subsequent calls return false.
func (lease *Lease) Release() bool {
	if lease == nil || lease.token == nil || lease.token.scheduler == nil {
		return false
	}
	token := lease.token
	scheduler := token.scheduler
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if token.released {
		return false
	}
	token.released = true
	if token.backend.pending > 0 {
		token.backend.pending--
	}
	if token.connection.pending > 0 {
		token.connection.pending--
	}
	return true
}

// Complete records a first-response latency and releases the reservation.
func (lease *Lease) Complete(firstResponseLatency time.Duration) {
	lease.RecordFirstResponse(firstResponseLatency)
	lease.Release()
}

type selectResult uint8

const (
	resultUnavailable selectResult = iota
	resultBusy
	resultSelected
)

func (scheduler *Scheduler) selectConnectionAffinityLocked(
	request SelectRequest,
) (*Lease, error) {
	connection := scheduler.connections[request.Affinity.ConnectionID]
	if connection == nil {
		return nil, ErrUnavailable
	}
	if request.Affinity.BackendID != "" &&
		request.Affinity.BackendID != connection.backend.id {
		return nil, ErrInvalidAffinity
	}
	if connection.pool != request.Pool ||
		connection.state == ConnectionUnavailable {
		return nil, ErrUnavailable
	}
	backend := connection.backend
	if atCapacity(backend.pending, backend.maxPending) ||
		connection.state != ConnectionReady ||
		atCapacity(connection.pending, connection.maxPending) {
		return nil, ErrBusy
	}
	return scheduler.reserveLocked(backend, connection), nil
}

func (scheduler *Scheduler) selectTierLocked(
	tier *tierState,
	pool Pool,
) (*Lease, selectResult) {
	switch tier.policy {
	case PolicyRoundRobin:
		return scheduler.selectRoundRobinLocked(tier, pool)
	case PolicyWeighted:
		return scheduler.selectWeightedLocked(tier, pool)
	case PolicyBestOf:
		return scheduler.selectBestOfLocked(tier, pool)
	default:
		return nil, resultUnavailable
	}
}

func (scheduler *Scheduler) selectRoundRobinLocked(
	tier *tierState,
	pool Pool,
) (*Lease, selectResult) {
	n := len(tier.backends)
	if n == 0 {
		return nil, resultUnavailable
	}
	busy := false
	for offset := 0; offset < n; offset++ {
		index := (tier.next + offset) % n
		lease, result := scheduler.tryBackendLocked(tier.backends[index], pool)
		if result == resultSelected {
			tier.next = (index + 1) % n
			return lease, resultSelected
		}
		busy = busy || result == resultBusy
	}
	if busy {
		return nil, resultBusy
	}
	return nil, resultUnavailable
}

func (scheduler *Scheduler) selectWeightedLocked(
	tier *tierState,
	pool Pool,
) (*Lease, selectResult) {
	order := scheduler.weightedOrderLocked(tier.backends)
	busy := false
	for _, backend := range order {
		lease, result := scheduler.tryBackendLocked(backend, pool)
		if result == resultSelected {
			return lease, resultSelected
		}
		busy = busy || result == resultBusy
	}
	if busy {
		return nil, resultBusy
	}
	return nil, resultUnavailable
}

func (scheduler *Scheduler) selectBestOfLocked(
	tier *tierState,
	pool Pool,
) (*Lease, selectResult) {
	now := scheduler.now()
	for _, backend := range tier.backends {
		scheduler.rollBackendFitnessLocked(backend, now)
	}

	n := len(tier.backends)
	if n < 2 {
		return scheduler.selectRoundRobinLocked(tier, pool)
	}

	firstIndex := scheduler.randomNLocked(n)
	secondIndex := scheduler.randomNLocked(n - 1)
	if secondIndex >= firstIndex {
		secondIndex++
	}
	firstIndex = (tier.next + firstIndex) % n
	secondIndex = (tier.next + secondIndex) % n
	first := tier.backends[firstIndex]
	second := tier.backends[secondIndex]
	preferred := second
	if backendFitnessAt(first, now) < backendFitnessAt(second, now) {
		preferred = first
	}

	lease, preferredResult := scheduler.tryBackendLocked(preferred, pool)
	if preferredResult == resultSelected {
		selectedIndex := backendIndex(tier.backends, preferred)
		tier.next = (selectedIndex + 1) % n
		return lease, resultSelected
	}

	busy := preferredResult == resultBusy
	for offset := 0; offset < n; offset++ {
		index := (tier.next + offset) % n
		backend := tier.backends[index]
		lease, result := scheduler.tryBackendLocked(backend, pool)
		if result == resultSelected {
			tier.next = (index + 1) % n
			return lease, resultSelected
		}
		busy = busy || result == resultBusy
	}
	if busy {
		return nil, resultBusy
	}
	return nil, resultUnavailable
}

func (scheduler *Scheduler) tryBackendLocked(
	backend *backendState,
	pool Pool,
) (*Lease, selectResult) {
	n := len(backend.connections)
	if n == 0 {
		return nil, resultUnavailable
	}

	poolExists := false
	for _, connection := range backend.connections {
		if connection.pool == pool && connection.state != ConnectionUnavailable {
			poolExists = true
			break
		}
	}
	if !poolExists {
		return nil, resultUnavailable
	}
	if atCapacity(backend.pending, backend.maxPending) {
		return nil, resultBusy
	}

	start := backend.nextConnection[pool]
	for offset := 0; offset < n; offset++ {
		index := (start + offset) % n
		connection := backend.connections[index]
		if connection.pool != pool || connection.state != ConnectionReady ||
			atCapacity(connection.pending, connection.maxPending) {
			continue
		}
		backend.nextConnection[pool] = (index + 1) % n
		return scheduler.reserveLocked(backend, connection), resultSelected
	}
	return nil, resultBusy
}

func (scheduler *Scheduler) reserveLocked(
	backend *backendState,
	connection *connectionState,
) *Lease {
	backend.pending++
	connection.pending++
	return &Lease{
		TierID:       backend.tier.id,
		BackendID:    backend.id,
		ConnectionID: connection.id,
		Pool:         connection.pool,
		token: &leaseToken{
			scheduler:  scheduler,
			backend:    backend,
			connection: connection,
		},
	}
}

func (scheduler *Scheduler) weightedOrderLocked(
	backends []*backendState,
) []*backendState {
	remaining := append([]*backendState(nil), backends...)
	for i := 1; i < len(remaining); i++ {
		for j := i; j > 0 && remaining[j].weight < remaining[j-1].weight; j-- {
			remaining[j], remaining[j-1] = remaining[j-1], remaining[j]
		}
	}

	order := make([]*backendState, 0, len(remaining))
	for len(remaining) > 0 {
		total := 0
		for _, backend := range remaining {
			total += backend.weight
		}
		if total == 0 {
			for len(remaining) > 0 {
				index := scheduler.randomNLocked(len(remaining))
				order = append(order, remaining[index])
				remaining = append(remaining[:index], remaining[index+1:]...)
			}
			break
		}

		zeroWeight := remaining[0].weight == 0
		drawRange := total
		if zeroWeight {
			// Reserve one draw for the first zero-weight backend, matching the
			// small chance created by OpenLDAP's RFC 2782 ordering.
			drawRange++
		}
		draw := scheduler.randomNLocked(drawRange)
		selected := len(remaining) - 1
		if zeroWeight && draw == 0 {
			selected = 0
			order = append(order, remaining[selected])
			remaining = append(remaining[:selected], remaining[selected+1:]...)
			continue
		}
		if zeroWeight {
			draw--
		}
		for index, backend := range remaining {
			if backend.weight == 0 {
				continue
			}
			if draw < backend.weight {
				selected = index
				break
			}
			draw -= backend.weight
		}
		order = append(order, remaining[selected])
		remaining = append(remaining[:selected], remaining[selected+1:]...)
	}
	return order
}

func (scheduler *Scheduler) randomNLocked(n int) int {
	if n <= 1 {
		return 0
	}
	value := scheduler.random.Intn(n) % n
	if value < 0 {
		value += n
	}
	return value
}

func selectionResult(lease *Lease, result selectResult) (*Lease, error) {
	switch result {
	case resultSelected:
		return lease, nil
	case resultBusy:
		return nil, ErrBusy
	default:
		return nil, ErrUnavailable
	}
}

func (scheduler *Scheduler) rollBestOfFitnessLocked(now time.Time) {
	for _, tier := range scheduler.tiers {
		if tier.policy != PolicyBestOf {
			continue
		}
		for _, backend := range tier.backends {
			scheduler.rollBackendFitnessLocked(backend, now)
		}
	}
}

func (scheduler *Scheduler) rollBackendFitnessLocked(
	backend *backendState,
	now time.Time,
) {
	nowSecond := now.Unix()
	if nowSecond <= backend.fitnessRolled {
		return
	}
	backend.fitnessRolled = nowSecond

	steps := nowSecond - backend.fitnessUpdated
	if backend.weight == 0 || steps <= 0 {
		return
	}

	count := backend.fitnessSamples
	total := backend.fitnessTimeUS
	backend.fitnessSamples = 0
	backend.fitnessTimeUS = 0
	if count == 0 {
		return
	}

	latest := total * float64(backend.weight) / float64(count)
	oldWeight := 0.5
	if steps > 10 {
		oldWeight = 0
	} else if steps > 1 {
		oldWeight = math.Exp2(-float64(steps))
	}
	backend.fitnessUS = oldWeight*backend.fitnessUS +
		(1-oldWeight)*latest
	backend.fitnessUpdated = nowSecond
}

func backendFitnessAt(backend *backendState, now time.Time) float64 {
	if backend.fitnessSamples == 0 {
		return backend.fitnessUS
	}

	latest := backend.fitnessTimeUS * float64(backend.weight) /
		float64(backend.fitnessSamples)
	// OpenLDAP's bestof_cmp blends the current window according to tv_usec.
	// This algebraic form is the finite limit of its factor expression at zero.
	fraction := float64(now.Nanosecond()/int(time.Microsecond)) / 1_000_000
	oldWeight := math.Exp2(-fraction)
	return oldWeight*backend.fitnessUS + (1-oldWeight)*latest
}

func backendIndex(backends []*backendState, target *backendState) int {
	for index, backend := range backends {
		if backend == target {
			return index
		}
	}
	return 0
}

func atCapacity(pending, maximum int) bool {
	return maximum > 0 && pending >= maximum
}

func validPolicy(policy Policy) bool {
	switch policy {
	case PolicyRoundRobin, PolicyWeighted, PolicyBestOf:
		return true
	default:
		return false
	}
}

func validPool(pool Pool) bool {
	return pool < poolCount
}

func validConnectionState(state ConnectionState) bool {
	return state <= ConnectionUnavailable
}

func durationFromFloat(nanoseconds float64) time.Duration {
	if nanoseconds >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	if nanoseconds <= float64(math.MinInt64) {
		return time.Duration(math.MinInt64)
	}
	return time.Duration(math.Round(nanoseconds))
}
