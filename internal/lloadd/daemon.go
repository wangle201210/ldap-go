package lloadd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"
)

// DaemonTopology is a fully parsed standalone configuration candidate.
// ListenURLs retain configuration order for diagnostics.
type DaemonTopology struct {
	Runtime    RuntimeConfig
	ListenURLs []string
	GentleHUP  bool
}

type DaemonTopologyLoader func(context.Context) (DaemonTopology, error)
type DaemonListenerKey func(string) (string, error)
type DaemonListenFunc func(string) (net.Listener, string, error)
type DaemonPrepareConnectionFunc func(string, RuntimeConfig, net.Conn) (net.Conn, error)

type DaemonOptions struct {
	Load                  DaemonTopologyLoader
	ListenerKey           DaemonListenerKey
	Listen                DaemonListenFunc
	Prepare               DaemonPrepareConnectionFunc
	PrepareConcurrency    int
	MaxRetiredGenerations int
	DrainTimeout          time.Duration
	Logger                *slog.Logger
}

type DaemonReloadResult struct {
	Generation uint64
	Listeners  []string
}

type DaemonSnapshot struct {
	Generation      uint64
	SuccessfulLoads uint64
	FailedLoads     uint64
	Listeners       []string
	Current         ProxyMonitorSnapshot
	Retired         int
	GentleHUP       bool
}

type Daemon struct {
	options DaemonOptions

	reloadMu     sync.Mutex
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	current      *daemonGeneration
	listeners    map[string]*daemonListener
	retired      map[*Proxy]struct{}
	generation   uint64
	successful   uint64
	failed       uint64
	started      bool
	closed       bool
	errors       chan error
	prepareSlots chan struct{}
	wg           sync.WaitGroup
}

type daemonGeneration struct {
	id        uint64
	proxy     *Proxy
	runtime   RuntimeConfig
	gentleHUP bool
}

type daemonListener struct {
	key         string
	raw         string
	description string
	listener    net.Listener

	mu      sync.Mutex
	stopped bool
}

func NewDaemon(options DaemonOptions) (*Daemon, error) {
	if options.Load == nil {
		return nil, errors.New("lloadd daemon topology loader is required")
	}
	if options.ListenerKey == nil {
		return nil, errors.New("lloadd daemon listener key function is required")
	}
	if options.Listen == nil {
		return nil, errors.New("lloadd daemon listen function is required")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	if options.DrainTimeout < 0 {
		return nil, errors.New("lloadd daemon drain timeout cannot be negative")
	}
	if options.DrainTimeout == 0 {
		options.DrainTimeout = 30 * time.Second
	}
	if options.PrepareConcurrency < 0 {
		return nil, errors.New("lloadd daemon prepare concurrency cannot be negative")
	}
	if options.PrepareConcurrency == 0 {
		options.PrepareConcurrency = 32
	}
	if options.MaxRetiredGenerations < 0 {
		return nil, errors.New("lloadd daemon retired generation limit cannot be negative")
	}
	if options.MaxRetiredGenerations == 0 {
		options.MaxRetiredGenerations = 2
	}
	return &Daemon{
		options:      options,
		listeners:    make(map[string]*daemonListener),
		retired:      make(map[*Proxy]struct{}),
		errors:       make(chan error, 1),
		prepareSlots: make(chan struct{}, options.PrepareConcurrency),
	}, nil
}

// Start loads and publishes the initial topology.
func (daemon *Daemon) Start(ctx context.Context) (DaemonReloadResult, error) {
	if ctx == nil {
		return DaemonReloadResult{}, errors.New("lloadd daemon context is required")
	}
	daemon.reloadMu.Lock()

	daemon.mu.Lock()
	if daemon.started {
		daemon.mu.Unlock()
		daemon.reloadMu.Unlock()
		return DaemonReloadResult{}, errors.New("lloadd daemon has already been started")
	}
	if daemon.closed {
		daemon.mu.Unlock()
		daemon.reloadMu.Unlock()
		return DaemonReloadResult{}, errors.New("lloadd daemon is closed")
	}
	daemon.ctx, daemon.cancel = context.WithCancel(ctx)
	daemon.started = true
	daemon.mu.Unlock()

	result, err := daemon.reloadLocked(true)
	daemon.reloadMu.Unlock()
	if err != nil {
		_ = daemon.Close()
		return DaemonReloadResult{}, err
	}
	return result, nil
}

// Reload transactionally publishes a new listener/backend topology. Existing
// connections remain attached to their old proxy generation until they close.
func (daemon *Daemon) Reload(ctx context.Context) (DaemonReloadResult, error) {
	if ctx == nil {
		return DaemonReloadResult{}, errors.New("lloadd reload context is required")
	}
	daemon.reloadMu.Lock()
	defer daemon.reloadMu.Unlock()
	return daemon.reloadLocked(false)
}

func (daemon *Daemon) reloadLocked(initial bool) (DaemonReloadResult, error) {
	daemon.mu.Lock()
	if !daemon.started || daemon.closed {
		daemon.mu.Unlock()
		return DaemonReloadResult{}, errors.New("lloadd daemon is not running")
	}
	rootContext := daemon.ctx
	if !initial && daemon.current != nil &&
		len(daemon.retired) >= daemon.options.MaxRetiredGenerations {
		daemon.failed++
		daemon.mu.Unlock()
		return DaemonReloadResult{}, errors.New("lloadd retired generation limit reached")
	}
	currentListeners := make(map[string]*daemonListener, len(daemon.listeners))
	for key, listener := range daemon.listeners {
		currentListeners[key] = listener
	}
	daemon.mu.Unlock()

	topology, err := daemon.options.Load(rootContext)
	if err != nil {
		daemon.recordFailedLoad(initial)
		return DaemonReloadResult{}, fmt.Errorf("load lloadd topology: %w", err)
	}
	proxy, err := NewProxy(topology.Runtime)
	if err != nil {
		daemon.recordFailedLoad(initial)
		return DaemonReloadResult{}, fmt.Errorf("build lloadd topology: %w", err)
	}

	candidate := make(map[string]*daemonListener, len(topology.ListenURLs))
	added := make([]*daemonListener, 0, len(topology.ListenURLs))
	rollback := func() {
		for _, listener := range added {
			listener.stop()
		}
		_ = proxy.Close()
	}
	for _, raw := range topology.ListenURLs {
		key, keyErr := daemon.options.ListenerKey(raw)
		if keyErr != nil {
			rollback()
			daemon.recordFailedLoad(initial)
			return DaemonReloadResult{}, fmt.Errorf("key lloadd listener %q: %w", raw, keyErr)
		}
		if _, duplicate := candidate[key]; duplicate {
			rollback()
			daemon.recordFailedLoad(initial)
			return DaemonReloadResult{}, fmt.Errorf("duplicate lloadd listener %q", raw)
		}
		if existing := currentListeners[key]; existing != nil {
			candidate[key] = existing
			continue
		}
		listener, description, listenErr := daemon.options.Listen(raw)
		if listenErr != nil {
			rollback()
			daemon.recordFailedLoad(initial)
			return DaemonReloadResult{}, listenErr
		}
		managed := &daemonListener{
			key:         key,
			raw:         raw,
			description: description,
			listener:    listener,
		}
		candidate[key] = managed
		added = append(added, managed)
	}
	if len(candidate) == 0 {
		rollback()
		daemon.recordFailedLoad(initial)
		return DaemonReloadResult{}, errors.New("lloadd topology has no listeners")
	}
	if err := proxy.Start(rootContext); err != nil {
		rollback()
		daemon.recordFailedLoad(initial)
		return DaemonReloadResult{}, fmt.Errorf("start lloadd topology: %w", err)
	}

	daemon.mu.Lock()
	if daemon.closed {
		daemon.mu.Unlock()
		rollback()
		return DaemonReloadResult{}, errors.New("lloadd daemon is closed")
	}
	oldGeneration := daemon.current
	removed := make([]*daemonListener, 0)
	for key, listener := range daemon.listeners {
		if candidate[key] == nil {
			removed = append(removed, listener)
		}
	}
	daemon.generation++
	generation := &daemonGeneration{
		id:        daemon.generation,
		proxy:     proxy,
		runtime:   topology.Runtime,
		gentleHUP: topology.GentleHUP,
	}
	daemon.current = generation
	daemon.listeners = candidate
	daemon.successful++
	result := DaemonReloadResult{
		Generation: generation.id,
		Listeners:  daemon.listenerDescriptionsLocked(),
	}
	if oldGeneration != nil {
		daemon.retired[oldGeneration.proxy] = struct{}{}
	}
	for _, listener := range added {
		daemon.wg.Add(1)
		go daemon.acceptLoop(listener)
	}
	daemon.mu.Unlock()

	for _, listener := range removed {
		listener.stop()
	}
	if oldGeneration != nil {
		daemon.wg.Add(1)
		go daemon.drain(oldGeneration.proxy)
	}
	daemon.options.Logger.Info(
		"lloadd topology published",
		"generation", result.Generation,
		"listeners", len(result.Listeners),
	)
	return result, nil
}

func (daemon *Daemon) recordFailedLoad(initial bool) {
	if initial {
		return
	}
	daemon.mu.Lock()
	daemon.failed++
	daemon.mu.Unlock()
}

func (daemon *Daemon) acceptLoop(listener *daemonListener) {
	defer daemon.wg.Done()
	for {
		connection, err := listener.listener.Accept()
		if err != nil {
			if listener.isStopped() || errors.Is(err, net.ErrClosed) {
				return
			}
			daemon.reportError(fmt.Errorf("accept lloadd client on %s: %w", listener.description, err))
			return
		}

		daemon.mu.Lock()
		generation := daemon.current
		valid := !daemon.closed && generation != nil && daemon.listeners[listener.key] == listener
		daemon.mu.Unlock()
		if !valid {
			_ = connection.Close()
			continue
		}
		select {
		case daemon.prepareSlots <- struct{}{}:
			daemon.wg.Add(1)
			go daemon.prepareAndServe(listener, generation, connection)
		default:
			_ = connection.Close()
			daemon.options.Logger.Warn(
				"rejecting lloadd client because listener preparation is saturated",
				"listener", listener.description,
			)
		}
	}
}

func (daemon *Daemon) prepareAndServe(
	listener *daemonListener,
	generation *daemonGeneration,
	connection net.Conn,
) {
	defer daemon.wg.Done()
	defer func() { <-daemon.prepareSlots }()
	if daemon.options.Prepare != nil {
		prepared, err := daemon.options.Prepare(listener.raw, generation.runtime, connection)
		if err != nil {
			_ = connection.Close()
			daemon.options.Logger.Debug(
				"rejecting lloadd client during listener preparation",
				"listener", listener.description,
				"error", err,
			)
			return
		}
		connection = prepared
	}
	if err := generation.proxy.ServeConnection(connection); err != nil {
		_ = connection.Close()
		if !errors.Is(err, ErrProxyClosed) {
			daemon.reportError(fmt.Errorf("serve lloadd client: %w", err))
		}
	}
}

func (daemon *Daemon) drain(proxy *Proxy) {
	defer daemon.wg.Done()
	ctx, cancel := daemon.drainContext(daemon.ctx)
	defer cancel()
	_ = proxy.Drain(ctx)
	_ = proxy.Close()
	daemon.mu.Lock()
	delete(daemon.retired, proxy)
	daemon.mu.Unlock()
}

func (daemon *Daemon) reportError(err error) {
	select {
	case daemon.errors <- err:
	default:
	}
}

func (daemon *Daemon) Errors() <-chan error {
	return daemon.errors
}

func (daemon *Daemon) Snapshot() DaemonSnapshot {
	daemon.mu.Lock()
	snapshot := DaemonSnapshot{
		Generation:      daemon.generation,
		SuccessfulLoads: daemon.successful,
		FailedLoads:     daemon.failed,
		Listeners:       daemon.listenerDescriptionsLocked(),
		Retired:         len(daemon.retired),
	}
	current := daemon.current
	if current != nil {
		snapshot.GentleHUP = current.gentleHUP
	}
	daemon.mu.Unlock()
	if current != nil {
		snapshot.Current = current.proxy.MonitorSnapshot()
	}
	return snapshot
}

func (daemon *Daemon) listenerDescriptionsLocked() []string {
	descriptions := make([]string, 0, len(daemon.listeners))
	for _, listener := range daemon.listeners {
		descriptions = append(descriptions, listener.description)
	}
	sort.Strings(descriptions)
	return descriptions
}

func (daemon *Daemon) Close() error {
	return daemon.Shutdown(context.Background(), false)
}

// Shutdown stops accepting new clients and either closes all generations
// immediately or lets current operations finish before the drain deadline.
func (daemon *Daemon) Shutdown(ctx context.Context, gentle bool) error {
	if ctx == nil {
		return errors.New("lloadd daemon shutdown context is required")
	}
	daemon.reloadMu.Lock()
	defer daemon.reloadMu.Unlock()

	daemon.mu.Lock()
	if daemon.closed {
		daemon.mu.Unlock()
		return nil
	}
	daemon.closed = true
	cancel := daemon.cancel
	listeners := make([]*daemonListener, 0, len(daemon.listeners))
	for _, listener := range daemon.listeners {
		listeners = append(listeners, listener)
	}
	proxies := make([]*Proxy, 0, len(daemon.retired)+1)
	if daemon.current != nil {
		proxies = append(proxies, daemon.current.proxy)
	}
	for proxy := range daemon.retired {
		proxies = append(proxies, proxy)
	}
	daemon.mu.Unlock()

	var result error
	for _, listener := range listeners {
		if err := listener.stop(); err != nil {
			result = errors.Join(result, err)
		}
	}
	if gentle {
		drainCtx, drainCancel := daemon.drainContext(ctx)
		var drains sync.WaitGroup
		for _, proxy := range proxies {
			drains.Add(1)
			go func(proxy *Proxy) {
				defer drains.Done()
				_ = proxy.Drain(drainCtx)
			}(proxy)
		}
		drains.Wait()
		drainCancel()
	}
	if cancel != nil {
		cancel()
	}
	for _, proxy := range proxies {
		if err := proxy.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	daemon.wg.Wait()
	return result
}

func (daemon *Daemon) drainContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if daemon.options.DrainTimeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, daemon.options.DrainTimeout)
}

func (listener *daemonListener) stop() error {
	listener.mu.Lock()
	if listener.stopped {
		listener.mu.Unlock()
		return nil
	}
	listener.stopped = true
	listener.mu.Unlock()
	return listener.listener.Close()
}

func (listener *daemonListener) isStopped() bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.stopped
}
