package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const monitorGeneralizedTimeLayout = "20060102150405Z"

var monitorOperationNames = [...]string{
	"Bind",
	"Unbind",
	"Search",
	"Compare",
	"Modify",
	"Modrdn",
	"Add",
	"Delete",
	"Abandon",
	"Extended",
}

type monitorOperationCounter struct {
	initiated atomic.Uint64
	completed atomic.Uint64
}

type monitorState struct {
	startedAt time.Time

	mu               sync.RWMutex
	connections      map[uint64]*monitorConnection
	listeners        map[string]string
	totalConnections uint64
	debugLevels      []string
	logLevels        []string
	logRouteState    atomic.Uint64

	operations [len(monitorOperationNames)]monitorOperationCounter
	bytes      atomic.Uint64
	pdus       atomic.Uint64
	entries    atomic.Uint64
	referrals  atomic.Uint64
}

type monitorConnection struct {
	mu sync.RWMutex

	id              uint64
	protocol        int
	authorizationDN string
	localAddress    string
	peerAddress     string
	peerDomain      string
	listener        string
	startedAt       time.Time
	activityAt      time.Time
	received        uint64
	pending         uint64
	executing       uint64
	completed       uint64
	gets            uint64
	reads           uint64
	writes          uint64
	writeWaiter     bool
}

type monitorConnectionSnapshot struct {
	id              uint64
	protocol        int
	authorizationDN string
	localAddress    string
	peerAddress     string
	peerDomain      string
	listener        string
	startedAt       time.Time
	activityAt      time.Time
	received        uint64
	pending         uint64
	executing       uint64
	completed       uint64
	gets            uint64
	reads           uint64
	writes          uint64
	writeWaiter     bool
}

func newMonitorState() *monitorState {
	return &monitorState{
		startedAt:   time.Now().UTC(),
		connections: make(map[uint64]*monitorConnection),
		listeners:   make(map[string]string),
		debugLevels: []string{"0"},
		logLevels:   []string{"0"},
	}
}

func (monitor *monitorState) loggingSnapshot() ([]string, []string) {
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	return append([]string(nil), monitor.debugLevels...),
		append([]string(nil), monitor.logLevels...)
}

func (monitor *monitorState) setLogging(debugLevels, logLevels []string) {
	mask := compileMonitorLogMask(logLevels)
	monitor.mu.Lock()
	monitor.debugLevels = append([]string(nil), debugLevels...)
	monitor.logLevels = append([]string(nil), logLevels...)
	monitor.logRouteState.Store(monitorLogRouteActive | uint64(uint32(mask)))
	monitor.mu.Unlock()
}

func (monitor *monitorState) enableLogRouting() {
	monitor.mu.Lock()
	mask := compileMonitorLogMask(monitor.logLevels)
	monitor.logRouteState.Store(monitorLogRouteActive | uint64(uint32(mask)))
	monitor.mu.Unlock()
}

func (monitor *monitorState) logRoute() (monitorLogCategory, bool) {
	state := monitor.logRouteState.Load()
	return monitorLogCategory(uint32(state)), state&monitorLogRouteActive != 0
}

func (monitor *monitorState) registerConnection(
	id uint64,
	connection net.Conn,
	implicitTLS bool,
) *monitorConnection {
	now := time.Now().UTC()
	localAddress := monitorAddress(connection.LocalAddr())
	listener := monitorListenerURL(connection.LocalAddr(), implicitTLS)
	tracked := &monitorConnection{
		id:           id,
		protocol:     3,
		localAddress: localAddress,
		peerAddress:  monitorAddress(connection.RemoteAddr()),
		peerDomain:   "unknown",
		listener:     listener,
		startedAt:    now,
		activityAt:   now,
	}
	monitor.mu.Lock()
	monitor.connections[id] = tracked
	monitor.totalConnections++
	if listener != "" {
		monitor.listeners[listener] = localAddress
	}
	monitor.mu.Unlock()
	return tracked
}

func (monitor *monitorState) unregisterConnection(id uint64) {
	monitor.mu.Lock()
	delete(monitor.connections, id)
	monitor.mu.Unlock()
}

func (monitor *monitorState) observeRequest(
	connection *monitorConnection,
	message ldapwire.Message,
) {
	now := time.Now().UTC()
	connection.mu.Lock()
	connection.received++
	connection.gets++
	connection.reads++
	connection.activityAt = now
	if request, ok := message.Request.(ldapwire.BindRequest); ok {
		connection.protocol = request.Version
	}
	connection.mu.Unlock()

	if operation, ok := monitorOperationIndex(message.Request); ok {
		monitor.operations[operation].initiated.Add(1)
	}
}

func (monitor *monitorState) queueOperation(connection *monitorConnection) {
	connection.mu.Lock()
	connection.pending++
	connection.activityAt = time.Now().UTC()
	connection.mu.Unlock()
}

func (monitor *monitorState) startOperation(
	connection *monitorConnection,
	started bool,
) {
	connection.mu.Lock()
	if connection.pending > 0 {
		connection.pending--
	}
	if started {
		connection.executing++
	}
	connection.activityAt = time.Now().UTC()
	connection.mu.Unlock()
}

func (monitor *monitorState) completeOperation(
	connection *monitorConnection,
	request ldapwire.Request,
	started bool,
) {
	connection.mu.Lock()
	if started && connection.executing > 0 {
		connection.executing--
	}
	connection.completed++
	connection.activityAt = time.Now().UTC()
	connection.mu.Unlock()
	if operation, ok := monitorOperationIndex(request); ok {
		monitor.operations[operation].completed.Add(1)
	}
}

func (monitor *monitorState) completeImmediateOperation(
	connection *monitorConnection,
	request ldapwire.Request,
) {
	monitor.completeOperation(connection, request, false)
}

func (monitor *monitorState) setWriteWaiter(
	connection *monitorConnection,
	value bool,
) {
	if monitor == nil || connection == nil {
		return
	}
	connection.mu.Lock()
	connection.writeWaiter = value
	connection.activityAt = time.Now().UTC()
	connection.mu.Unlock()
}

func (monitor *monitorState) updateConnectionState(
	connection *monitorConnection,
	state *connectionState,
) {
	connection.mu.Lock()
	connection.authorizationDN = state.boundDN
	connection.localAddress = monitorAddress(state.connection.LocalAddr())
	connection.peerAddress = monitorAddress(state.connection.RemoteAddr())
	connection.activityAt = time.Now().UTC()
	connection.mu.Unlock()
}

func (monitor *monitorState) observeResponse(
	connection *monitorConnection,
	encoded []byte,
) {
	operationTag, ok := monitorResponseTag(encoded)
	if !ok {
		return
	}
	monitor.bytes.Add(uint64(len(encoded)))
	monitor.pdus.Add(1)
	switch operationTag {
	case ldapwire.ApplicationSearchResultEntry:
		monitor.entries.Add(1)
	case ldapwire.ApplicationSearchResultReference:
		monitor.referrals.Add(1)
	}
	connection.mu.Lock()
	connection.writes++
	connection.activityAt = time.Now().UTC()
	connection.mu.Unlock()
}

func (monitor *monitorState) connectionSnapshots() []monitorConnectionSnapshot {
	monitor.mu.RLock()
	connections := make([]*monitorConnection, 0, len(monitor.connections))
	for _, connection := range monitor.connections {
		connections = append(connections, connection)
	}
	monitor.mu.RUnlock()

	snapshots := make([]monitorConnectionSnapshot, 0, len(connections))
	for _, connection := range connections {
		connection.mu.RLock()
		snapshots = append(snapshots, monitorConnectionSnapshot{
			id:              connection.id,
			protocol:        connection.protocol,
			authorizationDN: connection.authorizationDN,
			localAddress:    connection.localAddress,
			peerAddress:     connection.peerAddress,
			peerDomain:      connection.peerDomain,
			listener:        connection.listener,
			startedAt:       connection.startedAt,
			activityAt:      connection.activityAt,
			received:        connection.received,
			pending:         connection.pending,
			executing:       connection.executing,
			completed:       connection.completed,
			gets:            connection.gets,
			reads:           connection.reads,
			writes:          connection.writes,
			writeWaiter:     connection.writeWaiter,
		})
		connection.mu.RUnlock()
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].id < snapshots[j].id
	})
	return snapshots
}

func (monitor *monitorState) listenerSnapshots(
	configured []string,
) map[string]string {
	monitor.mu.RLock()
	listeners := make(map[string]string, len(monitor.listeners)+len(configured))
	for listener, address := range monitor.listeners {
		listeners[listener] = address
	}
	monitor.mu.RUnlock()
	for _, listener := range configured {
		if _, exists := listeners[listener]; exists {
			continue
		}
		address := ""
		if parsed, err := url.Parse(listener); err == nil {
			address = monitorURLAddress(parsed)
		}
		listeners[listener] = address
	}
	return listeners
}

func monitorOperationIndex(request ldapwire.Request) (int, bool) {
	switch request.(type) {
	case ldapwire.BindRequest:
		return 0, true
	case ldapwire.UnbindRequest:
		return 1, true
	case ldapwire.SearchRequest:
		return 2, true
	case ldapwire.CompareRequest:
		return 3, true
	case ldapwire.ModifyRequest:
		return 4, true
	case ldapwire.ModifyDNRequest:
		return 5, true
	case ldapwire.AddRequest:
		return 6, true
	case ldapwire.DeleteRequest:
		return 7, true
	case ldapwire.AbandonRequest:
		return 8, true
	case ldapwire.ExtendedRequest:
		return 9, true
	default:
		return 0, false
	}
}

func monitorResponseTag(encoded []byte) (uint64, bool) {
	packet, err := ber.DecodePacketErr(encoded)
	if err != nil || len(packet.Children) < 2 {
		return 0, false
	}
	operation := packet.Children[1]
	if operation.ClassType != ber.ClassApplication {
		return 0, false
	}
	return uint64(operation.Tag), true
}

func monitorAddress(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	switch address.Network() {
	case "unix", "unixpacket":
		return "PATH=" + address.String()
	default:
		return "IP=" + address.String()
	}
}

func monitorListenerURL(address net.Addr, implicitTLS bool) string {
	if address == nil {
		return ""
	}
	if address.Network() == "unix" || address.Network() == "unixpacket" {
		return "ldapi://" + url.PathEscape(address.String()) + "/"
	}
	scheme := "ldap"
	if implicitTLS {
		scheme = "ldaps"
	}
	return scheme + "://" + address.String() + "/"
}

func monitorURLAddress(parsed *url.URL) string {
	if parsed == nil {
		return ""
	}
	if parsed.Scheme == "ldapi" {
		path, _ := url.PathUnescape(parsed.Host + parsed.Path)
		return "PATH=" + path
	}
	if parsed.Host == "" {
		return ""
	}
	return "IP=" + parsed.Host
}

func (server *Server) monitorEntries(runtime *runtimeState) []directory.Entry {
	now := time.Now().UTC()
	startedAt := server.monitor.startedAt
	entries := []directory.Entry{
		newMonitorEntry("cn=Monitor", "Monitor", "monitorServer", startedAt),
	}
	root := &entries[0]
	addMonitorAttribute(root, "description",
		"This subtree contains monitoring/managing objects.",
		"This object contains information about this server.",
		"Most of the information is held in operational attributes, which must be explicitly requested.",
	)
	addMonitorAttribute(root, "monitoredInfo", "ldap-go 0.1-dev")

	containers := []struct {
		name        string
		description string
	}{
		{"Backends", "This subsystem contains information about available backends."},
		{"Connections", "This subsystem contains information about connections."},
		{"Databases", "This subsystem contains information about configured databases."},
		{"Listeners", "This subsystem contains information about active listeners."},
		{"Log", "This subsystem contains information about logging."},
		{"Operations", "This subsystem contains information about performed operations."},
		{"Overlays", "This subsystem contains information about available overlays."},
		{"SASL", "This subsystem contains information about SASL."},
		{"Statistics", "This subsystem contains statistics."},
		{"Threads", "This subsystem contains information about threads."},
		{"Time", "This subsystem contains information about time."},
		{"TLS", "This subsystem contains information about TLS."},
		{"Waiters", "This subsystem contains information about read/write waiters."},
	}
	for _, container := range containers {
		entry := newMonitorEntry(
			"cn="+container.name+",cn=Monitor",
			container.name,
			"monitorContainer",
			startedAt,
		)
		addMonitorAttribute(&entry, "description", container.description)
		if container.name == "Log" {
			addMonitorAttribute(
				&entry,
				"description",
				`Set the "monitorLogLevel" or "monitorDebugLevel" attributes to the desired levels.`,
			)
			debugLevels, logLevels := server.monitor.loggingSnapshot()
			addMonitorAttribute(&entry, "monitorDebugLevel", debugLevels...)
			addMonitorAttribute(&entry, "monitorLogLevel", logLevels...)
		}
		entries = append(entries, entry)
	}

	entries = append(entries, server.monitorBackendEntries(runtime, startedAt)...)
	entries = append(entries, server.monitorConnectionEntries(startedAt)...)
	entries = append(entries, server.monitorDatabaseEntries(runtime, startedAt)...)
	entries = append(entries, server.monitorListenerEntries(startedAt)...)
	entries = append(entries, server.monitorOperationEntries(startedAt)...)
	entries = append(entries, server.monitorOverlayEntries(runtime, startedAt)...)
	entries = append(entries, server.monitorStatisticEntries(startedAt)...)
	entries = append(entries, server.monitorThreadEntries(startedAt)...)
	entries = append(entries, monitorTimeEntries(startedAt, now)...)
	entries = append(entries, monitorWaiterEntries(
		startedAt,
		server.monitor.connectionSnapshots(),
	)...)
	server.populateMonitorContainerAttributes(entries, runtime)
	addMonitorSubordinateState(entries)
	return entries
}

func (server *Server) monitorBackendEntries(
	runtime *runtimeState,
	startedAt time.Time,
) []directory.Entry {
	types := monitorDatabaseTypes(runtime.databases)
	entries := make([]directory.Entry, 0, len(types))
	monitoredDatabases := monitorRuntimeDatabases(runtime.databases)
	for index, databaseType := range types {
		entry := newMonitorEntry(
			fmt.Sprintf("cn=Backend %d,cn=Backends,cn=Monitor", index),
			fmt.Sprintf("Backend %d", index),
			"monitoredObject",
			startedAt,
		)
		addMonitorAttribute(&entry, "monitoredInfo", databaseType)
		addMonitorAttribute(&entry, "monitorRuntimeConfig", "TRUE")
		for _, monitored := range monitoredDatabases {
			if databaseTypeName(runtime.databases[monitored.runtimeIndex]) == databaseType {
				addMonitorAttribute(
					&entry,
					"seeAlso",
					fmt.Sprintf("cn=Database %d,cn=Databases,cn=Monitor", monitored.monitorIndex),
				)
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

func (server *Server) monitorConnectionEntries(startedAt time.Time) []directory.Entry {
	snapshots := server.monitor.connectionSnapshots()
	server.monitor.mu.RLock()
	totalConnections := server.monitor.totalConnections
	server.monitor.mu.RUnlock()
	entries := []directory.Entry{
		monitorCounterEntry("Max File Descriptors", "Connections", 0, startedAt),
		monitorCounterEntry("Total", "Connections", totalConnections, startedAt),
		monitorCounterEntry("Current", "Connections", uint64(len(snapshots)), startedAt),
	}
	for _, snapshot := range snapshots {
		name := fmt.Sprintf("Connection %d", snapshot.id)
		entry := newMonitorEntry(
			"cn="+name+",cn=Connections,cn=Monitor",
			name,
			"monitorConnection",
			snapshot.startedAt,
		)
		addMonitorAttribute(&entry, "monitorConnectionNumber", strconv.FormatUint(snapshot.id, 10))
		addMonitorAttribute(&entry, "monitorConnectionProtocol", strconv.Itoa(snapshot.protocol))
		addMonitorAttribute(&entry, "monitorConnectionOpsReceived", strconv.FormatUint(snapshot.received, 10))
		addMonitorAttribute(&entry, "monitorConnectionOpsExecuting", strconv.FormatUint(snapshot.executing, 10))
		addMonitorAttribute(&entry, "monitorConnectionOpsPending", strconv.FormatUint(snapshot.pending, 10))
		addMonitorAttribute(&entry, "monitorConnectionOpsCompleted", strconv.FormatUint(snapshot.completed, 10))
		addMonitorAttribute(&entry, "monitorConnectionOpsAsync", "0")
		addMonitorAttribute(&entry, "monitorConnectionGet", strconv.FormatUint(snapshot.gets, 10))
		addMonitorAttribute(&entry, "monitorConnectionRead", strconv.FormatUint(snapshot.reads, 10))
		addMonitorAttribute(&entry, "monitorConnectionWrite", strconv.FormatUint(snapshot.writes, 10))
		addMonitorAttribute(&entry, "monitorConnectionMask", monitorConnectionMask(snapshot))
		if snapshot.authorizationDN != "" {
			addMonitorAttribute(&entry, "monitorConnectionAuthzDN", snapshot.authorizationDN)
		}
		addMonitorAttribute(&entry, "monitorConnectionListener", snapshot.listener)
		addMonitorAttribute(&entry, "monitorConnectionPeerDomain", snapshot.peerDomain)
		addMonitorAttribute(&entry, "monitorConnectionPeerAddress", snapshot.peerAddress)
		addMonitorAttribute(&entry, "monitorConnectionLocalAddress", snapshot.localAddress)
		addMonitorAttribute(&entry, "monitorConnectionStartTime", monitorTime(snapshot.startedAt))
		addMonitorAttribute(&entry, "monitorConnectionActivityTime", monitorTime(snapshot.activityAt))
		entry.ReplaceValues("modifyTimestamp", stringValues(monitorTime(snapshot.activityAt)))
		entries = append(entries, entry)
	}
	return entries
}

func (server *Server) monitorDatabaseEntries(
	runtime *runtimeState,
	startedAt time.Time,
) []directory.Entry {
	monitoredDatabases := monitorRuntimeDatabases(runtime.databases)
	entries := make([]directory.Entry, 0, len(monitoredDatabases)+1)
	backendIndexes := make(map[string]int)
	for index, name := range monitorDatabaseTypes(runtime.databases) {
		backendIndexes[name] = index
	}
	for _, monitored := range monitoredDatabases {
		databaseIndex := monitored.runtimeIndex
		database := runtime.databases[databaseIndex]
		name := fmt.Sprintf("Database %d", monitored.monitorIndex)
		entry := newMonitorEntry(
			"cn="+name+",cn=Databases,cn=Monitor",
			name,
			"monitoredObject",
			startedAt,
		)
		backendType := databaseTypeName(database)
		restrictions := effectiveDatabaseRestrictions(database)
		readOnly := restrictions&restrictWrites == restrictWrites
		addMonitorAttribute(&entry, "monitoredInfo", backendType)
		addMonitorAttribute(&entry, "monitorIsShadow", monitorBoolean(database.shadow))
		addMonitorAttribute(&entry, "readOnly", monitorBoolean(readOnly))
		for _, suffix := range database.suffixes {
			if isMonitorDatabase(database) {
				addMonitorAttribute(&entry, "monitorContext", suffix.String())
			} else {
				addMonitorAttribute(&entry, "namingContexts", suffix.String())
			}
		}
		for _, overlay := range runtimeDatabaseOverlayNames(database) {
			addMonitorAttribute(&entry, "monitorOverlay", overlay)
		}
		if database.shadow && len(database.updateRefs) > 0 {
			addMonitorAttribute(&entry, "monitorUpdateRef", database.updateRefs[0])
		}
		addMonitorAttribute(
			&entry,
			"restrictedOperation",
			databaseRestrictionValues(restrictions)...,
		)
		if database.subordinate && len(database.suffixes) == 1 {
			if superior := glueSuperiorDatabaseIndex(runtime.databases, databaseIndex); superior >= 0 &&
				len(runtime.databases[superior].suffixes) > 0 {
				addMonitorAttribute(
					&entry,
					"monitorSuperiorDN",
					runtime.databases[superior].suffixes[0].String(),
				)
			}
		}
		if backendIndex, ok := backendIndexes[backendType]; ok {
			addMonitorAttribute(
				&entry,
				"seeAlso",
				fmt.Sprintf("cn=Backend %d,cn=Backends,cn=Monitor", backendIndex),
			)
		}
		entries = append(entries, entry)
	}
	container := newMonitorEntry(
		"cn=Frontend,cn=Databases,cn=Monitor",
		"Frontend",
		"monitoredObject",
		startedAt,
	)
	frontendRestrictions := monitorFrontendRestrictions(runtime.databases)
	addMonitorAttribute(&container, "monitorIsShadow", "FALSE")
	addMonitorAttribute(
		&container,
		"readOnly",
		monitorBoolean(frontendRestrictions&restrictWrites == restrictWrites),
	)
	addMonitorAttribute(
		&container,
		"restrictedOperation",
		databaseRestrictionValues(frontendRestrictions)...,
	)
	entries = append(entries, container)
	return entries
}

func (server *Server) monitorListenerEntries(startedAt time.Time) []directory.Entry {
	listeners := server.monitor.listenerSnapshots(server.config.ListenerURLs)
	urls := make([]string, 0, len(listeners))
	for listener := range listeners {
		urls = append(urls, listener)
	}
	sort.Strings(urls)
	entries := make([]directory.Entry, 0, len(urls))
	for index, listener := range urls {
		name := fmt.Sprintf("Listener %d", index)
		entry := newMonitorEntry(
			"cn="+name+",cn=Listeners,cn=Monitor",
			name,
			"monitoredObject",
			startedAt,
		)
		addMonitorAttribute(&entry, "labeledURI", listener)
		if address := listeners[listener]; address != "" {
			addMonitorAttribute(&entry, "monitorConnectionLocalAddress", address)
		}
		if strings.HasPrefix(strings.ToLower(listener), "ldaps:") {
			addMonitorAttribute(&entry, "monitoredInfo", "TLS")
		}
		entries = append(entries, entry)
	}
	return entries
}

func (server *Server) monitorOperationEntries(startedAt time.Time) []directory.Entry {
	entries := make([]directory.Entry, 0, len(monitorOperationNames))
	for index, name := range monitorOperationNames {
		initiated := server.monitor.operations[index].initiated.Load()
		completed := server.monitor.operations[index].completed.Load()
		entry := newMonitorEntry(
			"cn="+name+",cn=Operations,cn=Monitor",
			name,
			"monitorOperation",
			startedAt,
		)
		addMonitorAttribute(&entry, "monitorOpInitiated", strconv.FormatUint(initiated, 10))
		addMonitorAttribute(&entry, "monitorOpCompleted", strconv.FormatUint(completed, 10))
		entries = append(entries, entry)
	}
	return entries
}

func (server *Server) populateMonitorContainerAttributes(
	entries []directory.Entry,
	runtime *runtimeState,
) {
	byDN := make(map[string]*directory.Entry, len(entries))
	for index := range entries {
		byDN[strings.ToLower(entries[index].DN)] = &entries[index]
	}

	if operations := byDN["cn=operations,cn=monitor"]; operations != nil {
		var initiated uint64
		var completed uint64
		for index := range server.monitor.operations {
			initiated += server.monitor.operations[index].initiated.Load()
			completed += server.monitor.operations[index].completed.Load()
		}
		addMonitorAttribute(operations, "monitorOpInitiated", strconv.FormatUint(initiated, 10))
		addMonitorAttribute(operations, "monitorOpCompleted", strconv.FormatUint(completed, 10))
	}
	if connections := byDN["cn=connections,cn=monitor"]; connections != nil {
		addMonitorAttribute(
			connections,
			"monitoredInfo",
			"maxConnections="+strconv.Itoa(server.config.MaxConnections),
			"rejectedConnections="+strconv.FormatUint(server.rejectedConnections.Load(), 10),
			"activeHandshakes="+strconv.FormatInt(server.handshakeLimiter.active.Load(), 10),
			"waitingHandshakes="+strconv.FormatInt(server.handshakeLimiter.waiting.Load(), 10),
		)
	}
	if threads := byDN["cn=threads,cn=monitor"]; threads != nil {
		addMonitorAttribute(
			threads,
			"monitoredInfo",
			"maxConcurrentOperations="+strconv.Itoa(server.operationLimiter.limit()),
			"activeOperations="+strconv.FormatInt(server.operationLimiter.active.Load(), 10),
			"waitingOperations="+strconv.FormatInt(server.operationLimiter.waiting.Load(), 10),
		)
	}

	if backends := byDN["cn=backends,cn=monitor"]; backends != nil {
		addMonitorAttribute(backends, "monitoredInfo", monitorDatabaseTypes(runtime.databases)...)
	}

	if databases := byDN["cn=databases,cn=monitor"]; databases != nil {
		for _, monitored := range monitorRuntimeDatabases(runtime.databases) {
			database := runtime.databases[monitored.runtimeIndex]
			for _, suffix := range database.suffixes {
				if isMonitorDatabase(database) {
					addMonitorAttribute(databases, "monitorContext", suffix.String())
				} else {
					addMonitorAttribute(databases, "namingContexts", suffix.String())
				}
			}
		}
		frontendRestrictions := monitorFrontendRestrictions(runtime.databases)
		addMonitorAttribute(
			databases,
			"readOnly",
			monitorBoolean(frontendRestrictions&restrictWrites == restrictWrites),
		)
		addMonitorAttribute(
			databases,
			"restrictedOperation",
			databaseRestrictionValues(frontendRestrictions)...,
		)
	}

	if overlays := byDN["cn=overlays,cn=monitor"]; overlays != nil {
		var names []string
		seen := make(map[string]struct{})
		for _, database := range runtime.databases {
			for _, name := range runtimeDatabaseOverlayNames(database) {
				if _, exists := seen[name]; exists {
					continue
				}
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
		sort.Strings(names)
		addMonitorAttribute(overlays, "monitoredInfo", names...)
	}
}

func (server *Server) monitorOverlayEntries(
	runtime *runtimeState,
	startedAt time.Time,
) []directory.Entry {
	names := make(map[string]struct{})
	for _, database := range runtime.databases {
		for _, name := range runtimeDatabaseOverlayNames(database) {
			names[name] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	entries := make([]directory.Entry, 0, len(ordered))
	for index, overlay := range ordered {
		name := fmt.Sprintf("Overlay %d", index)
		entry := newMonitorEntry(
			"cn="+name+",cn=Overlays,cn=Monitor",
			name,
			"monitoredObject",
			startedAt,
		)
		addMonitorAttribute(&entry, "monitoredInfo", overlay)
		addMonitorAttribute(&entry, "monitorRuntimeConfig", "TRUE")
		entries = append(entries, entry)
	}
	return entries
}

func (server *Server) monitorStatisticEntries(startedAt time.Time) []directory.Entry {
	return []directory.Entry{
		monitorCounterEntry("Bytes", "Statistics", server.monitor.bytes.Load(), startedAt),
		monitorCounterEntry("PDU", "Statistics", server.monitor.pdus.Load(), startedAt),
		monitorCounterEntry("Entries", "Statistics", server.monitor.entries.Load(), startedAt),
		monitorCounterEntry("Referrals", "Statistics", server.monitor.referrals.Load(), startedAt),
	}
}

func (server *Server) monitorThreadEntries(startedAt time.Time) []directory.Entry {
	connections := server.monitor.connectionSnapshots()
	var active uint64
	var pending uint64
	for _, connection := range connections {
		active += connection.executing
		pending += connection.pending
	}
	values := []struct {
		name        string
		value       string
		description string
	}{
		{"Max", strconv.Itoa(goruntime.GOMAXPROCS(0)), "Maximum number of threads as configured"},
		{"Max Pending", "0", "Maximum number of pending threads"},
		{"Open", strconv.Itoa(goruntime.NumGoroutine()), "Number of open threads"},
		{"Starting", "0", "Number of threads being started"},
		{"Active", strconv.FormatUint(active, 10), "Number of active threads"},
		{"Pending", strconv.FormatUint(pending, 10), "Number of pending threads"},
		{"Backload", strconv.FormatUint(active+pending, 10), "Number of active plus pending threads"},
		{"State", "running", "Thread pool state"},
		{"Runqueue", "", "Queue of running threads - besides those handling operations"},
		{"Tasklist", "", "List of running plus standby threads - besides those handling operations"},
	}
	entries := make([]directory.Entry, 0, len(values))
	for _, value := range values {
		entry := newMonitorEntry(
			"cn="+value.name+",cn=Threads,cn=Monitor",
			value.name,
			"monitoredObject",
			startedAt,
		)
		if value.value != "" {
			addMonitorAttribute(&entry, "monitoredInfo", value.value)
		}
		addMonitorAttribute(&entry, "description", value.description)
		entries = append(entries, entry)
	}
	return entries
}

func monitorTimeEntries(startedAt, now time.Time) []directory.Entry {
	start := newMonitorEntry("cn=Start,cn=Time,cn=Monitor", "Start", "monitoredObject", startedAt)
	addMonitorAttribute(&start, "monitorTimestamp", monitorTime(startedAt))
	current := newMonitorEntry("cn=Current,cn=Time,cn=Monitor", "Current", "monitoredObject", startedAt)
	addMonitorAttribute(&current, "monitorTimestamp", monitorTime(now))
	uptime := newMonitorEntry("cn=Uptime,cn=Time,cn=Monitor", "Uptime", "monitoredObject", startedAt)
	seconds := uint64(max(time.Duration(0), now.Sub(startedAt)) / time.Second)
	addMonitorAttribute(&uptime, "monitoredInfo", strconv.FormatUint(seconds, 10))
	return []directory.Entry{start, current, uptime}
}

func monitorWaiterEntries(
	startedAt time.Time,
	connections []monitorConnectionSnapshot,
) []directory.Entry {
	writeWaiters := uint64(0)
	for _, connection := range connections {
		if connection.writeWaiter {
			writeWaiters++
		}
	}
	return []directory.Entry{
		monitorCounterEntry("Read", "Waiters", 0, startedAt),
		monitorCounterEntry("Write", "Waiters", writeWaiters, startedAt),
	}
}

func newMonitorEntry(
	dn,
	commonName,
	objectClass string,
	createdAt time.Time,
) directory.Entry {
	timestamp := monitorTime(createdAt)
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues(objectClass)},
			{Description: "structuralObjectClass", Values: stringValues(objectClass)},
			{Description: "cn", Values: stringValues(commonName)},
			{Description: "createTimestamp", Values: stringValues(timestamp)},
			{Description: "modifyTimestamp", Values: stringValues(timestamp)},
			{Description: "entryDN", Values: stringValues(dn)},
			{Description: "subschemaSubentry", Values: stringValues("cn=Subschema")},
		},
	}
}

func monitorCounterEntry(
	name,
	container string,
	value uint64,
	startedAt time.Time,
) directory.Entry {
	entry := newMonitorEntry(
		"cn="+name+",cn="+container+",cn=Monitor",
		name,
		"monitorCounterObject",
		startedAt,
	)
	addMonitorAttribute(&entry, "monitorCounter", strconv.FormatUint(value, 10))
	return entry
}

func addMonitorAttribute(entry *directory.Entry, description string, values ...string) {
	values = compactMonitorValues(values)
	if len(values) == 0 {
		return
	}
	existing := entry.Values(description)
	combined := make([]string, 0, len(existing)+len(values))
	for _, value := range existing {
		combined = append(combined, string(value))
	}
	combined = append(combined, values...)
	entry.ReplaceValues(description, stringValues(combined...))
}

func compactMonitorValues(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func addMonitorSubordinateState(entries []directory.Entry) {
	parents := make(map[string]struct{})
	for _, entry := range entries {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			continue
		}
		parent, ok := dn.Parent()
		if ok {
			parents[parent.Key()] = struct{}{}
		}
	}
	for index := range entries {
		dn, err := directory.ParseDN(entries[index].DN)
		if err != nil {
			continue
		}
		_, hasChildren := parents[dn.Key()]
		entries[index].ReplaceValues(
			"hasSubordinates",
			stringValues(monitorBoolean(hasChildren)),
		)
	}
}

func monitorDatabaseTypes(databases []runtimeDatabase) []string {
	var types []string
	seen := make(map[string]struct{})
	for _, database := range databases {
		if databaseType(database.name) == "frontend" {
			continue
		}
		name := databaseTypeName(database)
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		types = append(types, name)
	}
	return types
}

type monitorRuntimeDatabase struct {
	runtimeIndex int
	monitorIndex int
}

func monitorRuntimeDatabases(databases []runtimeDatabase) []monitorRuntimeDatabase {
	result := make([]monitorRuntimeDatabase, 0, len(databases))
	for runtimeIndex := range databases {
		if databaseType(databases[runtimeIndex].name) == "frontend" {
			continue
		}
		result = append(result, monitorRuntimeDatabase{
			runtimeIndex: runtimeIndex,
			monitorIndex: len(result),
		})
	}
	return result
}

func monitorFrontendRestrictions(databases []runtimeDatabase) databaseRestrictions {
	for _, database := range databases {
		if databaseType(database.name) == "frontend" {
			if database.frontendRestrictions == 0 {
				return effectiveDatabaseRestrictions(database)
			}
			return database.frontendRestrictions
		}
	}
	return inheritedFrontendRestrictions(databases)
}

func databaseTypeName(database runtimeDatabase) string {
	name := databaseType(database.name)
	if name == "bootstrap" {
		return "mdb"
	}
	return name
}

func runtimeDatabaseOverlayNames(database runtimeDatabase) []string {
	var names []string
	if database.allOperationalAttrs {
		names = append(names, "allop")
	}
	if database.lastBindOverlay {
		names = append(names, "lastbind")
	}
	if database.nopsOverlay {
		names = append(names, "nops")
	}
	if database.noOpSearchOverlay {
		names = append(names, "noopsrch")
	}
	if database.explicitGlue {
		names = append(names, "glue")
	}
	if database.serverSideSort {
		names = append(names, "sssvlv")
	}
	if database.syncProvider {
		names = append(names, "syncprov")
	}
	if database.dds != nil {
		names = append(names, "dds")
	}
	if database.ppolicy != nil {
		names = append(names, "ppolicy")
	}
	if database.chain != nil {
		names = append(names, "chain")
	}
	if database.constraint != nil {
		names = append(names, "constraint")
	}
	if database.dynlist != nil {
		names = append(names, "dynlist")
	}
	if database.dyngroup != nil {
		names = append(names, "dyngroup")
	}
	if database.unique != nil {
		names = append(names, "unique")
	}
	if database.valueSort != nil {
		names = append(names, "valsort")
	}
	if len(database.retcodes) > 0 {
		names = append(names, "retcode")
	}
	if len(database.memberOf) > 0 {
		names = append(names, "memberof")
	}
	if len(database.refint) > 0 {
		names = append(names, "refint")
	}
	if database.accesslog != nil {
		names = append(names, "accesslog")
	}
	if database.auditlog != nil {
		names = append(names, "auditlog")
	}
	return names
}

func monitorConnectionMask(snapshot monitorConnectionSnapshot) string {
	var mask strings.Builder
	mask.WriteByte('r')
	if snapshot.executing > 0 {
		mask.WriteByte('x')
	}
	if snapshot.pending > 0 {
		mask.WriteByte('p')
	}
	if snapshot.writeWaiter {
		mask.WriteByte('w')
	}
	return mask.String()
}

func monitorBoolean(value bool) string {
	if value {
		return "TRUE"
	}
	return "FALSE"
}

func monitorTime(value time.Time) string {
	return value.UTC().Format(monitorGeneralizedTimeLayout)
}

func monitorDatabaseIndexForDN(databases []runtimeDatabase, dn directory.DN) int {
	index := databaseIndexForDN(databases, dn)
	if index < 0 || !isMonitorDatabase(databases[index]) {
		return -1
	}
	return index
}

type monitorSearchCandidate struct {
	entry directory.Entry
	dn    directory.DN
}

func (server *Server) monitorEntryIndex(
	runtime *runtimeState,
) (map[string]directory.Entry, []monitorSearchCandidate, error) {
	generated := server.monitorEntries(runtime)
	byDN := make(map[string]directory.Entry, len(generated))
	all := make([]monitorSearchCandidate, 0, len(generated))
	for _, entry := range generated {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return nil, nil, fmt.Errorf("parse generated monitor DN %q: %w", entry.DN, err)
		}
		byDN[dn.Key()] = entry
		all = append(all, monitorSearchCandidate{entry: entry, dn: dn})
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].dn.Key() < all[j].dn.Key()
	})
	return byDN, all, nil
}

func (server *Server) searchMonitor(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	controls requestControls,
	paging *pagedSearchContext,
	limit int,
) error {
	if controls.sync != nil && controls.sync.critical {
		return server.writeSearchDone(
			connection,
			messageID,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"Sync is not enabled for this search target",
			),
		)
	}
	if controls.sorting != nil || controls.vlv != nil || controls.valueSort != nil {
		critical := (controls.sorting != nil && controls.sorting.critical) ||
			(controls.vlv != nil && controls.vlv.critical) ||
			(controls.valueSort != nil && controls.valueSort.critical)
		if critical {
			return server.writeSearchResult(
				connection,
				messageID,
				state,
				paging,
				nil,
				nil,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"control is not enabled for the monitor database",
				),
				pagedSearchCursor{},
				false,
			)
		}
	}

	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return server.writeSearchResult(
			connection,
			messageID,
			state,
			paging,
			nil,
			nil,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
			pagedSearchCursor{},
			false,
		)
	}
	byDN, all, err := server.monitorEntryIndex(state.runtime)
	if err != nil {
		return err
	}

	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	var selected []monitorSearchCandidate
	deadline := timeLimitDeadline(request.TimeLimit)
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		baseEntry, exists := byDN[base.Key()]
		if !exists {
			result.Code = ldapwire.ResultNoSuchObject
			result.MatchedDN = monitorMatchedDN(
				state.runtime,
				server,
				reader,
				state.boundDN,
				base,
				byDN,
			)
			return nil
		}
		if !server.allowed(
			state.runtime,
			reader,
			state.boundDN,
			baseEntry,
			"entry",
			nil,
			acl.Search,
		) {
			if server.allowed(
				state.runtime,
				reader,
				state.boundDN,
				baseEntry,
				"entry",
				nil,
				acl.Disclose,
			) {
				result.Code = ldapwire.ResultInsufficientAccessRights
			} else {
				result.Code = ldapwire.ResultNoSuchObject
			}
			return nil
		}
		if err := server.checkAssertion(
			state.runtime,
			reader,
			state.boundDN,
			baseEntry,
			controls.assertion,
		); err != nil {
			result.Code = ldapwire.ResultAssertionFailed
			return nil
		}

		for _, candidate := range all {
			if expired(deadline) {
				result.Code = ldapwire.ResultTimeLimitExceeded
				break
			}
			if !directory.InScope(base, candidate.dn, request.Scope) {
				continue
			}
			matches, matchErr := server.filterMatches(
				state.runtime,
				reader,
				state.boundDN,
				candidate.entry,
				request.Filter,
			)
			if matchErr != nil {
				result.Code = ldapwire.ResultInappropriateMatching
				result.DiagnosticMessage = matchErr.Error()
				break
			}
			if !matches || !server.allowed(
				state.runtime,
				reader,
				state.boundDN,
				candidate.entry,
				"entry",
				nil,
				acl.Read,
			) {
				continue
			}
			if paging != nil && paging.cursor.valid &&
				candidate.dn.Key() <= paging.cursor.dnKey {
				continue
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				reader,
				state.boundDN,
				candidate.entry,
				acl.Read,
				request.TypesOnly,
			)
			candidate.entry = server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			)
			selected = append(selected, candidate)
		}
		return nil
	})
	if err != nil {
		if paging != nil {
			clearPagedSearch(state)
		}
		return fmt.Errorf("search monitor database: %w", err)
	}
	if result.Code != ldapwire.ResultSuccess {
		selected = nil
	}

	entryLimit := limit
	if paging != nil {
		remaining := limit - paging.count
		if remaining < 0 {
			remaining = 0
		}
		entryLimit = min(paging.size, remaining)
	}
	hasMore := false
	if len(selected) > entryLimit {
		selected = selected[:entryLimit]
		if paging != nil && paging.count+len(selected) < limit {
			hasMore = true
		} else {
			result.Code = ldapwire.ResultSizeLimitExceeded
		}
	}
	entries := make([]directory.Entry, len(selected))
	for index := range selected {
		entries[index] = selected[index].entry
	}
	cursor := pagedSearchCursor{}
	if len(selected) > 0 {
		cursor = pagedSearchCursor{
			route: 0,
			dnKey: selected[len(selected)-1].dn.Key(),
			valid: true,
		}
	}
	return server.writeSearchResult(
		connection,
		messageID,
		state,
		paging,
		nil,
		entries,
		result,
		cursor,
		hasMore,
	)
}

func monitorMatchedDN(
	runtime *runtimeState,
	server *Server,
	reader storage.Reader,
	subjectDN string,
	base directory.DN,
	entries map[string]directory.Entry,
) string {
	current := base
	for {
		parent, ok := current.Parent()
		if !ok {
			return ""
		}
		entry, exists := entries[parent.Key()]
		if exists && server.allowed(
			runtime,
			reader,
			subjectDN,
			entry,
			"entry",
			nil,
			acl.Disclose,
		) {
			return entry.DN
		}
		current = parent
	}
}

func (server *Server) modifyMonitorEntry(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	dn directory.DN,
	changes []ldapwire.Modification,
	controls requestControls,
) error {
	server.configMu.Lock()
	defer server.configMu.Unlock()

	runtime := server.runtime.Load()
	byDN, _, err := server.monitorEntryIndex(runtime)
	if err != nil {
		return server.internalOperationError(
			connection,
			messageID,
			ldapwire.ApplicationModifyResponse,
			err,
		)
	}
	entry, exists := byDN[dn.Key()]
	if !exists {
		err = server.config.Store.View(ctx, func(reader storage.Reader) error {
			return operationFailedWithMatchedDN(
				ldapwire.ResultNoSuchObject,
				monitorMatchedDN(runtime, server, reader, state.boundDN, dn, byDN),
				"",
			)
		})
		return server.finishOperationWithControls(
			connection,
			messageID,
			ldapwire.ApplicationModifyResponse,
			err,
			nil,
		)
	}

	var (
		responseControls []ldapwire.Control
		debugLevels      []string
		logLevels        []string
		loggingChanged   bool
		nextRuntime      *runtimeState
	)
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		if err := server.checkAssertion(
			runtime,
			reader,
			state.boundDN,
			entry,
			controls.assertion,
		); err != nil {
			return err
		}
		if !server.canApplyModifications(
			runtime,
			reader,
			state.boundDN,
			entry,
			changes,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		preRead, err := server.readResponseControl(
			runtime,
			reader,
			state.boundDN,
			entry,
			controls.preRead,
			preReadControlOID,
		)
		if err != nil {
			return err
		}
		if preRead != nil {
			responseControls = append(responseControls, *preRead)
		}

		updated := entry.Clone()
		switch {
		case dn.Key() == staticRuntimeDN("cn=Log,cn=Monitor").Key():
			debugLevels, logLevels, err = applyMonitorLogModifications(
				runtime,
				&updated,
				changes,
			)
			loggingChanged = err == nil
		case monitorDatabaseIndexForEntry(runtime.databases, dn) >= 0:
			runtimeIndex := monitorDatabaseIndexForEntry(runtime.databases, dn)
			if isMonitorDatabase(runtime.databases[runtimeIndex]) {
				return operationFailed(
					ldapwire.ResultUnwillingToPerform,
					"no modifications allowed to monitor database entry",
				)
			}
			var restrictions databaseRestrictions
			restrictions, err = applyMonitorDatabaseModifications(
				runtime,
				&updated,
				changes,
			)
			if err == nil {
				copy := *runtime
				copy.databases = append([]runtimeDatabase(nil), runtime.databases...)
				copy.databases[runtimeIndex].restrictions = restrictions
				copy.databases[runtimeIndex].readOnly = restrictions&restrictWrites == restrictWrites
				copy.revision = server.nextRuntimeRevision()
				nextRuntime = &copy
			}
		default:
			return operationFailed(ldapwire.ResultUnwillingToPerform, "")
		}
		if err != nil {
			return err
		}
		postRead, err := server.readResponseControl(
			runtime,
			reader,
			state.boundDN,
			updated,
			controls.postRead,
			postReadControlOID,
		)
		if err != nil {
			return err
		}
		if postRead != nil {
			responseControls = append(responseControls, *postRead)
		}
		return nil
	})
	if err == nil {
		if loggingChanged {
			server.monitor.setLogging(debugLevels, logLevels)
		}
		if nextRuntime != nil {
			server.activateRuntime(nextRuntime)
		}
	}
	return server.finishOperationWithControls(
		connection,
		messageID,
		ldapwire.ApplicationModifyResponse,
		err,
		responseControls,
	)
}

func applyMonitorLogModifications(
	runtime *runtimeState,
	entry *directory.Entry,
	changes []ldapwire.Modification,
) ([]string, []string, error) {
	for _, change := range changes {
		name := monitorCanonicalAttribute(
			runtime,
			change.Attribute.Description,
			"monitorDebugLevel",
			"monitorLogLevel",
		)
		if name == "" {
			return nil, nil, operationFailed(ldapwire.ResultUnwillingToPerform, "")
		}

		// OpenLDAP 2.6 reaches its generic operational-attribute branch
		// before the log-specific validation and operation switch.
		entry.ReplaceValues(name, change.Attribute.Values)
	}
	return byteValuesToStrings(entry.Values("monitorDebugLevel")),
		byteValuesToStrings(entry.Values("monitorLogLevel")), nil
}

func byteValuesToStrings(values [][]byte) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func applyMonitorDatabaseModifications(
	runtime *runtimeState,
	entry *directory.Entry,
	changes []ldapwire.Modification,
) (databaseRestrictions, error) {
	restrictions, err := monitorRestrictionValues(entry.Values("restrictedOperation"))
	if err != nil {
		return 0, err
	}
	for _, change := range changes {
		name := monitorCanonicalAttribute(
			runtime,
			change.Attribute.Description,
			"readOnly",
			"restrictedOperation",
		)
		if name == "" {
			return 0, operationFailed(ldapwire.ResultUnwillingToPerform, "")
		}
		if change.Operation == ldapwire.ModificationIncrement {
			return 0, operationFailed(ldapwire.ResultOther, "")
		}
		change.Attribute.Description = name
		switch name {
		case "readOnly":
			if change.Operation == ldapwire.ModificationAdd && entry.HasAttribute(name) {
				return 0, operationFailed(ldapwire.ResultConstraintViolation, "")
			}
			for index, raw := range change.Attribute.Values {
				switch {
				case strings.EqualFold(string(raw), "TRUE"):
					change.Attribute.Values[index] = []byte("TRUE")
				case strings.EqualFold(string(raw), "FALSE"):
					change.Attribute.Values[index] = []byte("FALSE")
				default:
					return 0, operationFailed(ldapwire.ResultInvalidAttributeSyntax, "")
				}
			}
			if len(change.Attribute.Values) > 1 {
				return 0, operationFailed(ldapwire.ResultConstraintViolation, "")
			}
			if err := applyModification(entry, change); err != nil {
				return 0, err
			}
			if change.Operation != ldapwire.ModificationDelete &&
				len(change.Attribute.Values) == 1 {
				if strings.EqualFold(string(change.Attribute.Values[0]), "TRUE") {
					restrictions |= restrictWrites
				} else {
					restrictions &^= restrictWrites
				}
				setMonitorRestrictionValues(entry, restrictions)
			}
		case "restrictedOperation":
			for index, raw := range change.Attribute.Values {
				flag, ok := databaseRestrictionName(string(raw), false)
				if !ok {
					return 0, operationFailed(ldapwire.ResultInvalidAttributeSyntax, "")
				}
				values := databaseRestrictionValues(flag)
				if len(values) != 1 {
					return 0, operationFailed(ldapwire.ResultInvalidAttributeSyntax, "")
				}
				change.Attribute.Values[index] = []byte(values[0])
			}
			if err := applyModification(entry, change); err != nil {
				return 0, err
			}
			restrictions, err = monitorRestrictionValues(
				entry.Values("restrictedOperation"),
			)
			if err != nil {
				return 0, err
			}
		}
		if restrictions&restrictExtended != 0 &&
			restrictions&restrictSpecificExtended != 0 {
			return 0, operationFailed(ldapwire.ResultConstraintViolation, "")
		}
	}
	values := entry.Values("readOnly")
	if len(values) != 1 {
		return 0, operationFailed(ldapwire.ResultConstraintViolation, "")
	}
	entry.ReplaceValues(
		"readOnly",
		stringValues(monitorBoolean(restrictions&restrictWrites == restrictWrites)),
	)
	setMonitorRestrictionValues(entry, restrictions)
	return restrictions, nil
}

func monitorRestrictionValues(values [][]byte) (databaseRestrictions, error) {
	var restrictions databaseRestrictions
	for _, raw := range values {
		flag, ok := databaseRestrictionName(string(raw), false)
		if !ok || restrictions&flag != 0 {
			return 0, operationFailed(ldapwire.ResultInvalidAttributeSyntax, "")
		}
		restrictions |= flag
	}
	return restrictions, nil
}

func setMonitorRestrictionValues(
	entry *directory.Entry,
	restrictions databaseRestrictions,
) {
	entry.ReplaceValues(
		"restrictedOperation",
		stringValues(databaseRestrictionValues(restrictions)...),
	)
}

func monitorCanonicalAttribute(
	runtime *runtimeState,
	description string,
	allowed ...string,
) string {
	if strings.Contains(description, ";") {
		return ""
	}
	candidate, exists := runtime.schema.AttributeType(description)
	if !exists {
		return ""
	}
	for _, name := range allowed {
		target, exists := runtime.schema.AttributeType(name)
		if exists && candidate.OID == target.OID {
			return name
		}
	}
	return ""
}

func monitorDatabaseIndexForEntry(
	databases []runtimeDatabase,
	dn directory.DN,
) int {
	for _, monitored := range monitorRuntimeDatabases(databases) {
		candidate, err := directory.ParseDN(fmt.Sprintf(
			"cn=Database %d,cn=Databases,cn=Monitor",
			monitored.monitorIndex,
		))
		if err == nil && candidate.Equal(dn) {
			return monitored.runtimeIndex
		}
	}
	return -1
}
