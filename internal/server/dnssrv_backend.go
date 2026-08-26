package server

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	defaultDNSSRVCacheTTL    = 5 * time.Minute
	defaultDNSSRVNegativeTTL = 30 * time.Second
	defaultDNSSRVCacheSize   = 1024
	dnssrvNoRecordsMessage   = "no DNS SRV RR available for DN"
	dnssrvReferralMessage    = "DNS SRV generated referrals"
)

// DNSSRVResolver is implemented by net.Resolver and injectable resolvers.
type DNSSRVResolver interface {
	LookupSRV(
		ctx context.Context,
		service, proto, name string,
	) (canonicalName string, records []*net.SRV, err error)
}

type dnssrvBackendRuntimeConfiguration struct {
	common      chainRemoteConfiguration
	positiveTTL time.Duration
	negativeTTL time.Duration
	resolver    DNSSRVResolver
	now         func() time.Time

	mu              sync.Mutex
	cache           map[string]*list.Element
	lru             *list.List
	maxCacheEntries int
	inflight        map[string]*dnssrvLookup
}

type dnssrvCacheEntry struct {
	key     string
	expires time.Time
	remotes []chainRemoteConfiguration
	failure *ldapwire.Result
}

type dnssrvLookup struct {
	done  chan struct{}
	entry dnssrvCacheEntry
}

func loadDNSSRVBackendRuntimeConfiguration(
	entry directory.Entry,
) (*dnssrvBackendRuntimeConfiguration, error) {
	positive, _, err := singleDDSTime(entry, "olcDNSSRVCacheTTL", defaultDNSSRVCacheTTL)
	if err != nil {
		return nil, err
	}
	negative, _, err := singleDDSTime(entry, "olcDNSSRVNegativeTTL", defaultDNSSRVNegativeTTL)
	if err != nil {
		return nil, err
	}
	if positive <= 0 || negative <= 0 {
		return nil, fmt.Errorf("%s dnssrv cache TTLs must be greater than zero", entry.DN)
	}
	return &dnssrvBackendRuntimeConfiguration{
		common:          defaultChainRemoteConfiguration(),
		positiveTTL:     positive,
		negativeTTL:     negative,
		now:             time.Now,
		cache:           make(map[string]*list.Element),
		lru:             list.New(),
		maxCacheEntries: defaultDNSSRVCacheSize,
		inflight:        make(map[string]*dnssrvLookup),
	}, nil
}

func (configuration *dnssrvBackendRuntimeConfiguration) resolve(
	ctx context.Context,
	dn directory.DN,
) (*ldapBackendRuntimeConfiguration, *ldapwire.Result) {
	domain, ok := dnssrvDomain(dn)
	if !ok {
		failure := ldapwire.ResultError(ldapwire.ResultNoSuchObject, dnssrvNoRecordsMessage)
		return nil, &failure
	}
	key := strings.ToLower(domain)
	now := configuration.now
	if now == nil {
		now = time.Now
	}
	configuration.mu.Lock()
	configuration.initializeCacheLocked()
	configuration.removeExpiredLocked(now())
	if element, found := configuration.cache[key]; found {
		configuration.lru.MoveToFront(element)
		cached := element.Value.(dnssrvCacheEntry)
		configuration.mu.Unlock()
		return dnssrvLDAPConfiguration(cached.remotes), cloneDNSSRVFailure(cached.failure)
	}
	if pending, found := configuration.inflight[key]; found {
		configuration.mu.Unlock()
		select {
		case <-pending.done:
			return dnssrvLDAPConfiguration(pending.entry.remotes),
				cloneDNSSRVFailure(pending.entry.failure)
		case <-ctx.Done():
			failure := ldapwire.ResultError(ldapwire.ResultUnavailable, "DNS SRV lookup canceled")
			return nil, &failure
		}
	}
	pending := &dnssrvLookup{done: make(chan struct{})}
	configuration.inflight[key] = pending
	configuration.mu.Unlock()

	resolver := configuration.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	_, records, err := resolver.LookupSRV(ctx, "ldap", "tcp", domain)
	remotes, failure := configuration.remotesFromSRV(records, err)
	ttl := configuration.positiveTTL
	if failure != nil {
		ttl = configuration.negativeTTL
	}
	entry := dnssrvCacheEntry{
		key:     key,
		expires: now().Add(ttl),
		remotes: cloneDNSSRVRemotes(remotes),
		failure: cloneDNSSRVFailure(failure),
	}
	configuration.mu.Lock()
	pending.entry = entry
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		configuration.storeCacheEntryLocked(entry)
	}
	delete(configuration.inflight, key)
	close(pending.done)
	configuration.mu.Unlock()
	return dnssrvLDAPConfiguration(remotes), failure
}

func (configuration *dnssrvBackendRuntimeConfiguration) initializeCacheLocked() {
	if configuration.cache == nil {
		configuration.cache = make(map[string]*list.Element)
	}
	if configuration.lru == nil {
		configuration.lru = list.New()
	}
	if configuration.inflight == nil {
		configuration.inflight = make(map[string]*dnssrvLookup)
	}
	if configuration.maxCacheEntries <= 0 {
		configuration.maxCacheEntries = defaultDNSSRVCacheSize
	}
}

func (configuration *dnssrvBackendRuntimeConfiguration) removeExpiredLocked(now time.Time) {
	for element := configuration.lru.Back(); element != nil; {
		previous := element.Prev()
		entry := element.Value.(dnssrvCacheEntry)
		if !now.Before(entry.expires) {
			delete(configuration.cache, entry.key)
			configuration.lru.Remove(element)
		}
		element = previous
	}
}

func (configuration *dnssrvBackendRuntimeConfiguration) storeCacheEntryLocked(
	entry dnssrvCacheEntry,
) {
	if existing, found := configuration.cache[entry.key]; found {
		existing.Value = entry
		configuration.lru.MoveToFront(existing)
		return
	}
	element := configuration.lru.PushFront(entry)
	configuration.cache[entry.key] = element
	for configuration.lru.Len() > configuration.maxCacheEntries {
		oldest := configuration.lru.Back()
		if oldest == nil {
			break
		}
		delete(configuration.cache, oldest.Value.(dnssrvCacheEntry).key)
		configuration.lru.Remove(oldest)
	}
}

func (configuration *dnssrvBackendRuntimeConfiguration) remotesFromSRV(
	records []*net.SRV,
	lookupErr error,
) ([]chainRemoteConfiguration, *ldapwire.Result) {
	if lookupErr != nil {
		code := ldapwire.ResultUnavailable
		diagnostic := "DNS SRV lookup failed"
		var dnsErr *net.DNSError
		if errors.As(lookupErr, &dnsErr) && dnsErr.IsNotFound {
			code = ldapwire.ResultNoSuchObject
			diagnostic = dnssrvNoRecordsMessage
		}
		failure := ldapwire.ResultError(code, diagnostic)
		return nil, &failure
	}
	ordered := make([]*net.SRV, 0, len(records))
	for _, record := range records {
		if record == nil || record.Port == 0 {
			continue
		}
		target := strings.TrimSuffix(strings.TrimSpace(record.Target), ".")
		if target == "" {
			continue
		}
		copy := *record
		copy.Target = target
		ordered = append(ordered, &copy)
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].Priority < ordered[right].Priority
	})
	remotes := make([]chainRemoteConfiguration, 0, len(ordered))
	for _, record := range ordered {
		rawURI := "ldap://" + net.JoinHostPort(record.Target, fmt.Sprintf("%d", record.Port))
		parsed, endpointKey, err := parseChainConfiguredURI(rawURI)
		if err != nil {
			continue
		}
		remote := configuration.common.clone()
		remote.uri = parsed
		remote.endpointKey = endpointKey
		remotes = append(remotes, remote)
	}
	if len(remotes) == 0 {
		failure := ldapwire.ResultError(ldapwire.ResultNoSuchObject, dnssrvNoRecordsMessage)
		return nil, &failure
	}
	return remotes, nil
}

func dnssrvDomain(dn directory.DN) (string, bool) {
	labels := make([]string, 0)
	current := dn
	started := false
	for current.Depth() > 0 {
		rdn := current.RDNValues()
		isDC := len(rdn) == 1 &&
			(strings.EqualFold(rdn[0].Type, "dc") ||
				strings.EqualFold(rdn[0].Type, "0.9.2342.19200300.100.1.25")) &&
			len(rdn[0].Value) > 0
		if isDC {
			started = true
			label := string(rdn[0].Value)
			if strings.ContainsAny(label, ".\x00") {
				return "", false
			}
			labels = append(labels, label)
		} else if started {
			labels = labels[:0]
			started = false
		}
		parent, ok := current.Parent()
		if !ok {
			break
		}
		current = parent
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

func dnssrvLDAPConfiguration(remotes []chainRemoteConfiguration) *ldapBackendRuntimeConfiguration {
	if len(remotes) == 0 {
		return nil
	}
	return &ldapBackendRuntimeConfiguration{
		remotes:   cloneDNSSRVRemotes(remotes),
		preferred: &proxyPreferredRemoteState{},
	}
}

func cloneDNSSRVRemotes(remotes []chainRemoteConfiguration) []chainRemoteConfiguration {
	cloned := make([]chainRemoteConfiguration, len(remotes))
	for index := range remotes {
		cloned[index] = remotes[index].clone()
	}
	return cloned
}

func cloneDNSSRVFailure(failure *ldapwire.Result) *ldapwire.Result {
	if failure == nil {
		return nil
	}
	cloned := *failure
	cloned.Referrals = append([]string(nil), failure.Referrals...)
	return &cloned
}

func (server *Server) tryDNSSRVBackendOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	if _, bind := message.Request.(ldapwire.BindRequest); bind {
		return false, nil
	}
	target, ok := dnssrvRequestTarget(state, message.Request)
	if !ok {
		return false, nil
	}
	database := databaseForDN(state.runtime, target)
	if database == nil || database.dnssrvBackend == nil {
		return false, nil
	}
	if databaseRestricts(*database, requestDatabaseRestriction(message.Request)) {
		return true, writeResultForMessage(connection, message, ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform, "operation restricted",
		))
	}
	support := supportsManageDsaIT | supportsLazyCommit
	if _, search := message.Request.(ldapwire.SearchRequest); search {
		support |= supportsMatchedValues
	}
	controls, controlFailure := parseRequestControlsWithDisallows(
		message.Controls,
		support,
		state.runtime.disallows,
	)
	if controlFailure != nil {
		return true, writeResultForMessage(connection, message, *controlFailure)
	}
	if controls.manageDsaIT {
		if _, search := message.Request.(ldapwire.SearchRequest); search {
			return true, writeResultForMessage(connection, message, ldapwire.Result{
				Code: ldapwire.ResultNoSuchObject,
			})
		}
		return true, writeResultForMessage(connection, message, ldapwire.ResultError(
			ldapwire.ResultOther,
			"DNS SRV problem processing manageDSAit control",
		))
	}
	configuration, failure := database.dnssrvBackend.resolve(ctx, target)
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	referrals := make([]string, 0, len(configuration.remotes))
	for _, remote := range configuration.remotes {
		referrals = append(referrals, remote.uri)
	}
	return true, writeResultForMessage(connection, message, ldapwire.Result{
		Code:              ldapwire.ResultReferral,
		DiagnosticMessage: dnssrvReferralMessage,
		Referrals:         referrals,
	})
}

func (server *Server) tryDNSSRVBackendBind(
	_ context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	requestDN directory.DN,
) (bool, error) {
	database := databaseForDN(state.runtime, requestDN)
	if database == nil || database.dnssrvBackend == nil {
		return false, nil
	}
	if _, root := databaseAuthenticationRoot(state.runtime, *database, requestDN); root {
		return false, nil
	}
	diagnostic := "anonymous bind expected"
	if request.Authentication.IsSASL || len(request.Authentication.Simple) != 0 {
		diagnostic = "you shouldn't send strangers your password"
	}
	return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, diagnostic),
		nil,
	))
}

func dnssrvRequestTarget(
	state *connectionState,
	request ldapwire.Request,
) (directory.DN, bool) {
	if extended, ok := request.(ldapwire.ExtendedRequest); ok {
		if extended.Name == transactionStartOID || extended.Name == transactionEndOID ||
			extended.Name == whoAmIOID {
			if state.boundDN == "" {
				return directory.DN{}, false
			}
			dn, err := parseConnectionDN(state, state.boundDN)
			return dn, err == nil
		}
	}
	target, _, _, ok := chainOperationTarget(state, request)
	return target, ok
}
