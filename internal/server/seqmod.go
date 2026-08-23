package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type seqmodRuntimeConfiguration struct {
	configDNKey string
	disabled    bool
	coordinator *seqmodCoordinator
}

type seqmodConfigurationError struct {
	code       ldapwire.ResultCode
	diagnostic string
}

func (failure *seqmodConfigurationError) Error() string {
	return failure.diagnostic
}

func seqmodConfigurationFailure(
	code ldapwire.ResultCode,
	format string,
	arguments ...any,
) error {
	return &seqmodConfigurationError{
		code:       code,
		diagnostic: fmt.Sprintf(format, arguments...),
	}
}

func seqmodConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *seqmodConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(failure.code, failure.diagnostic), true
}

func loadSeqmodRuntimeConfiguration(
	entry directory.Entry,
	entryDN directory.DN,
) (seqmodRuntimeConfiguration, error) {
	if err := validateSeqmodConfigurationAttributes(entry); err != nil {
		return seqmodRuntimeConfiguration{}, err
	}

	overlayValues := entry.Values("olcOverlay")
	if len(overlayValues) != 1 {
		return seqmodRuntimeConfiguration{}, seqmodConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"%s olcOverlay must be single-valued",
			entry.DN,
		)
	}
	attributeIndex, err := parseOrderedSeqmodName(string(overlayValues[0]))
	if err != nil {
		return seqmodRuntimeConfiguration{}, seqmodConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"%s olcOverlay: %v",
			entry.DN,
			err,
		)
	}
	rdnValues := entryDN.RDNValues()
	if len(rdnValues) != 1 || !strings.EqualFold(rdnValues[0].Type, "olcOverlay") {
		return seqmodRuntimeConfiguration{}, seqmodConfigurationFailure(
			ldapwire.ResultNamingViolation,
			"%s seqmod overlay RDN must be olcOverlay={n}seqmod",
			entry.DN,
		)
	}
	rdnIndex, err := parseOrderedSeqmodName(string(rdnValues[0].Value))
	if err != nil {
		return seqmodRuntimeConfiguration{}, seqmodConfigurationFailure(
			ldapwire.ResultNamingViolation,
			"%s seqmod overlay RDN: %v",
			entry.DN,
			err,
		)
	}
	if rdnIndex != attributeIndex {
		return seqmodRuntimeConfiguration{}, seqmodConfigurationFailure(
			ldapwire.ResultNamingViolation,
			"%s olcOverlay value does not match its RDN",
			entry.DN,
		)
	}
	disabled, _, err := singleBoolean(entry, "olcDisabled")
	if err != nil {
		return seqmodRuntimeConfiguration{}, seqmodConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"%v",
			err,
		)
	}
	return seqmodRuntimeConfiguration{
		configDNKey: entryDN.NormalizedString(),
		disabled:    disabled,
		coordinator: newSeqmodCoordinator(),
	}, nil
}

func validateSeqmodConfigurationAttributes(entry directory.Entry) error {
	allowed := map[string]struct{}{
		"objectclass":           {},
		"olcoverlay":            {},
		"olcdisabled":           {},
		"entryuuid":             {},
		"entrycsn":              {},
		"createtimestamp":       {},
		"modifytimestamp":       {},
		"creatorsname":          {},
		"modifiersname":         {},
		"structuralobjectclass": {},
		"subschemasubentry":     {},
	}
	for _, attribute := range entry.Attributes {
		if _, ok := allowed[strings.ToLower(attribute.Description)]; ok {
			continue
		}
		return seqmodConfigurationFailure(
			ldapwire.ResultUndefinedAttributeType,
			"%s has undefined seqmod configuration attribute %q",
			entry.DN,
			attribute.Description,
		)
	}
	return nil
}

func parseOrderedSeqmodName(value string) (int, error) {
	if len(value) < len("{0}seqmod") || value[0] != '{' {
		return 0, fmt.Errorf("must use the ordered form {n}seqmod")
	}
	end := strings.IndexByte(value, '}')
	if end <= 1 || !strings.EqualFold(value[end+1:], "seqmod") {
		return 0, fmt.Errorf("must use the ordered form {n}seqmod")
	}
	ordering := value[1:end]
	for _, character := range ordering {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("ordering prefix %q is not a nonnegative integer", ordering)
		}
	}
	index, err := strconv.Atoi(ordering)
	if err != nil {
		return 0, fmt.Errorf("ordering prefix %q is invalid", ordering)
	}
	return index, nil
}

func seqmodOverlayDNTargetsSeqmod(entryDN directory.DN) bool {
	rdnValues := entryDN.RDNValues()
	return len(rdnValues) == 1 &&
		strings.EqualFold(rdnValues[0].Type, "olcOverlay") &&
		databaseType(string(rdnValues[0].Value)) == "seqmod"
}

func reuseSeqmodCoordinators(previous, next *runtimeState) {
	if previous == nil || next == nil {
		return
	}
	coordinators := make(map[string]*seqmodCoordinator)
	for index := range previous.databases {
		configuration := previous.databases[index].seqmod
		if configuration != nil {
			coordinators[configuration.configDNKey] = configuration.coordinator
		}
	}
	for index := range next.databases {
		configuration := next.databases[index].seqmod
		if configuration == nil {
			continue
		}
		if coordinator := coordinators[configuration.configDNKey]; coordinator != nil {
			configuration.coordinator = coordinator
		}
	}
}

func acquireFrontendSeqmod(
	ctx context.Context,
	runtime *runtimeState,
	target directory.DN,
) (func(), error) {
	if runtime == nil {
		return seqmodNoopRelease, nil
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if databaseType(database.name) == "frontend" {
			if !seqmodConfigurationActive(database.seqmod) {
				return seqmodNoopRelease, nil
			}
			normalized, err := normalizeSeqmodRuntimeTarget(runtime, target)
			if err != nil {
				return nil, err
			}
			return acquireSeqmodConfiguration(ctx, database.seqmod, normalized)
		}
	}
	return seqmodNoopRelease, nil
}

func acquireDatabaseSeqmod(
	ctx context.Context,
	database runtimeDatabase,
	target directory.DN,
) (func(), error) {
	if databaseType(database.name) == "frontend" {
		return seqmodNoopRelease, nil
	}
	if !seqmodConfigurationActive(database.seqmod) {
		return seqmodNoopRelease, nil
	}
	normalized, err := normalizeRuntimeDatabaseDN(database, target)
	if err != nil {
		return nil, err
	}
	return acquireSeqmodConfiguration(ctx, database.seqmod, normalized)
}

func normalizeSeqmodRuntimeTarget(
	runtime *runtimeState,
	target directory.DN,
) (directory.DN, error) {
	if runtime == nil {
		return target, nil
	}
	if database := databaseForDN(runtime, target); database != nil {
		return normalizeRuntimeDatabaseDN(*database, target)
	}
	if runtime.schema != nil {
		return runtime.schema.NormalizeDN(target.String())
	}
	return target, nil
}

func acquireSeqmodConfiguration(
	ctx context.Context,
	configuration *seqmodRuntimeConfiguration,
	target directory.DN,
) (func(), error) {
	if !seqmodConfigurationActive(configuration) {
		return seqmodNoopRelease, nil
	}
	lock := seqmodHeldLock{
		coordinator: configuration.coordinator,
		targetKey:   target.NormalizedString(),
	}
	if held, ok := ctx.Value(seqmodHeldContextKey{}).(map[seqmodHeldLock]struct{}); ok {
		if _, exists := held[lock]; exists {
			return seqmodNoopRelease, nil
		}
	}
	return configuration.coordinator.acquire(ctx, lock.targetKey)
}

func seqmodConfigurationActive(configuration *seqmodRuntimeConfiguration) bool {
	return configuration != nil &&
		!configuration.disabled &&
		configuration.coordinator != nil
}

func seqmodNoopRelease() {}

type seqmodCoordinator struct {
	mu     sync.Mutex
	queues map[string][]*seqmodWaiter
}

type seqmodWaiter struct {
	ready chan struct{}
}

type seqmodHeldContextKey struct{}

type seqmodHeldLock struct {
	coordinator *seqmodCoordinator
	targetKey   string
}

func newSeqmodCoordinator() *seqmodCoordinator {
	return &seqmodCoordinator{queues: make(map[string][]*seqmodWaiter)}
}

func (coordinator *seqmodCoordinator) acquire(
	ctx context.Context,
	key string,
) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waiter := &seqmodWaiter{ready: make(chan struct{})}
	coordinator.mu.Lock()
	queue := coordinator.queues[key]
	coordinator.queues[key] = append(queue, waiter)
	if len(queue) == 0 {
		close(waiter.ready)
	}
	coordinator.mu.Unlock()

	select {
	case <-waiter.ready:
		return coordinator.releaseOnce(key, waiter), nil
	case <-ctx.Done():
		coordinator.removeCanceled(key, waiter)
		return nil, ctx.Err()
	}
}

func (coordinator *seqmodCoordinator) releaseOnce(
	key string,
	waiter *seqmodWaiter,
) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			coordinator.mu.Lock()
			defer coordinator.mu.Unlock()
			queue := coordinator.queues[key]
			if len(queue) == 0 || queue[0] != waiter {
				return
			}
			coordinator.promoteNextLocked(key, queue[1:])
		})
	}
}

func (coordinator *seqmodCoordinator) removeCanceled(
	key string,
	waiter *seqmodWaiter,
) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	queue := coordinator.queues[key]
	for index, candidate := range queue {
		if candidate != waiter {
			continue
		}
		if index == 0 {
			coordinator.promoteNextLocked(key, queue[1:])
			return
		}
		copy(queue[index:], queue[index+1:])
		queue[len(queue)-1] = nil
		coordinator.queues[key] = queue[:len(queue)-1]
		return
	}
}

func (coordinator *seqmodCoordinator) promoteNextLocked(
	key string,
	queue []*seqmodWaiter,
) {
	if len(queue) == 0 {
		delete(coordinator.queues, key)
		return
	}
	coordinator.queues[key] = queue
	close(queue[0].ready)
}
