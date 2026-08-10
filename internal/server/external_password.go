package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const defaultOpenLDAPRADIUSConfigPath = "/etc/radius.conf"

var (
	canonicalLocalHostnameOnce sync.Once
	canonicalLocalHostnameName string
	canonicalLocalHostnameErr  error
	openLDAPRADIUSPasswordMu   sync.Mutex
)

type externalPasswordRuntimeConfiguration struct {
	radiusEnabled       bool
	radiusConfigPath    string
	radiusNASIdentifier string
}

func loadExternalPasswordRuntimeConfiguration(
	reader storage.Reader,
	config Config,
) (externalPasswordRuntimeConfiguration, error) {
	result := externalPasswordRuntimeConfiguration{
		radiusConfigPath:    strings.TrimSpace(config.RADIUSConfigPath),
		radiusNASIdentifier: strings.TrimSpace(config.RADIUSNASIdentifier),
	}
	result.radiusEnabled = result.radiusConfigPath != ""

	var moduleConfigPath string
	var moduleConfigSet bool
	var radiusModuleSeen bool
	err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !configurationSuffix.Equal(entryDN) &&
			!configurationSuffix.AncestorOf(entryDN) {
			return nil
		}
		for _, raw := range entry.Values("olcModuleLoad") {
			module, arguments, err := parseOpenLDAPModuleLoad(string(raw))
			if err != nil {
				return fmt.Errorf("%s olcModuleLoad: %w", entry.DN, err)
			}
			if !openLDAPPasswordModuleName(module, "pw-radius") {
				continue
			}
			if radiusModuleSeen {
				return errors.New("pw-radius module is loaded more than once")
			}
			radiusModuleSeen = true
			for _, argument := range arguments {
				key, value, found := strings.Cut(argument, "=")
				if !found || !strings.EqualFold(key, "config") {
					return fmt.Errorf("pw-radius has unknown argument %q", argument)
				}
				if !moduleConfigSet {
					moduleConfigPath = value
					moduleConfigSet = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return result, fmt.Errorf("load external password modules: %w", err)
	}
	if result.radiusConfigPath == "" && moduleConfigSet {
		result.radiusConfigPath = moduleConfigPath
	}
	if radiusModuleSeen {
		result.radiusEnabled = true
	}
	if result.radiusConfigPath == "" && radiusModuleSeen && !moduleConfigSet {
		result.radiusConfigPath = defaultOpenLDAPRADIUSConfigPath
	}
	if result.radiusEnabled && result.radiusNASIdentifier == "" {
		hostname, err := canonicalLocalHostname()
		if err != nil {
			return result, fmt.Errorf("resolve RADIUS NAS identifier: %w", err)
		}
		result.radiusNASIdentifier = hostname
	}
	return result, nil
}

func (server *Server) verifyStoredPassword(
	ctx context.Context,
	runtime *runtimeState,
	stored, supplied []byte,
) bool {
	scheme, identity := externalPasswordScheme(stored)
	if scheme == "" {
		return auth.VerifyPassword(stored, supplied)
	}
	if len(supplied) == 0 {
		return false
	}

	switch scheme {
	case auth.OpenLDAPRADIUSHashScheme:
		if !runtime.externalPasswords.radiusEnabled {
			return false
		}
		openLDAPRADIUSPasswordMu.Lock()
		defer openLDAPRADIUSPasswordMu.Unlock()
		servers, err := auth.LoadOpenLDAPRADIUSConfig(
			runtime.externalPasswords.radiusConfigPath,
		)
		if err == nil {
			defer func() {
				for index := range servers {
					clear(servers[index].Secret)
				}
			}()
			var authenticated bool
			authenticated, err = auth.VerifyOpenLDAPRADIUSPassword(
				ctx,
				servers,
				identity,
				supplied,
				[]byte(runtime.externalPasswords.radiusNASIdentifier),
			)
			if err == nil {
				return authenticated
			}
		}
		server.config.Logger.Warn(
			"external password verification failed",
			"scheme",
			auth.OpenLDAPRADIUSHashScheme,
			"error",
			err,
		)
		return false
	default:
		return false
	}
}

func canonicalLocalHostname() (string, error) {
	canonicalLocalHostnameOnce.Do(func() {
		hostname, err := os.Hostname()
		if err != nil {
			canonicalLocalHostnameErr = err
			return
		}
		hostname = strings.TrimSuffix(strings.TrimSpace(hostname), ".")
		if hostname == "" {
			canonicalLocalHostnameErr = errors.New("local hostname is empty")
			return
		}
		canonicalLocalHostnameName = hostname
		canonical, err := net.LookupCNAME(hostname)
		if err == nil {
			canonical = strings.TrimSuffix(strings.TrimSpace(canonical), ".")
			if canonical != "" {
				canonicalLocalHostnameName = canonical
			}
		}
	})
	return canonicalLocalHostnameName, canonicalLocalHostnameErr
}

type externalPasswordMatchKey struct {
	stored   [sha256.Size]byte
	supplied [sha256.Size]byte
}

type externalPasswordMatches struct {
	values    map[externalPasswordMatchKey]bool
	collector *externalPasswordVerificationCollector
}

type externalPasswordVerificationSequence struct {
	stored        [][]byte
	supplied      []byte
	requiresMatch bool
}

type preparedExternalPasswordVerificationContextKey struct{}

type collectExternalPasswordVerificationContextKey struct{}

type externalPasswordVerificationCollector struct {
	matches externalPasswordMatches
	request *externalPasswordVerificationSequence
}

type preparedExternalPasswordVerification struct {
	matches externalPasswordMatches
}

func verifyStoredPasswordWithExternalMatches(
	stored, supplied []byte,
	externalMatches externalPasswordMatches,
) bool {
	if scheme, _ := externalPasswordScheme(stored); scheme != "" {
		key := newExternalPasswordMatchKey(stored, supplied)
		matched, _ := externalMatches.values[key]
		return matched
	}
	return auth.VerifyPassword(stored, supplied)
}

func (server *Server) preverifyOrderedPasswords(
	ctx context.Context,
	runtime *runtimeState,
	storedValues [][]byte,
	supplied []byte,
	matches externalPasswordMatches,
) bool {
	for _, stored := range storedValues {
		if scheme, _ := externalPasswordScheme(stored); scheme != "" {
			key := newExternalPasswordMatchKey(stored, supplied)
			matched, seen := matches.values[key]
			if !seen {
				matched = server.verifyStoredPassword(ctx, runtime, stored, supplied)
				matches.values[key] = matched
			}
			if matched {
				return true
			}
			continue
		}
		if auth.VerifyPassword(stored, supplied) {
			return true
		}
	}
	return false
}

func newExternalPasswordMatchKey(stored, supplied []byte) externalPasswordMatchKey {
	return externalPasswordMatchKey{
		stored:   sha256.Sum256(stored),
		supplied: sha256.Sum256(supplied),
	}
}

func newExternalPasswordMatches() externalPasswordMatches {
	return externalPasswordMatches{
		values: make(map[externalPasswordMatchKey]bool),
	}
}

func (matches externalPasswordMatches) empty() bool {
	return len(matches.values) == 0
}

func externalPasswordStateChanged() error {
	return operationFailed(
		ldapwire.ResultBusy,
		"external password verification state changed; retry the operation",
	)
}

func (server *Server) preverifyExternalPasswordBind(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	password []byte,
	now time.Time,
) (externalPasswordMatches, error) {
	var candidates [][]byte
	totpPasswordEnabled := false
	lastTOTPAuthentication := time.Time{}
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		entry, err := tx.Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if runtime.schema.EntryHasObjectClass(entry, "subentry") ||
			runtime.schema.EntryHasObjectClass(entry, "alias") ||
			runtime.schema.EntryHasObjectClass(entry, "referral") {
			return nil
		}
		policy, hasPolicy := loadPasswordPolicy(runtime, reader, database, entry)
		if database.ppolicy != nil && hasPolicy {
			locked, _ := evaluatePasswordPolicyAccountLock(
				entry,
				policy,
				database,
				now,
			)
			if locked {
				return nil
			}
		}
		totpPasswordEnabled = activeTOTPPasswordConfiguration(runtime, &database) != nil
		if totpPasswordEnabled {
			lastTOTPAuthentication = totpPasswordLastAuthentication(runtime.schema, entry)
		}
		for _, stored := range runtime.schema.AttributeValues(entry, policy.attribute) {
			if !server.allowed(
				runtime,
				tx,
				"",
				entry,
				policy.attribute,
				stored,
				acl.Auth,
			) {
				continue
			}
			candidates = append(candidates, bytes.Clone(stored))
		}
		return nil
	})
	if err != nil || len(candidates) == 0 {
		return externalPasswordMatches{}, err
	}
	matches := newExternalPasswordMatches()
	for _, stored := range candidates {
		if scheme, _ := externalPasswordScheme(stored); scheme != "" {
			if server.preverifyOrderedPasswords(
				ctx, runtime, [][]byte{stored}, password, matches,
			) {
				break
			}
			continue
		}
		matched := auth.VerifyPassword(stored, password)
		if totpPasswordEnabled && auth.IsTOTPPassword(stored) {
			matched = auth.VerifyTOTPPassword(
				stored,
				password,
				now,
				lastTOTPAuthentication,
			)
		}
		if matched {
			break
		}
	}
	if matches.empty() {
		return externalPasswordMatches{}, nil
	}
	return matches, nil
}

func (server *Server) preverifyPasswordModification(
	ctx context.Context,
	runtime *runtimeState,
	boundDN string,
	database runtimeDatabase,
	target directory.DN,
	changes []ldapwire.Modification,
	assertion *directory.Filter,
	options passwordPolicyModificationOptions,
) (externalPasswordMatches, error) {
	var sequences []externalPasswordVerificationSequence
	defer func() { clearExternalPasswordVerificationSequences(sequences) }()
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		entry, err := tx.Get(target)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		appendSequence := func(
			storedValues [][]byte,
			supplied []byte,
			requiresMatch bool,
		) {
			sequences = append(sequences, externalPasswordVerificationSequence{
				stored:        cloneByteValues(storedValues),
				supplied:      bytes.Clone(supplied),
				requiresMatch: requiresMatch,
			})
		}

		if options.passwordModify && options.hasOldPassword {
			var allowedValues [][]byte
			for _, stored := range runtime.schema.AttributeValues(entry, "userPassword") {
				if !server.allowed(
					runtime,
					tx,
					boundDN,
					entry,
					"userPassword",
					stored,
					acl.Auth,
				) {
					continue
				}
				allowedValues = append(allowedValues, stored)
			}
			appendSequence(allowedValues, options.oldPassword, true)
		}
		if database.ppolicy != nil && !database.ppolicy.disableWrite {
			prepared, err := server.preparePasswordPolicyModification(
				runtime,
				reader,
				boundDN,
				database,
				entry,
				changes,
				options,
			)
			if err != nil {
				return err
			}
			policy := prepared.policy
			processed := prepared.processed
			analysis := prepared.analysis
			if analysis.passwordModified {
				oldPassword := passwordPolicyOldPassword(analysis, options)
				if len(oldPassword) > 0 {
					appendSequence(
						runtime.schema.AttributeValues(entry, policy.attribute),
						oldPassword,
						true,
					)
				}
				if analysis.newPasswordIndex >= 0 && prepared.hasPolicy &&
					policy.inHistory > 0 && !prepared.passwordAdministrator {
					candidate := processed[analysis.newPasswordIndex].Attribute.Values[0]
					if options.passwordModify {
						candidate = options.newPassword
					}
					currentAndHistory := cloneByteValues(
						runtime.schema.AttributeValues(entry, policy.attribute),
					)
					history := parsePasswordHistory(entry.Values("pwdHistory"))
					if len(history) > policy.inHistory {
						history = history[len(history)-policy.inHistory:]
					}
					for _, item := range history {
						currentAndHistory = append(currentAndHistory, bytes.Clone(item.password))
					}
					appendSequence(currentAndHistory, candidate, false)
				}
			}
		}
		if !externalPasswordSequencesNeedVerification(sequences) {
			sequences = nil
			return nil
		}
		collectivePlan, err := buildCollectiveAttributePlan(runtime.schema, tx)
		if err != nil {
			return err
		}
		logicalEntry, err := collectivePlan.apply(entry)
		if err != nil {
			return err
		}
		if err := server.checkAssertion(
			runtime,
			tx,
			boundDN,
			logicalEntry,
			assertion,
		); err != nil {
			return err
		}
		if !server.canApplyModifications(runtime, tx, boundDN, logicalEntry, changes) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		return nil
	})
	if err != nil {
		return externalPasswordMatches{}, err
	}
	if collector, present := ctx.Value(
		collectExternalPasswordVerificationContextKey{},
	).(*externalPasswordVerificationCollector); present {
		matches := collector.matches
		matches.collector = collector
		return matches, nil
	}
	if len(sequences) == 0 {
		return externalPasswordMatches{}, nil
	}
	if prepared, present, err := preparedExternalPasswordMatches(ctx); present {
		return prepared, err
	}
	matches := newExternalPasswordMatches()
	for _, sequence := range sequences {
		matched := server.preverifyOrderedPasswords(
			ctx,
			runtime,
			sequence.stored,
			sequence.supplied,
			matches,
		)
		if sequence.requiresMatch && !matched {
			break
		}
	}
	if matches.empty() {
		return externalPasswordMatches{}, nil
	}
	return matches, nil
}

func externalPasswordSequencesNeedVerification(
	sequences []externalPasswordVerificationSequence,
) bool {
	for _, sequence := range sequences {
		for _, stored := range sequence.stored {
			if scheme, _ := externalPasswordScheme(stored); scheme != "" {
				return true
			}
		}
	}
	return false
}

func preparedExternalPasswordMatches(
	ctx context.Context,
) (externalPasswordMatches, bool, error) {
	prepared, present := ctx.Value(
		preparedExternalPasswordVerificationContextKey{},
	).(preparedExternalPasswordVerification)
	if !present {
		return externalPasswordMatches{}, false, nil
	}
	return prepared.matches, true, nil
}

func validateExternalPasswordMatches(
	matches externalPasswordMatches,
	storedValues [][]byte,
	supplied []byte,
) error {
	for _, stored := range storedValues {
		if scheme, _ := externalPasswordScheme(stored); scheme == "" {
			if auth.VerifyPassword(stored, supplied) {
				return nil
			}
			continue
		}
		key := newExternalPasswordMatchKey(stored, supplied)
		matched, exists := matches.values[key]
		if !exists {
			if matches.collector != nil {
				if matches.collector.request == nil {
					matches.collector.request = &externalPasswordVerificationSequence{
						stored:   cloneByteValues(storedValues),
						supplied: bytes.Clone(supplied),
					}
				}
				return operationFailed(
					ldapwire.ResultBusy,
					"external password verification pending",
				)
			}
			return externalPasswordStateChanged()
		}
		if matched {
			return nil
		}
	}
	return nil
}

func (server *Server) preverifyEntryPasswords(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	target directory.DN,
	attribute string,
	supplied []byte,
) (externalPasswordMatches, error) {
	var (
		storedValues [][]byte
	)
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		entry, err := readerForDatabase(reader, database).Get(target)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, stored := range runtime.schema.AttributeValues(entry, attribute) {
			storedValues = append(storedValues, bytes.Clone(stored))
		}
		return nil
	})
	if err != nil || len(storedValues) == 0 {
		return externalPasswordMatches{}, err
	}
	defer func() {
		for _, stored := range storedValues {
			clear(stored)
		}
	}()
	if collector, present := ctx.Value(
		collectExternalPasswordVerificationContextKey{},
	).(*externalPasswordVerificationCollector); present {
		matches := collector.matches
		matches.collector = collector
		return matches, nil
	}
	if prepared, present, err := preparedExternalPasswordMatches(ctx); present {
		return prepared, err
	}
	matches := newExternalPasswordMatches()
	server.preverifyOrderedPasswords(ctx, runtime, storedValues, supplied, matches)
	if matches.empty() {
		return externalPasswordMatches{}, nil
	}
	return matches, nil
}

func clearExternalPasswordVerificationSequences(
	sequences []externalPasswordVerificationSequence,
) {
	for index := range sequences {
		for _, stored := range sequences[index].stored {
			clear(stored)
		}
		clear(sequences[index].supplied)
	}
}

func externalPasswordScheme(stored []byte) (string, []byte) {
	scheme := auth.OpenLDAPRADIUSHashScheme
	if len(stored) >= len(scheme) &&
		bytes.EqualFold(stored[:len(scheme)], []byte(scheme)) {
		return scheme, stored[len(scheme):]
	}
	return "", nil
}

func parseOpenLDAPModuleLoad(value string) (string, []string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") {
		end := strings.IndexByte(value, '}')
		if end < 2 {
			return "", nil, errors.New("invalid ordering prefix")
		}
		if _, err := strconv.ParseUint(value[1:end], 10, 31); err != nil {
			return "", nil, errors.New("invalid ordering prefix")
		}
		value = strings.TrimSpace(value[end+1:])
	}
	fields, err := splitOpenLDAPModuleFields(value)
	if err != nil {
		return "", nil, err
	}
	if len(fields) == 0 {
		return "", nil, errors.New("empty module load value")
	}
	return fields[0], fields[1:], nil
}

func splitOpenLDAPModuleFields(value string) ([]string, error) {
	var fields []string
	for offset := 0; ; {
		for offset < len(value) && (value[offset] == ' ' || value[offset] == '\t') {
			offset++
		}
		if offset == len(value) {
			return fields, nil
		}
		var field strings.Builder
		quoted := false
		for offset < len(value) {
			character := value[offset]
			switch {
			case character == '"':
				quoted = !quoted
				offset++
			case character == '\\':
				if offset+1 == len(value) {
					return nil, errors.New("module argument ends with an escape")
				}
				field.WriteByte(value[offset+1])
				offset += 2
			case !quoted && (character == ' ' || character == '\t'):
				offset++
				fields = append(fields, field.String())
				goto next
			default:
				field.WriteByte(character)
				offset++
			}
		}
		if quoted {
			return nil, errors.New("unterminated quoted module argument")
		}
		fields = append(fields, field.String())
		return fields, nil
	next:
	}
}

func openLDAPPasswordModuleName(value, name string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(value)))
	return base == name || strings.HasPrefix(base, name+".")
}

func validateOpenLDAPModuleOnlineModification(
	runtime *runtimeState,
	entry directory.Entry,
	changes []ldapwire.Modification,
) error {
	moduleEntry := runtime.schema.EntryHasObjectClass(entry, "olcModuleList")
	for _, change := range changes {
		attribute := baseAttributeName(change.Attribute.Description)
		if !strings.EqualFold(attribute, "olcModuleLoad") &&
			!strings.EqualFold(attribute, "olcModulePath") {
			continue
		}
		if !moduleEntry {
			return operationFailed(
				ldapwire.ResultOther,
				"module attributes require an olcModuleList entry",
			)
		}
		if (strings.EqualFold(attribute, "olcModulePath") &&
			change.Operation == ldapwire.ModificationAdd) ||
			change.Operation == ldapwire.ModificationDelete ||
			change.Operation == ldapwire.ModificationReplace {
			return operationFailed(
				ldapwire.ResultOther,
				"cannot delete "+attribute,
			)
		}
	}
	return nil
}

func validateOpenLDAPModuleOnlineAdd(
	runtime *runtimeState,
	entry directory.Entry,
) error {
	hasLoad := entry.HasAttribute("olcModuleLoad")
	hasPath := entry.HasAttribute("olcModulePath")
	if !hasLoad && !hasPath {
		return nil
	}
	if !runtime.schema.EntryHasObjectClass(entry, "olcModuleList") {
		return operationFailed(
			ldapwire.ResultOther,
			"module attributes require an olcModuleList entry",
		)
	}
	if hasPath {
		return operationFailed(
			ldapwire.ResultOther,
			"cannot insert olcModulePath online",
		)
	}
	return nil
}
