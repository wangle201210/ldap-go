package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	passwordPolicyControlOID      = "1.3.6.1.4.1.42.2.27.8.5.1"
	accountUsabilityControlOID    = "1.3.6.1.4.1.42.2.27.9.5.8"
	netscapePasswordExpiredOID    = "2.16.840.1.113730.3.4.4"
	netscapePasswordExpiringOID   = "2.16.840.1.113730.3.4.5"
	passwordHistorySyntaxOID      = "1.3.6.1.4.1.1466.115.121.1.40"
	permanentPasswordLockoutValue = "000001010000Z"
	passwordPolicyRestrictionText = "Operations are restricted to bind/unbind/abandon/StartTLS/modify password"
)

type passwordPolicyError int64

const (
	passwordPolicyNoError                passwordPolicyError = -1
	passwordPolicyPasswordExpired        passwordPolicyError = 0
	passwordPolicyAccountLocked          passwordPolicyError = 1
	passwordPolicyChangeAfterReset       passwordPolicyError = 2
	passwordPolicyModificationNotAllowed passwordPolicyError = 3
	passwordPolicyMustSupplyOldPassword  passwordPolicyError = 4
	passwordPolicyInsufficientQuality    passwordPolicyError = 5
	passwordPolicyTooShort               passwordPolicyError = 6
	passwordPolicyTooYoung               passwordPolicyError = 7
	passwordPolicyInHistory              passwordPolicyError = 8
	passwordPolicyTooLong                passwordPolicyError = 9
)

type passwordPolicyRuntimeConfiguration struct {
	defaultPolicy        *directory.DN
	hashCleartext        bool
	forwardUpdates       bool
	useLockout           bool
	disableWrite         bool
	sendNetscapeControls bool
	passwordCheckModule  string
}

type passwordPolicy struct {
	attribute             string
	minAge                int
	maxAge                int
	maxIdle               int
	inHistory             int
	checkQuality          int
	minLength             int
	maxLength             int
	expireWarning         int
	graceExpiry           int
	graceAuthentication   int
	lockout               bool
	lockoutDuration       int
	minDelay              int
	maxDelay              int
	maxFailure            int
	maxRecordedFailure    int
	failureCountInterval  int
	mustChange            bool
	allowUserChange       bool
	safeModify            bool
	useCheckModule        bool
	checkModuleConfigured bool
	checkModuleArgument   []byte
}

type passwordPolicyModificationOptions struct {
	requestControl bool
	passwordModify bool
	hasOldPassword bool
	oldPassword    []byte
	newPassword    []byte
}

var errInvalidPasswordPolicy = errors.New("invalid password policy")

func defaultPasswordPolicy() passwordPolicy {
	return passwordPolicy{
		attribute:       "userPassword",
		allowUserChange: true,
	}
}

func loadPasswordPolicyRuntimeConfiguration(
	entry directory.Entry,
) (passwordPolicyRuntimeConfiguration, error) {
	var configuration passwordPolicyRuntimeConfiguration
	defaultValues := entry.Values("olcPPolicyDefault")
	if len(defaultValues) > 1 {
		return configuration, fmt.Errorf(
			"%s olcPPolicyDefault must be single-valued",
			entry.DN,
		)
	}
	if len(defaultValues) == 1 {
		defaultPolicy, err := directory.ParseDN(string(defaultValues[0]))
		if err != nil {
			return configuration, fmt.Errorf(
				"%s olcPPolicyDefault: %w",
				entry.DN,
				err,
			)
		}
		configuration.defaultPolicy = &defaultPolicy
	}

	var err error
	configuration.hashCleartext, _, err = singleBoolean(
		entry,
		"olcPPolicyHashCleartext",
	)
	if err != nil {
		return configuration, err
	}
	configuration.forwardUpdates, _, err = singleBoolean(
		entry,
		"olcPPolicyForwardUpdates",
	)
	if err != nil {
		return configuration, err
	}
	configuration.useLockout, _, err = singleBoolean(
		entry,
		"olcPPolicyUseLockout",
	)
	if err != nil {
		return configuration, err
	}
	configuration.disableWrite, _, err = singleBoolean(
		entry,
		"olcPPolicyDisableWrite",
	)
	if err != nil {
		return configuration, err
	}
	configuration.sendNetscapeControls, _, err = singleBoolean(
		entry,
		"olcPPolicySendNetscapeControls",
	)
	if err != nil {
		return configuration, err
	}
	moduleValues := entry.Values("olcPPolicyCheckModule")
	if len(moduleValues) > 1 {
		return configuration, fmt.Errorf(
			"%s olcPPolicyCheckModule must be single-valued",
			entry.DN,
		)
	}
	if len(moduleValues) == 1 {
		configuration.passwordCheckModule = string(moduleValues[0])
	}
	return configuration, nil
}

func loadPasswordPolicy(
	runtime *runtimeState,
	reader storage.Reader,
	database runtimeDatabase,
	entry directory.Entry,
) (passwordPolicy, bool) {
	policy := defaultPasswordPolicy()
	if database.ppolicy == nil {
		return policy, false
	}

	var policyDN *directory.DN
	assigned := entry.Values("pwdPolicySubentry")
	switch len(assigned) {
	case 0:
		policyDN = database.ppolicy.defaultPolicy
	case 1:
		parsed, err := directory.ParseDN(string(assigned[0]))
		if err != nil {
			return policy, false
		}
		policyDN = &parsed
	default:
		return policy, false
	}
	if policyDN == nil {
		return policy, false
	}
	policyDatabase := databaseForDN(runtime, *policyDN)
	if policyDatabase == nil {
		return policy, false
	}
	policyEntry, err := storage.ReaderInPartition(
		reader,
		policyDatabase.partition,
	).Get(*policyDN)
	if err != nil {
		return policy, false
	}
	if err := parsePasswordPolicyEntry(policyEntry, &policy); err != nil {
		return defaultPasswordPolicy(), false
	}
	policy.checkModuleConfigured =
		database.ppolicy.passwordCheckModule != ""
	return policy, true
}

func parsePasswordPolicyEntry(
	entry directory.Entry,
	policy *passwordPolicy,
) error {
	integerAttributes := []struct {
		name   string
		target *int
	}{
		{"pwdMinAge", &policy.minAge},
		{"pwdMaxAge", &policy.maxAge},
		{"pwdMaxIdle", &policy.maxIdle},
		{"pwdInHistory", &policy.inHistory},
		{"pwdCheckQuality", &policy.checkQuality},
		{"pwdMinLength", &policy.minLength},
		{"pwdMaxLength", &policy.maxLength},
		{"pwdExpireWarning", &policy.expireWarning},
		{"pwdGraceExpiry", &policy.graceExpiry},
		{"pwdGraceAuthNLimit", &policy.graceAuthentication},
		{"pwdLockoutDuration", &policy.lockoutDuration},
		{"pwdMinDelay", &policy.minDelay},
		{"pwdMaxDelay", &policy.maxDelay},
		{"pwdMaxFailure", &policy.maxFailure},
		{"pwdMaxRecordedFailure", &policy.maxRecordedFailure},
		{"pwdFailureCountInterval", &policy.failureCountInterval},
	}
	for _, attribute := range integerAttributes {
		value, present, err := passwordPolicyInteger(entry, attribute.name)
		if err != nil {
			return err
		}
		if present {
			*attribute.target = value
		}
	}

	booleanAttributes := []struct {
		name   string
		target *bool
	}{
		{"pwdLockout", &policy.lockout},
		{"pwdMustChange", &policy.mustChange},
		{"pwdAllowUserChange", &policy.allowUserChange},
		{"pwdSafeModify", &policy.safeModify},
		{"pwdUseCheckModule", &policy.useCheckModule},
	}
	for _, attribute := range booleanAttributes {
		value, present, err := passwordPolicyBoolean(entry, attribute.name)
		if err != nil {
			return err
		}
		if present {
			*attribute.target = value
		}
	}

	arguments := entry.Values("pwdCheckModuleArg")
	if len(arguments) > 1 {
		return errInvalidPasswordPolicy
	}
	if len(arguments) == 1 {
		policy.checkModuleArgument = arguments[0]
	}
	if policy.maxRecordedFailure < policy.maxFailure {
		policy.maxRecordedFailure = policy.maxFailure
	}
	if policy.maxRecordedFailure == 0 && policy.minDelay != 0 {
		policy.maxRecordedFailure = 5
	}
	if policy.minDelay != 0 && policy.maxDelay == 0 {
		policy.maxDelay = policy.minDelay
	}
	return nil
}

func passwordPolicyInteger(
	entry directory.Entry,
	attribute string,
) (int, bool, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return 0, false, nil
	}
	if len(values) != 1 {
		return 0, false, errInvalidPasswordPolicy
	}
	parsed, err := strconv.ParseInt(
		strings.TrimSpace(string(values[0])),
		10,
		32,
	)
	if err != nil {
		return 0, false, errInvalidPasswordPolicy
	}
	return int(parsed), true, nil
}

func passwordPolicyBoolean(
	entry directory.Entry,
	attribute string,
) (bool, bool, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return false, false, nil
	}
	if len(values) != 1 {
		return false, false, errInvalidPasswordPolicy
	}
	switch {
	case strings.EqualFold(string(values[0]), "TRUE"):
		return true, true, nil
	case strings.EqualFold(string(values[0]), "FALSE"):
		return false, true, nil
	default:
		return false, false, errInvalidPasswordPolicy
	}
}

func passwordPolicyResponseControl(
	expirationSeconds int,
	graceAuthentications int,
	policyError passwordPolicyError,
) ldapwire.Control {
	return ldapwire.Control{
		OID: passwordPolicyControlOID,
		Value: ldapwire.EncodePasswordPolicyResponseValue(
			int64(expirationSeconds),
			int64(graceAuthentications),
			int64(policyError),
		),
		HasValue: true,
	}
}

func passwordPolicyOperationFailed(
	code ldapwire.ResultCode,
	diagnostic string,
	requestControl bool,
	policyError passwordPolicyError,
) error {
	failure := &operationFailure{
		result: ldapwire.ResultError(code, diagnostic),
	}
	if requestControl {
		failure.controls = []ldapwire.Control{passwordPolicyResponseControl(
			-1,
			-1,
			policyError,
		)}
	}
	return failure
}

func netscapePasswordControl(
	expired bool,
	warningSeconds int,
) ldapwire.Control {
	oid := netscapePasswordExpiringOID
	if expired {
		oid = netscapePasswordExpiredOID
	}
	return ldapwire.Control{
		OID:      oid,
		Value:    []byte(strconv.Itoa(warningSeconds)),
		HasValue: true,
	}
}

func formatPasswordPolicyTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("20060102150405Z")
}

func formatPasswordPolicyFailureTime(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format(
		"20060102150405.000000Z",
	)
}

func parsePasswordPolicyTime(value []byte) (time.Time, bool) {
	raw := string(value)
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405.000000Z",
		"200601021504Z",
	} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func passwordPolicyEnabledForDatabase(database *runtimeDatabase) bool {
	return database != nil && database.ppolicy != nil
}

func runtimeSupportsPasswordPolicy(databases []runtimeDatabase) bool {
	for index := range databases {
		if databases[index].ppolicy != nil {
			return true
		}
	}
	return false
}

type passwordBindResult struct {
	authenticated bool
	restricted    bool
	controls      []ldapwire.Control
}

type passwordBindEvaluation struct {
	policyError          passwordPolicyError
	expirationSeconds    int
	graceAuthentications int
	passwordExpired      bool
	authenticated        bool
	restricted           bool
}

func (server *Server) authenticatePasswordBind(
	ctx context.Context,
	runtime *runtimeState,
	rawDN string,
	password []byte,
	requestControl bool,
) (passwordBindResult, error) {
	var result passwordBindResult
	if rawDN == "" || len(password) == 0 {
		return result, nil
	}
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		return result, nil
	}
	database := databaseForDN(runtime, dn)
	if database == nil {
		return result, nil
	}
	if database.rootDN != nil &&
		database.rootDN.Equal(dn) &&
		database.rootPasswordSet {
		result.authenticated = auth.VerifyPassword(
			database.rootPassword,
			password,
		)
		return result, nil
	}

	evaluation := passwordBindEvaluation{
		policyError:          passwordPolicyNoError,
		expirationSeconds:    -1,
		graceAuthentications: -1,
	}
	var syncChange *syncChange
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
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

		before := entry.Clone()
		policy, hasPolicy := loadPasswordPolicy(
			runtime,
			writer,
			*database,
			entry,
		)
		overlayEnabled := database.ppolicy != nil
		writePolicyState := passwordPolicyWritesLocally(*database)
		var clearExpiredLock bool
		if overlayEnabled && hasPolicy {
			var locked bool
			locked, clearExpiredLock = evaluatePasswordPolicyAccountLock(
				entry,
				policy,
				*database,
				time.Now(),
			)
			if clearExpiredLock && writePolicyState {
				entry.ReplaceValues("pwdAccountLockedTime", nil)
			}
			if locked {
				evaluation.policyError = passwordPolicyAccountLocked
				return server.finishPasswordBindStateWrite(
					writer,
					runtime,
					*database,
					before,
					&entry,
					&syncChange,
				)
			}
		}

		passwordPresent := entry.HasAttribute(policy.attribute)
		for _, stored := range entry.Values(policy.attribute) {
			if server.allowed(
				runtime,
				tx,
				"",
				entry,
				policy.attribute,
				stored,
				acl.Auth,
			) && auth.VerifyPassword(stored, password) {
				evaluation.authenticated = true
			}
		}
		if overlayEnabled && passwordPresent {
			now := time.Now()
			if !evaluation.authenticated {
				if hasPolicy && writePolicyState {
					applyPasswordPolicyBindFailure(&entry, policy, now)
				}
			} else if hasPolicy {
				evaluateSuccessfulPasswordPolicyBind(
					&entry,
					policy,
					now,
					&evaluation,
					writePolicyState,
				)
			}
		}
		if evaluation.authenticated && database.lastBind {
			applyPasswordLastSuccess(
				&entry,
				time.Now(),
				database.lastBindPrecision,
			)
		}
		return server.finishPasswordBindStateWrite(
			writer,
			runtime,
			*database,
			before,
			&entry,
			&syncChange,
		)
	})
	if err != nil {
		return passwordBindResult{}, err
	}
	server.finishWriteEffects(ctx, nil, syncChange)

	result.authenticated = evaluation.authenticated
	result.restricted = evaluation.restricted
	if database.ppolicy != nil {
		switch {
		case requestControl:
			policyError := evaluation.policyError
			if policyError == passwordPolicyAccountLocked &&
				!database.ppolicy.useLockout {
				policyError = passwordPolicyNoError
			}
			result.controls = append(result.controls, passwordPolicyResponseControl(
				evaluation.expirationSeconds,
				evaluation.graceAuthentications,
				policyError,
			))
		case database.ppolicy.sendNetscapeControls:
			switch {
			case evaluation.policyError != passwordPolicyNoError ||
				evaluation.passwordExpired:
				result.controls = append(
					result.controls,
					netscapePasswordControl(true, 0),
				)
			case evaluation.expirationSeconds > 0:
				result.controls = append(
					result.controls,
					netscapePasswordControl(
						false,
						evaluation.expirationSeconds,
					),
				)
			}
		}
	}
	return result, nil
}

func (server *Server) finishPasswordBindStateWrite(
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
	before directory.Entry,
	entry *directory.Entry,
	syncChange **syncChange,
) error {
	if before.Equal(*entry) {
		return nil
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	if lastModEnabled(runtime, dn) {
		actor := ""
		if database.rootDN != nil {
			actor = database.rootDN.String()
		}
		server.applyModifyOperationalAttributes(
			entry,
			actor,
			runtime.serverID,
		)
	}
	if err := storage.WriterInPartition(
		writer,
		database.partition,
	).Put(*entry, true); err != nil {
		return err
	}
	change, err := server.recordSyncChange(
		writer,
		runtime,
		database,
		&before,
		entry,
	)
	if err != nil {
		return err
	}
	*syncChange = change
	return nil
}

func evaluatePasswordPolicyAccountLock(
	entry directory.Entry,
	policy passwordPolicy,
	database runtimeDatabase,
	now time.Time,
) (locked bool, expiredPermanentLock bool) {
	if value, present := singlePasswordPolicyTime(entry, "pwdStartTime"); present {
		start, valid := parsePasswordPolicyTime(value)
		if !valid || now.Before(start) {
			return true, false
		}
	}
	if value, present := singlePasswordPolicyTime(entry, "pwdEndTime"); present {
		end, valid := parsePasswordPolicyTime(value)
		if !valid || !now.Before(end) {
			return true, false
		}
	}
	if !policy.lockout {
		return false, false
	}
	if value, present := singlePasswordPolicyTime(
		entry,
		"pwdAccountTmpLockoutEnd",
	); present {
		end, valid := parsePasswordPolicyTime(value)
		if !valid || now.Before(end) {
			return true, false
		}
	}
	if policy.maxIdle > 0 && database.lastBind {
		value, present := singlePasswordPolicyTime(entry, "pwdLastSuccess")
		if !present {
			value, present = singlePasswordPolicyTime(entry, "pwdChangedTime")
		}
		if present {
			last, valid := parsePasswordPolicyTime(value)
			if !valid || now.After(last.Add(
				time.Duration(policy.maxIdle)*time.Second,
			)) {
				return true, false
			}
		}
	}
	value, present := singlePasswordPolicyTime(entry, "pwdAccountLockedTime")
	if !present {
		return false, false
	}
	if string(value) == permanentPasswordLockoutValue {
		return true, false
	}
	lockedAt, valid := parsePasswordPolicyTime(value)
	if !valid {
		return true, false
	}
	if now.Before(lockedAt) {
		return false, false
	}
	if policy.lockoutDuration == 0 {
		return true, false
	}
	if now.Before(lockedAt.Add(
		time.Duration(policy.lockoutDuration) * time.Second,
	)) {
		return true, false
	}
	return false, true
}

func singlePasswordPolicyTime(
	entry directory.Entry,
	attribute string,
) ([]byte, bool) {
	values := entry.Values(attribute)
	if len(values) != 1 {
		return nil, len(values) > 0
	}
	return values[0], true
}

func applyPasswordPolicyBindFailure(
	entry *directory.Entry,
	policy passwordPolicy,
	now time.Time,
) {
	if policy.maxRecordedFailure <= 0 {
		return
	}
	activeFailures := 0
	type recordedFailure struct {
		raw  []byte
		time time.Time
	}
	var failures []recordedFailure
	for _, raw := range entry.Values("pwdFailureTime") {
		parsed, valid := parsePasswordPolicyTime(raw)
		if !valid {
			continue
		}
		failures = append(failures, recordedFailure{raw: raw, time: parsed})
		if policy.failureCountInterval == 0 ||
			!now.After(parsed.Add(
				time.Duration(policy.failureCountInterval)*time.Second,
			)) {
			activeFailures++
		}
	}
	failures = append(failures, recordedFailure{
		raw:  []byte(formatPasswordPolicyFailureTime(now)),
		time: now,
	})
	if len(failures) > policy.maxRecordedFailure {
		failures = failures[len(failures)-policy.maxRecordedFailure:]
	}
	values := make([][]byte, len(failures))
	for index := range failures {
		values[index] = failures[index].raw
	}
	entry.ReplaceValues("pwdFailureTime", values)

	if policy.maxFailure > 0 &&
		activeFailures >= policy.maxFailure-1 {
		entry.ReplaceValues(
			"pwdAccountLockedTime",
			[][]byte{[]byte(formatPasswordPolicyTime(now))},
		)
		return
	}
	if policy.minDelay <= 0 {
		return
	}
	delay := passwordPolicyFailureDelay(policy, activeFailures)
	entry.ReplaceValues(
		"pwdAccountTmpLockoutEnd",
		[][]byte{[]byte(formatPasswordPolicyTime(
			now.Add(time.Duration(delay) * time.Second),
		))},
	)
}

func passwordPolicyFailureDelay(
	policy passwordPolicy,
	activeFailures int,
) int {
	if activeFailures >= strconv.IntSize-2 {
		return policy.maxDelay
	}
	delay := int64(policy.minDelay) << activeFailures
	maximum := int64(policy.maxDelay)
	if delay < 0 || delay > math.MaxInt {
		delay = maximum
	}
	if maximum > 0 && delay > maximum {
		delay = maximum
	}
	return int(delay)
}

func passwordPolicyWritesLocally(database runtimeDatabase) bool {
	return database.ppolicy != nil &&
		!database.ppolicy.disableWrite &&
		!(database.shadow && database.ppolicy.forwardUpdates)
}

func evaluateSuccessfulPasswordPolicyBind(
	entry *directory.Entry,
	policy passwordPolicy,
	now time.Time,
	evaluation *passwordBindEvaluation,
	writeState bool,
) {
	if writeState {
		entry.ReplaceValues("pwdFailureTime", nil)
	}
	resetRequired := policy.mustChange &&
		firstPasswordPolicyBoolean(*entry, "pwdReset")
	if resetRequired {
		evaluation.policyError = passwordPolicyChangeAfterReset
		evaluation.restricted = true
	}

	changedValue, changedPresent := singlePasswordPolicyTime(
		*entry,
		"pwdChangedTime",
	)
	changed, changedValid := parsePasswordPolicyTime(changedValue)
	if !changedPresent || !changedValid || policy.maxAge == 0 {
		return
	}
	age := int(now.Sub(changed) / time.Second)
	if !resetRequired && age > policy.maxAge {
		evaluation.passwordExpired = true
		graceRemaining := policy.graceAuthentication
		if policy.graceExpiry > 0 &&
			age > policy.maxAge+policy.graceExpiry {
			graceRemaining = 0
		} else {
			graceRemaining -= len(entry.Values("pwdGraceUseTime"))
		}
		graceRemaining--
		evaluation.graceAuthentications = graceRemaining
		if graceRemaining < 0 {
			evaluation.authenticated = false
			evaluation.policyError = passwordPolicyPasswordExpired
			return
		}
		if writeState {
			_ = entry.AddValues(
				"pwdGraceUseTime",
				[][]byte{[]byte(formatPasswordPolicyFailureTime(now))},
			)
		}
		return
	}
	if policy.expireWarning > 0 &&
		policy.maxAge-age < policy.expireWarning {
		evaluation.expirationSeconds = max(policy.maxAge-age, 0)
	}
}

func firstPasswordPolicyBoolean(
	entry directory.Entry,
	attribute string,
) bool {
	values := entry.Values(attribute)
	return len(values) > 0 && strings.EqualFold(string(values[0]), "TRUE")
}

func applyPasswordLastSuccess(
	entry *directory.Entry,
	now time.Time,
	precision int,
) {
	if value, present := singlePasswordPolicyTime(
		*entry,
		"pwdLastSuccess",
	); present {
		previous, valid := parsePasswordPolicyTime(value)
		if valid && !now.After(previous.Add(
			time.Duration(precision)*time.Second,
		)) {
			return
		}
	}
	entry.ReplaceValues(
		"pwdLastSuccess",
		[][]byte{[]byte(formatPasswordPolicyTime(now))},
	)
}

func (server *Server) passwordPolicyModificationProcessor(
	runtime *runtimeState,
	boundDN string,
	database runtimeDatabase,
	options passwordPolicyModificationOptions,
) entryModificationProcessor {
	if database.ppolicy == nil || database.ppolicy.disableWrite {
		return nil
	}
	return func(
		reader storage.Reader,
		entry directory.Entry,
		changes []ldapwire.Modification,
	) ([]ldapwire.Modification, entryModificationMutation, error) {
		policy, hasPolicy := loadPasswordPolicy(
			runtime,
			reader,
			database,
			entry,
		)
		processed := clonePasswordPolicyModifications(changes)
		analysis, err := analyzePasswordPolicyModifications(
			runtime,
			policy,
			processed,
		)
		if err != nil {
			return nil, nil, err
		}
		if !analysis.passwordModified {
			mutation := passwordPolicyUnlockMutation(entry, analysis)
			return processed, mutation, nil
		}

		passwordAdministrator := server.allowed(
			runtime,
			reader,
			boundDN,
			entry,
			policy.attribute,
			nil,
			acl.Manage,
		)
		maintainState := true
		if hasPolicy && !passwordAdministrator {
			self := passwordPolicySameDN(boundDN, entry.DN)
			if !policy.allowUserChange && self {
				return nil, nil, passwordPolicyOperationFailed(
					ldapwire.ResultInsufficientAccessRights,
					"User alteration of password is not allowed",
					options.requestControl,
					passwordPolicyModificationNotAllowed,
				)
			}
			if analysis.newPasswordIndex < 0 {
				maintainState = false
			} else {
				if policy.safeModify &&
					!passwordPolicySuppliesOldPassword(
						analysis,
						options,
					) {
					return nil, nil, passwordPolicyOperationFailed(
						ldapwire.ResultInsufficientAccessRights,
						"Must supply old password to be changed as well as new one",
						options.requestControl,
						passwordPolicyMustSupplyOldPassword,
					)
				}
				if !firstPasswordPolicyBoolean(entry, "pwdReset") &&
					policy.minAge > 0 &&
					isPasswordPolicyTooYoung(entry, policy, time.Now()) {
					return nil, nil, passwordPolicyOperationFailed(
						ldapwire.ResultConstraintViolation,
						"Password is too young to change",
						options.requestControl,
						passwordPolicyTooYoung,
					)
				}
			}
		}

		if analysis.newPasswordIndex >= 0 {
			oldPassword := passwordPolicyOldPassword(
				analysis,
				options,
			)
			if len(oldPassword) > 0 {
				matched := matchingStoredPassword(
					runtime.schema.AttributeValues(
						entry,
						policy.attribute,
					),
					oldPassword,
				)
				if matched == nil {
					return nil, nil, passwordPolicyOperationFailed(
						ldapwire.ResultUnwillingToPerform,
						"Must supply correct old password to change to new one",
						options.requestControl,
						passwordPolicyMustSupplyOldPassword,
					)
				}
				if analysis.oldPasswordIndex >= 0 {
					processed[analysis.oldPasswordIndex].
						Attribute.Values = [][]byte{bytes.Clone(matched)}
				}
			}

			candidate := processed[analysis.newPasswordIndex].
				Attribute.Values[0]
			if options.passwordModify {
				candidate = options.newPassword
			}
			if hasPolicy && !passwordAdministrator {
				if policyError := checkPasswordPolicyQuality(
					candidate,
					policy,
				); policyError != passwordPolicyNoError {
					diagnostic := "Password fails quality checking policy"
					switch policyError {
					case passwordPolicyTooShort:
						diagnostic = "Password is too short"
					case passwordPolicyTooLong:
						diagnostic = "Password is too long"
					}
					return nil, nil, passwordPolicyOperationFailed(
						ldapwire.ResultConstraintViolation,
						diagnostic,
						options.requestControl,
						policyError,
					)
				}
				if policy.inHistory > 0 &&
					passwordPolicyMatchesCurrentOrHistory(
						entry,
						runtime,
						policy,
						candidate,
					) {
					return nil, nil, passwordPolicyOperationFailed(
						ldapwire.ResultConstraintViolation,
						"Password is in history of old passwords",
						options.requestControl,
						passwordPolicyInHistory,
					)
				}
			}

			if database.ppolicy.hashCleartext &&
				!options.passwordModify &&
				!passwordPolicyStoredScheme(candidate) {
				hashed, hashErr := auth.HashPassword(
					candidate,
					runtime.passwordHashSchemes[0],
					nil,
				)
				if hashErr != nil {
					return nil, nil, hashErr
				}
				processed[analysis.newPasswordIndex].
					Attribute.Values = [][]byte{hashed}
			}
		}

		if !maintainState {
			return processed, nil, nil
		}
		mutation := buildPasswordPolicyStateMutation(
			entry,
			policy,
			passwordAdministrator,
			analysis,
			time.Now(),
		)
		return processed, mutation, nil
	}
}

func (server *Server) applyPasswordPolicyAdd(
	runtime *runtimeState,
	policyReader storage.Reader,
	aclReader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	entry *directory.Entry,
	requestControl bool,
) error {
	if database.ppolicy == nil {
		return nil
	}
	policy, hasPolicy := loadPasswordPolicy(
		runtime,
		policyReader,
		database,
		*entry,
	)
	var (
		passwordAttributeIndex = -1
		passwordValues         [][]byte
	)
	for index := range entry.Attributes {
		if !passwordPolicyAttributeMatches(
			runtime,
			entry.Attributes[index].Description,
			policy.attribute,
		) {
			continue
		}
		if passwordAttributeIndex < 0 {
			passwordAttributeIndex = index
		}
		passwordValues = append(
			passwordValues,
			entry.Attributes[index].Values...,
		)
	}
	if len(passwordValues) == 0 {
		return nil
	}
	if len(passwordValues) != 1 {
		return operationFailed(
			ldapwire.ResultConstraintViolation,
			"Password policy only allows one password value",
		)
	}

	passwordAdministrator := server.allowed(
		runtime,
		aclReader,
		boundDN,
		*entry,
		policy.attribute,
		nil,
		acl.Manage,
	)
	if hasPolicy && !passwordAdministrator {
		if policyError := checkPasswordPolicyQuality(
			passwordValues[0],
			policy,
		); policyError != passwordPolicyNoError {
			diagnostic := "Password fails quality checking policy"
			switch policyError {
			case passwordPolicyTooShort:
				diagnostic = "Password is too short"
			case passwordPolicyTooLong:
				diagnostic = "Password is too long"
			}
			return passwordPolicyOperationFailed(
				ldapwire.ResultConstraintViolation,
				diagnostic,
				requestControl,
				policyError,
			)
		}
	}
	if database.ppolicy.hashCleartext &&
		!passwordPolicyStoredScheme(passwordValues[0]) {
		hashed, err := auth.HashPassword(
			passwordValues[0],
			runtime.passwordHashSchemes[0],
			nil,
		)
		if err != nil {
			return err
		}
		entry.Attributes[passwordAttributeIndex].Values = [][]byte{hashed}
	}
	if (policy.maxAge > 0 || policy.minAge > 0) &&
		!runtime.schema.HasAttributeDescription(*entry, "pwdChangedTime") {
		entry.ReplaceValues(
			"pwdChangedTime",
			[][]byte{[]byte(formatPasswordPolicyTime(time.Now()))},
		)
	}
	return nil
}

type passwordPolicyModificationAnalysis struct {
	passwordModified      bool
	lastPasswordOperation ldapwire.ModificationOperation
	newPasswordIndex      int
	oldPasswordIndex      int
	suppliedOldPassword   []byte
	suppliesDeleteThenAdd bool
	explicitReset         bool
	explicitChangedTime   bool
	explicitHistory       bool
	explicitDeleteGrace   bool
	explicitDeleteLock    bool
	explicitDeleteFailure bool
	explicitDeleteSuccess bool
}

func analyzePasswordPolicyModifications(
	runtime *runtimeState,
	policy passwordPolicy,
	changes []ldapwire.Modification,
) (passwordPolicyModificationAnalysis, error) {
	analysis := passwordPolicyModificationAnalysis{
		newPasswordIndex: -1,
		oldPasswordIndex: -1,
	}
	deleteSeen := false
	for index, change := range changes {
		description := change.Attribute.Description
		if passwordPolicyAttributeMatches(
			runtime,
			description,
			policy.attribute,
		) {
			analysis.passwordModified = true
			analysis.lastPasswordOperation = change.Operation
			if change.Operation == ldapwire.ModificationDelete &&
				len(change.Attribute.Values) > 0 &&
				!deleteSeen {
				deleteSeen = true
				analysis.oldPasswordIndex = index
				analysis.suppliedOldPassword = bytes.Clone(
					change.Attribute.Values[0],
				)
			}
			if (change.Operation == ldapwire.ModificationAdd ||
				change.Operation == ldapwire.ModificationReplace) &&
				len(change.Attribute.Values) > 0 {
				if analysis.newPasswordIndex >= 0 ||
					len(change.Attribute.Values) != 1 {
					return passwordPolicyModificationAnalysis{},
						operationFailed(
							ldapwire.ResultConstraintViolation,
							"Password policy only allows one password value",
						)
				}
				analysis.newPasswordIndex = index
				if deleteSeen {
					analysis.suppliesDeleteThenAdd = true
				}
			}
			continue
		}
		switch {
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdReset",
		):
			if change.Operation == ldapwire.ModificationAdd ||
				change.Operation == ldapwire.ModificationReplace {
				analysis.explicitReset = true
			}
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdChangedTime",
		):
			analysis.explicitChangedTime = true
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdHistory",
		):
			analysis.explicitHistory = true
		}
		if change.Operation != ldapwire.ModificationDelete {
			continue
		}
		switch {
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdGraceUseTime",
		):
			analysis.explicitDeleteGrace = true
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdAccountLockedTime",
		):
			analysis.explicitDeleteLock = true
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdFailureTime",
		):
			analysis.explicitDeleteFailure = true
		case passwordPolicyAttributeMatches(
			runtime,
			description,
			"pwdLastSuccess",
		):
			analysis.explicitDeleteSuccess = true
		}
	}
	return analysis, nil
}

func clonePasswordPolicyModifications(
	changes []ldapwire.Modification,
) []ldapwire.Modification {
	cloned := make([]ldapwire.Modification, len(changes))
	for index, change := range changes {
		cloned[index] = ldapwire.Modification{
			Operation: change.Operation,
			Attribute: directory.Attribute{
				Description: change.Attribute.Description,
				Values:      make([][]byte, len(change.Attribute.Values)),
			},
		}
		for valueIndex, value := range change.Attribute.Values {
			cloned[index].Attribute.Values[valueIndex] = bytes.Clone(value)
		}
	}
	return cloned
}

func passwordPolicyAttributeMatches(
	runtime *runtimeState,
	left string,
	right string,
) bool {
	leftType, leftOK := runtime.schema.AttributeType(left)
	rightType, rightOK := runtime.schema.AttributeType(right)
	if leftOK && rightOK {
		return strings.EqualFold(leftType.OID, rightType.OID)
	}
	return strings.EqualFold(
		strings.TrimSpace(left),
		strings.TrimSpace(right),
	)
}

func passwordPolicySameDN(left, right string) bool {
	leftDN, leftErr := directory.ParseDN(left)
	rightDN, rightErr := directory.ParseDN(right)
	return leftErr == nil && rightErr == nil && leftDN.Equal(rightDN)
}

func passwordPolicySuppliesOldPassword(
	analysis passwordPolicyModificationAnalysis,
	options passwordPolicyModificationOptions,
) bool {
	return analysis.suppliesDeleteThenAdd ||
		(options.passwordModify && options.hasOldPassword)
}

func passwordPolicyOldPassword(
	analysis passwordPolicyModificationAnalysis,
	options passwordPolicyModificationOptions,
) []byte {
	if options.passwordModify && options.hasOldPassword {
		return options.oldPassword
	}
	if analysis.oldPasswordIndex < 0 {
		return nil
	}
	return analysis.suppliedOldPassword
}

func matchingStoredPassword(storedValues [][]byte, supplied []byte) []byte {
	for _, stored := range storedValues {
		if auth.VerifyPassword(stored, supplied) {
			return stored
		}
	}
	return nil
}

func isPasswordPolicyTooYoung(
	entry directory.Entry,
	policy passwordPolicy,
	now time.Time,
) bool {
	raw, present := singlePasswordPolicyTime(entry, "pwdChangedTime")
	if !present {
		return false
	}
	changed, valid := parsePasswordPolicyTime(raw)
	return valid &&
		int(now.Sub(changed)/time.Second) < policy.minAge
}

func checkPasswordPolicyQuality(
	password []byte,
	policy passwordPolicy,
) passwordPolicyError {
	if policy.checkQuality <= 0 {
		return passwordPolicyNoError
	}
	if len(password) == 0 || policy.minLength > len(password) {
		return passwordPolicyTooShort
	}
	if policy.maxLength > 0 && len(password) > policy.maxLength {
		return passwordPolicyTooLong
	}
	if passwordPolicyStoredScheme(password) &&
		!passwordPolicyCleartextScheme(password) {
		if policy.checkQuality == 2 {
			return passwordPolicyInsufficientQuality
		}
		return passwordPolicyNoError
	}
	if policy.useCheckModule && policy.checkModuleConfigured {
		// OpenLDAP fails closed when a policy requests a checker but no
		// check_password() implementation can be called.
		return passwordPolicyInsufficientQuality
	}
	return passwordPolicyNoError
}

func passwordPolicyStoredScheme(value []byte) bool {
	if len(value) < 3 || value[0] != '{' {
		return false
	}
	end := bytes.IndexByte(value, '}')
	if end <= 1 {
		return false
	}
	_, err := auth.NormalizePasswordHashScheme(string(value[:end+1]))
	return err == nil
}

func passwordPolicyCleartextScheme(value []byte) bool {
	return len(value) >= len("{CLEARTEXT}") &&
		strings.EqualFold(
			string(value[:len("{CLEARTEXT}")]),
			"{CLEARTEXT}",
		)
}

func passwordPolicyMatchesCurrentOrHistory(
	entry directory.Entry,
	runtime *runtimeState,
	policy passwordPolicy,
	candidate []byte,
) bool {
	for _, stored := range runtime.schema.AttributeValues(
		entry,
		policy.attribute,
	) {
		if auth.VerifyPassword(stored, candidate) {
			return true
		}
	}
	history := parsePasswordHistory(entry.Values("pwdHistory"))
	if len(history) > policy.inHistory {
		history = history[len(history)-policy.inHistory:]
	}
	for _, item := range history {
		if auth.VerifyPassword(item.password, candidate) {
			return true
		}
	}
	return false
}

type passwordHistoryItem struct {
	time     time.Time
	raw      []byte
	password []byte
}

func parsePasswordHistory(values [][]byte) []passwordHistoryItem {
	var history []passwordHistoryItem
	for _, raw := range values {
		item, valid := parsePasswordHistoryValue(raw)
		if valid {
			history = append(history, item)
		}
	}
	sort.SliceStable(history, func(left, right int) bool {
		return history[left].time.Before(history[right].time)
	})
	return history
}

func parsePasswordHistoryValue(raw []byte) (passwordHistoryItem, bool) {
	remaining := raw
	fields := make([][]byte, 0, 3)
	for range 3 {
		index := bytes.IndexByte(remaining, '#')
		if index < 0 {
			return passwordHistoryItem{}, false
		}
		fields = append(fields, remaining[:index])
		remaining = remaining[index+1:]
	}
	recordedAt, valid := parsePasswordPolicyTime(fields[0])
	if !valid {
		return passwordHistoryItem{}, false
	}
	length, err := strconv.Atoi(string(fields[2]))
	if err != nil || length < 0 || len(remaining) != length {
		return passwordHistoryItem{}, false
	}
	return passwordHistoryItem{
		time:     recordedAt,
		raw:      bytes.Clone(raw),
		password: bytes.Clone(remaining),
	}, true
}

func buildPasswordHistoryValue(
	recordedAt time.Time,
	password []byte,
) []byte {
	prefix := fmt.Sprintf(
		"%s#%s#%d#",
		formatPasswordPolicyTime(recordedAt),
		passwordHistorySyntaxOID,
		len(password),
	)
	value := make([]byte, 0, len(prefix)+len(password))
	value = append(value, prefix...)
	value = append(value, password...)
	return value
}

func buildPasswordPolicyStateMutation(
	entry directory.Entry,
	policy passwordPolicy,
	passwordAdministrator bool,
	analysis passwordPolicyModificationAnalysis,
	now time.Time,
) entryModificationMutation {
	history := parsePasswordHistory(entry.Values("pwdHistory"))
	currentPasswords := entry.Values(policy.attribute)
	return func(updated *directory.Entry) error {
		if !analysis.explicitChangedTime {
			if analysis.lastPasswordOperation ==
				ldapwire.ModificationDelete {
				updated.ReplaceValues("pwdChangedTime", nil)
			} else {
				updated.ReplaceValues(
					"pwdChangedTime",
					[][]byte{[]byte(formatPasswordPolicyTime(now))},
				)
			}
		}
		if !analysis.explicitDeleteGrace {
			updated.ReplaceValues("pwdGraceUseTime", nil)
		}
		if !analysis.explicitDeleteLock {
			updated.ReplaceValues("pwdAccountLockedTime", nil)
		}
		if !analysis.explicitDeleteFailure {
			updated.ReplaceValues("pwdFailureTime", nil)
		}
		if !analysis.explicitDeleteSuccess {
			updated.ReplaceValues("pwdLastSuccess", nil)
		}
		if !analysis.explicitReset {
			if policy.mustChange && passwordAdministrator {
				updated.ReplaceValues(
					"pwdReset",
					[][]byte{[]byte("TRUE")},
				)
			} else {
				updated.ReplaceValues("pwdReset", nil)
			}
		}
		if analysis.explicitHistory {
			return nil
		}
		if policy.inHistory <= 0 {
			updated.ReplaceValues("pwdHistory", nil)
			return nil
		}
		if len(currentPasswords) > 0 {
			history = append(history, passwordHistoryItem{
				time: now,
				raw: buildPasswordHistoryValue(
					now,
					currentPasswords[0],
				),
				password: bytes.Clone(currentPasswords[0]),
			})
		}
		if len(history) > policy.inHistory {
			history = history[len(history)-policy.inHistory:]
		}
		values := make([][]byte, len(history))
		for index := range history {
			values[index] = bytes.Clone(history[index].raw)
		}
		updated.ReplaceValues("pwdHistory", values)
		return nil
	}
}

func passwordPolicyUnlockMutation(
	entry directory.Entry,
	analysis passwordPolicyModificationAnalysis,
) entryModificationMutation {
	if !analysis.explicitDeleteLock ||
		analysis.explicitDeleteFailure ||
		!entry.HasAttribute("pwdFailureTime") {
		return nil
	}
	return func(updated *directory.Entry) error {
		updated.ReplaceValues("pwdFailureTime", nil)
		return nil
	}
}

func refreshPasswordPolicyRestriction(state *connectionState) {
	if state.passwordPolicyRestrictedDN == "" {
		return
	}
	if !passwordPolicySameDN(
		state.boundDN,
		state.passwordPolicyRestrictedDN,
	) {
		state.passwordPolicyRestrictedDN = ""
	}
}

func passwordPolicyRestrictionResult() ldapwire.Result {
	return ldapwire.ResultError(
		ldapwire.ResultInsufficientAccessRights,
		passwordPolicyRestrictionText,
	)
}

func (server *Server) writePasswordPolicyRestriction(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	requestControl bool,
) error {
	var controls []ldapwire.Control
	if requestControl {
		controls = []ldapwire.Control{passwordPolicyResponseControl(
			-1,
			-1,
			passwordPolicyChangeAfterReset,
		)}
	}
	return server.writeOperationResultWithControls(
		connection,
		messageID,
		responseTag,
		passwordPolicyRestrictionResult(),
		controls,
	)
}

func passwordPolicyModificationAllowedWhileRestricted(
	runtime *runtimeState,
	changes []ldapwire.Modification,
) bool {
	for _, change := range changes {
		if passwordPolicyAttributeMatches(
			runtime,
			change.Attribute.Description,
			"userPassword",
		) || runtime.schema.IsOperational(
			change.Attribute.Description,
		) {
			continue
		}
		return false
	}
	return true
}

func passwordPolicyModifiesPassword(
	runtime *runtimeState,
	changes []ldapwire.Modification,
) bool {
	for _, change := range changes {
		if passwordPolicyAttributeMatches(
			runtime,
			change.Attribute.Description,
			"userPassword",
		) {
			return true
		}
	}
	return false
}

func (server *Server) passwordPolicySearchEntryControls(
	ctx context.Context,
	state *connectionState,
	selected directory.Entry,
) []ldapwire.Control {
	if !state.accountUsabilityRequested {
		return nil
	}
	dn, err := directory.ParseDN(selected.DN)
	if err != nil {
		return nil
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil || database.ppolicy == nil {
		return nil
	}

	var control *ldapwire.Control
	_ = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
		entry, err := tx.Get(dn)
		if err != nil {
			return nil
		}
		policy, hasPolicy := loadPasswordPolicy(
			state.runtime,
			reader,
			*database,
			entry,
		)
		if !hasPolicy ||
			!state.runtime.schema.HasAttributeDescription(
				entry,
				policy.attribute,
			) ||
			!server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				policy.attribute,
				nil,
				acl.Compare,
			) {
			return nil
		}
		value := encodePasswordPolicyAccountUsability(
			entry,
			policy,
			*database,
			time.Now(),
		)
		control = &ldapwire.Control{
			OID:      accountUsabilityControlOID,
			Value:    value,
			HasValue: true,
		}
		return nil
	})
	if control == nil {
		return nil
	}
	return []ldapwire.Control{*control}
}

func encodePasswordPolicyAccountUsability(
	entry directory.Entry,
	policy passwordPolicy,
	database runtimeDatabase,
	now time.Time,
) []byte {
	secondsUntilExpiry := -1
	expired := false
	grace := -1
	if raw, present := singlePasswordPolicyTime(
		entry,
		"pwdChangedTime",
	); present && policy.maxAge > 0 {
		if changed, valid := parsePasswordPolicyTime(raw); valid {
			secondsUntilExpiry = int(
				changed.Add(
					time.Duration(policy.maxAge)*time.Second,
				).Sub(now) / time.Second,
			)
			expired = secondsUntilExpiry <= 0
			if expired && policy.graceAuthentication > 0 &&
				(policy.graceExpiry == 0 ||
					secondsUntilExpiry+policy.graceExpiry > 0) {
				grace = policy.graceAuthentication
				// OpenLDAP's account-usability callback subtracts one once
				// pwdGraceUseTime exists, independent of its value count.
				if len(entry.Values("pwdGraceUseTime")) > 0 {
					grace--
				}
			}
		}
	}
	if !expired && policy.maxIdle > 0 {
		if raw, present := singlePasswordPolicyTime(
			entry,
			"pwdLastSuccess",
		); present {
			if last, valid := parsePasswordPolicyTime(raw); valid {
				remaining := int(
					last.Add(
						time.Duration(policy.maxIdle)*
							time.Second,
					).Sub(now) / time.Second,
				)
				if remaining <= 0 {
					expired = true
				} else if secondsUntilExpiry < 0 ||
					remaining < secondsUntilExpiry {
					secondsUntilExpiry = remaining
				}
			}
		}
	}

	locked, _ := evaluatePasswordPolicyAccountLock(
		entry,
		policy,
		database,
		now,
	)
	if !expired && !locked {
		return ldapwire.EncodeAccountUsabilityAvailable(
			int64(secondsUntilExpiry),
		)
	}
	info := ldapwire.AccountUsabilityMoreInfo{
		RemainingGrace:      int64(grace),
		SecondsBeforeUnlock: -1,
	}
	if locked {
		secondsBeforeUnlock := int64(
			passwordPolicySecondsBeforeUnlock(
				entry,
				policy,
				now,
			),
		)
		if secondsBeforeUnlock > 0 {
			info.Inactive = true
			info.SecondsBeforeUnlock = secondsBeforeUnlock
		}
	}
	if policy.mustChange &&
		firstPasswordPolicyBoolean(entry, "pwdReset") {
		info.Reset = true
	}
	return ldapwire.EncodeAccountUsabilityUnavailable(info)
}

func passwordPolicySecondsBeforeUnlock(
	entry directory.Entry,
	policy passwordPolicy,
	now time.Time,
) int {
	unlockAt := time.Time{}
	permanent := false
	if raw, present := singlePasswordPolicyTime(
		entry,
		"pwdAccountLockedTime",
	); present {
		lockedAt, valid := parsePasswordPolicyTime(raw)
		switch {
		case !valid:
			permanent = true
		case now.Before(lockedAt):
		case string(raw) == permanentPasswordLockoutValue ||
			policy.lockoutDuration == 0:
			permanent = true
		default:
			candidate := lockedAt.Add(
				time.Duration(policy.lockoutDuration) *
					time.Second,
			)
			if candidate.After(now) {
				unlockAt = candidate
			}
		}
	}
	if !permanent {
		if raw, present := singlePasswordPolicyTime(
			entry,
			"pwdAccountTmpLockoutEnd",
		); present {
			if candidate, valid := parsePasswordPolicyTime(raw); valid && candidate.After(unlockAt) {
				unlockAt = candidate
			}
		}
	}
	if permanent || !unlockAt.After(now) {
		return -1
	}
	return max(int(unlockAt.Sub(now)/time.Second), 0)
}
