package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type securityStrengthRequirements struct {
	overall         uint32
	transport       uint32
	tls             uint32
	sasl            uint32
	updateOverall   uint32
	updateTransport uint32
	updateTLS       uint32
	updateSASL      uint32
	simpleBind      uint32
	configured      securityFactorMask
}

type securityFactorMask uint16

const (
	securityFactorOverall securityFactorMask = 1 << iota
	securityFactorTransport
	securityFactorTLS
	securityFactorSASL
	securityFactorUpdateOverall
	securityFactorUpdateTransport
	securityFactorUpdateTLS
	securityFactorUpdateSASL
	securityFactorSimpleBind
)

type operationRequirements uint8

const (
	requireBind operationRequirements = 1 << iota
	requireLDAPv3
	requireAuthentication
	requireSASL
	requireStrongAuthentication
)

type operationPolicyKind uint8

const (
	policyRead operationPolicyKind = iota
	policyUpdate
	policySimpleBind
	policySASLBind
	policyAnonymousBind
)

type securityConfigurationError struct {
	message string
}

func (failure *securityConfigurationError) Error() string {
	return failure.message
}

func securityConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *securityConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(
		ldapwire.ResultOther,
		"invalid cn=config: "+err.Error(),
	), true
}

func loadFrontendSecurityConfiguration(
	reader storage.Reader,
	databases []runtimeDatabase,
) (securityStrengthRequirements, operationRequirements, error) {
	var security securityStrengthRequirements
	var requires operationRequirements
	entry, err := reader.Get(configurationSuffix)
	switch {
	case err == nil:
		security, err = parseSecurityStrengthRequirements(entry.Values("olcSecurity"))
		if err != nil {
			return securityStrengthRequirements{}, 0, fmt.Errorf(
				"%s olcSecurity: %w",
				entry.DN,
				err,
			)
		}
		requires, err = parseOperationRequirements(entry.Values("olcRequires"))
		if err != nil {
			return securityStrengthRequirements{}, 0, fmt.Errorf(
				"%s olcRequires: %w",
				entry.DN,
				err,
			)
		}
	case errors.Is(err, storage.ErrEntryNotFound):
	case err != nil:
		return securityStrengthRequirements{}, 0, fmt.Errorf(
			"load global security configuration: %w",
			err,
		)
	}

	for index := range databases {
		database := &databases[index]
		if databaseType(database.name) != "frontend" {
			continue
		}
		security = applyConfiguredSecurityStrengthRequirements(
			security,
			database.security,
		)
		requires, err = applyOperationRequirementValues(
			requires,
			database.requiresValues,
			false,
		)
		if err != nil {
			return securityStrengthRequirements{}, 0, fmt.Errorf(
				"frontend olcRequires: %w",
				err,
			)
		}
		break
	}
	for index := range databases {
		database := &databases[index]
		if databaseType(database.name) == "frontend" {
			database.security = security
			database.requires = requires
			continue
		}
		database.security = applyConfiguredSecurityStrengthRequirements(
			security,
			database.security,
		)
		database.requires, err = applyOperationRequirementValues(
			requires,
			database.requiresValues,
			true,
		)
		if err != nil {
			return securityStrengthRequirements{}, 0, fmt.Errorf(
				"%s olcRequires: %w",
				database.name,
				err,
			)
		}
	}
	return security, requires, nil
}

func parseSecurityStrengthRequirements(
	values [][]byte,
) (securityStrengthRequirements, error) {
	var requirements securityStrengthRequirements
	for _, raw := range values {
		value := string(raw)
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return securityStrengthRequirements{}, errors.New("value contains no factors")
		}
		for _, field := range fields {
			name, rawStrength, found := strings.Cut(field, "=")
			if !found {
				return securityStrengthRequirements{}, &securityConfigurationError{
					message: fmt.Sprintf("unknown factor %q", field),
				}
			}
			target := securityStrengthTarget(&requirements, name)
			if target == nil {
				return securityStrengthRequirements{}, &securityConfigurationError{
					message: fmt.Sprintf("unknown factor %q", name),
				}
			}
			strength, err := parseSecurityStrength(rawStrength)
			if err != nil {
				return securityStrengthRequirements{}, &securityConfigurationError{
					message: fmt.Sprintf("unable to parse factor %q", field),
				}
			}
			*target = strength
			requirements.configured |= securityFactorForName(name)
		}
	}
	return requirements, nil
}

func securityFactorForName(name string) securityFactorMask {
	switch strings.ToLower(name) {
	case "ssf":
		return securityFactorOverall
	case "transport":
		return securityFactorTransport
	case "tls":
		return securityFactorTLS
	case "sasl":
		return securityFactorSASL
	case "update_ssf":
		return securityFactorUpdateOverall
	case "update_transport":
		return securityFactorUpdateTransport
	case "update_tls":
		return securityFactorUpdateTLS
	case "update_sasl":
		return securityFactorUpdateSASL
	case "simple_bind":
		return securityFactorSimpleBind
	default:
		return 0
	}
}

func securityStrengthTarget(
	requirements *securityStrengthRequirements,
	name string,
) *uint32 {
	switch strings.ToLower(name) {
	case "ssf":
		return &requirements.overall
	case "transport":
		return &requirements.transport
	case "tls":
		return &requirements.tls
	case "sasl":
		return &requirements.sasl
	case "update_ssf":
		return &requirements.updateOverall
	case "update_transport":
		return &requirements.updateTransport
	case "update_tls":
		return &requirements.updateTLS
	case "update_sasl":
		return &requirements.updateSASL
	case "simple_bind":
		return &requirements.simpleBind
	default:
		return nil
	}
}

func parseSecurityStrength(value string) (uint32, error) {
	if strings.HasPrefix(value, "+") {
		value = value[1:]
	}
	if value == "" {
		return 0, errors.New("empty security strength")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("security strength is not decimal")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}

func parseOperationRequirements(values [][]byte) (operationRequirements, error) {
	return applyOperationRequirementValues(0, values, false)
}

func applyOperationRequirementValues(
	initial operationRequirements,
	values [][]byte,
	resetForEachValue bool,
) (operationRequirements, error) {
	requirements := initial
	for _, raw := range values {
		if resetForEachValue {
			requirements = initial
		}
		value := string(raw)
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return 0, errors.New("value contains no requirements")
		}
		for index, field := range fields {
			if strings.EqualFold(field, "none") {
				if index != 0 {
					return 0, &securityConfigurationError{
						message: "none must be listed first",
					}
				}
				requirements = 0
				continue
			}
			requirement, ok := operationRequirementName(field)
			if !ok {
				return 0, &securityConfigurationError{
					message: fmt.Sprintf("unknown feature %q", field),
				}
			}
			requirements |= requirement
		}
	}
	return requirements, nil
}

func operationRequirementName(value string) (operationRequirements, bool) {
	switch strings.ToLower(value) {
	case "bind":
		return requireBind, true
	case "ldapv3":
		return requireLDAPv3, true
	case "authc":
		return requireAuthentication, true
	case "sasl":
		return requireSASL, true
	case "strong":
		return requireStrongAuthentication, true
	default:
		return 0, false
	}
}

func overrideSecurityStrengthRequirements(
	base securityStrengthRequirements,
	override securityStrengthRequirements,
) securityStrengthRequirements {
	baseFields := []*uint32{
		&base.overall,
		&base.transport,
		&base.tls,
		&base.sasl,
		&base.updateOverall,
		&base.updateTransport,
		&base.updateTLS,
		&base.updateSASL,
		&base.simpleBind,
	}
	overrideFields := []uint32{
		override.overall,
		override.transport,
		override.tls,
		override.sasl,
		override.updateOverall,
		override.updateTransport,
		override.updateTLS,
		override.updateSASL,
		override.simpleBind,
	}
	for index, value := range overrideFields {
		if value != 0 {
			*baseFields[index] = value
		}
	}
	return base
}

func applyConfiguredSecurityStrengthRequirements(
	base securityStrengthRequirements,
	configured securityStrengthRequirements,
) securityStrengthRequirements {
	baseFields := []*uint32{
		&base.overall,
		&base.transport,
		&base.tls,
		&base.sasl,
		&base.updateOverall,
		&base.updateTransport,
		&base.updateTLS,
		&base.updateSASL,
		&base.simpleBind,
	}
	configuredFields := []uint32{
		configured.overall,
		configured.transport,
		configured.tls,
		configured.sasl,
		configured.updateOverall,
		configured.updateTransport,
		configured.updateTLS,
		configured.updateSASL,
		configured.simpleBind,
	}
	factors := []securityFactorMask{
		securityFactorOverall,
		securityFactorTransport,
		securityFactorTLS,
		securityFactorSASL,
		securityFactorUpdateOverall,
		securityFactorUpdateTransport,
		securityFactorUpdateTLS,
		securityFactorUpdateSASL,
		securityFactorSimpleBind,
	}
	for index, factor := range factors {
		if configured.configured&factor != 0 {
			*baseFields[index] = configuredFields[index]
		}
	}
	base.configured |= configured.configured
	return base
}

func effectiveSecurityPolicy(
	runtime *runtimeState,
	database *runtimeDatabase,
) (securityStrengthRequirements, operationRequirements) {
	if runtime == nil {
		return securityStrengthRequirements{}, 0
	}
	security := runtime.security
	requires := runtime.requires
	if database != nil && databaseType(database.name) != "frontend" {
		security = overrideSecurityStrengthRequirements(security, database.security)
		requires |= database.requires
	}
	return security, requires
}

func operationSecurityResult(
	state *connectionState,
	database *runtimeDatabase,
	kind operationPolicyKind,
) *ldapwire.Result {
	if state == nil || state.runtime == nil {
		return nil
	}
	security, requires := effectiveSecurityPolicy(state.runtime, database)
	transportSSF, tlsSSF := connectionTransportAndTLSSSF(state)
	overallSSF := max(transportSSF, tlsSSF, state.saslSSF)

	if result := insufficientSSFResult(
		transportSSF,
		security.transport,
		"transport confidentiality required",
		"stronger transport confidentiality required",
	); result != nil {
		return result
	}
	if result := insufficientSSFResult(
		tlsSSF,
		security.tls,
		"TLS confidentiality required",
		"stronger TLS confidentiality required",
	); result != nil {
		return result
	}
	if kind == policySimpleBind {
		if result := insufficientSSFResult(
			overallSSF,
			security.simpleBind,
			"confidentiality required",
			"stronger confidentiality required",
		); result != nil {
			return result
		}
	}
	if kind != policySASLBind && kind != policyAnonymousBind {
		if result := insufficientSSFResult(
			state.saslSSF,
			security.sasl,
			"SASL confidentiality required",
			"stronger SASL confidentiality required",
		); result != nil {
			return result
		}
		if result := insufficientSSFResult(
			overallSSF,
			security.overall,
			"confidentiality required",
			"stronger confidentiality required",
		); result != nil {
			return result
		}
	}

	if kind == policyUpdate {
		checks := []struct {
			actual, required uint32
			zero, weak       string
		}{
			{transportSSF, security.updateTransport, "transport confidentiality required for update", "stronger transport confidentiality required for update"},
			{tlsSSF, security.updateTLS, "TLS confidentiality required for update", "stronger TLS confidentiality required for update"},
			{state.saslSSF, security.updateSASL, "SASL confidentiality required for update", "stronger SASL confidentiality required for update"},
			{overallSSF, security.updateOverall, "confidentiality required for update", "stronger confidentiality required for update"},
		}
		for _, check := range checks {
			if result := insufficientSSFResult(
				check.actual,
				check.required,
				check.zero,
				check.weak,
			); result != nil {
				return result
			}
		}
		if state.boundDN == "" && !state.runtime.allows.anonymousUpdates {
			result := ldapwire.ResultError(
				ldapwire.ResultStrongerAuthRequired,
				"modifications require authentication",
			)
			return &result
		}
	}

	if kind == policySimpleBind || kind == policySASLBind || kind == policyAnonymousBind {
		return nil
	}
	if requires&requireStrongAuthentication != 0 && state.boundDN == "" {
		result := ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"strong(er) authentication required",
		)
		return &result
	}
	if requires&requireSASL != 0 &&
		(state.boundDN == "" || !connectionUsesSASLAuthentication(state)) {
		result := ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"SASL authentication required",
		)
		return &result
	}
	if requires&requireAuthentication != 0 && state.boundDN == "" {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"authentication required",
		)
		return &result
	}
	if requires&requireBind != 0 && state.protocolVersion == 0 {
		result := ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"BIND required",
		)
		return &result
	}
	protocolVersion := state.protocolVersion
	if protocolVersion == 0 {
		protocolVersion = 3
	}
	if requires&requireLDAPv3 != 0 && protocolVersion < 3 {
		result := ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"operation restricted to LDAPv3 clients",
		)
		return &result
	}
	return nil
}

func (requirements securityStrengthRequirements) empty() bool {
	requirements.configured = 0
	return requirements == (securityStrengthRequirements{})
}

func configuredOperationSecurityResult(
	state *connectionState,
	database *runtimeDatabase,
	kind operationPolicyKind,
) *ldapwire.Result {
	if state == nil || state.runtime == nil {
		return nil
	}
	security, requires := effectiveSecurityPolicy(state.runtime, database)
	if security.empty() && requires == 0 {
		return nil
	}
	return operationSecurityResult(state, database, kind)
}

func insufficientSSFResult(
	actual,
	required uint32,
	zeroDiagnostic,
	weakDiagnostic string,
) *ldapwire.Result {
	if actual >= required {
		return nil
	}
	diagnostic := zeroDiagnostic
	if actual != 0 {
		diagnostic = weakDiagnostic
	}
	result := ldapwire.ResultError(
		ldapwire.ResultConfidentialityRequired,
		diagnostic,
	)
	return &result
}

func connectionUsesSASLAuthentication(state *connectionState) bool {
	return state != nil && state.authMechanism != "" &&
		!strings.EqualFold(state.authMechanism, "SIMPLE")
}

func requestSecurityPolicy(
	state *connectionState,
	request ldapwire.Request,
) (*runtimeDatabase, operationPolicyKind, bool) {
	if state == nil || state.runtime == nil ||
		!runtimeHasConfiguredOperationSecurity(state.runtime) {
		return nil, policyRead, false
	}
	var rawDN string
	kind := policyRead
	switch request := request.(type) {
	case ldapwire.SearchRequest:
		rawDN = request.BaseDN
	case ldapwire.CompareRequest:
		rawDN = request.DN
	case ldapwire.AddRequest:
		rawDN = request.Entry.DN
		kind = policyUpdate
	case ldapwire.ModifyRequest:
		rawDN = request.DN
		kind = policyUpdate
	case ldapwire.DeleteRequest:
		rawDN = request.DN
		kind = policyUpdate
	case ldapwire.ModifyDNRequest:
		rawDN = request.DN
		kind = policyUpdate
	default:
		return nil, policyRead, false
	}
	dn, err := parseConnectionDN(state, rawDN)
	if err != nil {
		return nil, kind, false
	}
	if dn.Depth() == 0 {
		if kind == policyUpdate {
			return nil, kind, false
		}
		return nil, kind, true
	}
	if dn.Depth() == 1 && isRuntimeSubschemaDN(state.runtime, dn) {
		return nil, kind, true
	}
	database := databaseForNormalizedDN(state.runtime, dn)
	if database == nil {
		return nil, kind, false
	}
	return database, kind, true
}

func runtimeHasConfiguredOperationSecurity(runtime *runtimeState) bool {
	if runtime == nil {
		return false
	}
	if !runtime.security.empty() || runtime.requires != 0 {
		return true
	}
	for index := range runtime.databases {
		if !runtime.databases[index].security.empty() ||
			runtime.databases[index].requires != 0 {
			return true
		}
	}
	return false
}

func requestSecurityResult(
	state *connectionState,
	request ldapwire.Request,
) *ldapwire.Result {
	database, kind, applies := requestSecurityPolicy(state, request)
	if !applies {
		return nil
	}
	return configuredOperationSecurityResult(state, database, kind)
}

func requestControlFailureBeforeSecurity(
	state *connectionState,
	message ldapwire.Message,
) *ldapwire.Result {
	runtime := state.runtime
	controls := message.Controls
	if supported, controlIndex := transactionCapableRequest(message); supported && controlIndex >= 0 {
		if failure := validateTransactionSpecificationControl(
			state.transaction,
			message.Controls,
			controlIndex,
		); failure != nil {
			return failure
		}
		if failure := validateTransactionOperationControls(message, controlIndex); failure != nil {
			return failure
		}
		controls = make([]ldapwire.Control, 0, len(message.Controls)-1)
		controls = append(controls, message.Controls[:controlIndex]...)
		controls = append(controls, message.Controls[controlIndex+1:]...)
	}
	var support requestControlSupport
	switch request := message.Request.(type) {
	case ldapwire.SearchRequest:
		return nil
	case ldapwire.AddRequest:
		support = supportsAssertion | supportsPostRead | supportsManageDsaIT |
			supportsPasswordPolicy | supportsRelax | supportsLazyCommit | supportsNoOp
	case ldapwire.ModifyRequest:
		support = supportsAssertion | supportsPreRead | supportsPostRead |
			supportsManageDsaIT | supportsPasswordPolicy | supportsRelax |
			supportsLazyCommit | supportsNoOp | supportsPermissiveModify
	case ldapwire.DeleteRequest:
		support = supportsAssertion | supportsPreRead | supportsManageDsaIT |
			supportsRelax | supportsLazyCommit | supportsNoOp | supportsTreeDelete
	case ldapwire.ModifyDNRequest:
		support = supportsAssertion | supportsPreRead | supportsPostRead |
			supportsManageDsaIT | supportsRelax | supportsLazyCommit | supportsNoOp
	case ldapwire.CompareRequest:
		_, failure := parseRequestControlsWithDisallows(
			controls,
			supportsAssertion|supportsManageDsaIT|supportsDontUseCopy|
				supportsNoOp|supportsLazyCommit,
			runtime.disallows,
		)
		return failure
	case ldapwire.ExtendedRequest:
		if request.Name == passwordModifyOID {
			support = supportsManageDsaIT | supportsPasswordPolicy | supportsPasswordHashScheme
		}
	case ldapwire.BindRequest:
		support = supportsPasswordPolicy
	default:
		return nil
	}
	_, failure := parseRequestControls(controls, support)
	return failure
}

func bindPreDelegationResult(
	state *connectionState,
	request ldapwire.BindRequest,
) (*ldapwire.Result, bool) {
	requestDN, err := parseRuntimeConnectionDN(state.runtime, request.Name)
	if err != nil {
		result := ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "invalid DN")
		return &result, false
	}
	switch {
	case request.Version < 2 || request.Version > 3:
		result := ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"requested protocol version not supported",
		)
		return &result, false
	case request.Version == 2 && !state.runtime.allows.bindV2:
		result := ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"historical protocol version requested, use LDAPv3 instead",
		)
		return &result, false
	}
	state.protocolVersion = request.Version

	password := request.Authentication.Simple
	anonymous := !request.Authentication.IsSASL &&
		(requestDN.Depth() == 0 || len(password) == 0)
	switch {
	case anonymous && requestDN.Depth() == 0 && len(password) != 0 &&
		!state.runtime.allows.bindAnonymousCredentials:
		result := ldapwire.ResultError(ldapwire.ResultInvalidCredentials, "")
		return &result, false
	case anonymous && requestDN.Depth() != 0 && len(password) == 0 &&
		!state.runtime.allows.bindAnonymousDN:
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"unauthenticated bind (DN with no password) disallowed",
		)
		return &result, false
	case anonymous && state.runtime.disallows.anonymousBind:
		result := ldapwire.ResultError(
			ldapwire.ResultInappropriateAuthentication,
			"anonymous bind disallowed",
		)
		return &result, false
	case !request.Authentication.IsSASL && !anonymous &&
		state.runtime.disallows.simpleBind:
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"unwilling to perform simple authentication",
		)
		return &result, false
	case request.Authentication.IsSASL &&
		strings.TrimSpace(request.Authentication.SASLMechanism) == "":
		return nil, false
	}

	var database *runtimeDatabase
	kind := policySimpleBind
	switch {
	case anonymous:
		kind = policyAnonymousBind
	case request.Authentication.IsSASL:
		kind = policySASLBind
	default:
		database = databaseForDN(state.runtime, requestDN)
		if database == nil {
			return nil, false
		}
	}
	if result := operationSecurityResult(state, database, kind); result != nil {
		return result, true
	}
	if anonymous || requestDN.Depth() == 0 {
		if frontendRestricts(state.runtime, restrictBind) {
			result := ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			)
			return &result, true
		}
	} else if database != nil && databaseRestricts(*database, restrictBind) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
		return &result, true
	}
	return nil, false
}

func extendedRequestSecurityResult(
	state *connectionState,
	request ldapwire.ExtendedRequest,
) *ldapwire.Result {
	if state == nil || state.runtime == nil {
		return nil
	}
	switch request.Name {
	case startTLSOID, cancelOID:
		return nil
	case onlineBackupOID:
		return configuredOperationSecurityResult(state, nil, policyUpdate)
	case whoAmIOID:
		if request.HasValue {
			return nil
		}
		var database *runtimeDatabase
		if state.boundDN != "" {
			dn, err := parseRuntimeConnectionDN(state.runtime, state.boundDN)
			if err != nil {
				return nil
			}
			database = databaseForDN(state.runtime, dn)
		}
		return configuredOperationSecurityResult(state, database, policyRead)
	case passwordModifyOID:
		if state.boundDN == "" {
			return nil
		}
		decoded, err := ldapwire.DecodePasswordModifyRequestValue(
			request.Value,
			request.HasValue,
		)
		if err != nil {
			return nil
		}
		target := state.boundDN
		if decoded.HasUserIdentity && len(decoded.UserIdentity) != 0 {
			target = string(decoded.UserIdentity)
		}
		dn, err := parseRuntimeConnectionDN(state.runtime, target)
		if err != nil || dn.Depth() == 0 {
			return nil
		}
		database := databaseForDN(state.runtime, dn)
		if database == nil {
			return nil
		}
		return configuredOperationSecurityResult(state, database, policyUpdate)
	case dynamicRefreshOID:
		decoded, err := ldapwire.DecodeDynamicRefreshRequestValue(
			request.Value,
			request.HasValue,
		)
		if err != nil || decoded.RequestTTL <= 0 ||
			decoded.RequestTTL > int64(ddsRFCMaxTTL/time.Second) {
			return nil
		}
		dn, err := parseRuntimeConnectionDN(state.runtime, decoded.EntryName)
		if err != nil {
			return nil
		}
		database := databaseForDN(state.runtime, dn)
		if database == nil || database.dds == nil || !database.dds.enabled {
			return nil
		}
		return configuredOperationSecurityResult(state, database, policyUpdate)
	case transactionStartOID:
		if request.HasValue {
			return nil
		}
		return configuredOperationSecurityResult(state, nil, policyUpdate)
	case transactionEndOID:
		if !request.HasValue || len(request.Value) == 0 {
			return nil
		}
		return configuredOperationSecurityResult(state, nil, policyUpdate)
	default:
		return nil
	}
}
