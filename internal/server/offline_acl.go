package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type OfflineACLRequest struct {
	TargetDN         string
	AuthenticationDN string
	AuthenticationID string
	AuthorizationDN  string
	AuthorizationID  string
	DryRun           bool
	PeerName         string
	SockName         string
	Domain           string
	SockURL          string
	SSF              int
	TransportSSF     int
	TLSSSF           int
	SASLSSF          int
	Checks           []OfflineACLCheckRequest
}

type OfflineACLCheckRequest struct {
	Attribute string
	Access    string
	Value     []byte
	HasValue  bool
}

type OfflineACLCheckResult struct {
	Attribute string
	Access    string
	Value     []byte
	HasValue  bool
	Allowed   bool
	Mask      string
}

type OfflineACLReport struct {
	AuthenticationDN string
	AuthorizationDN  string
	Checks           []OfflineACLCheckResult
}

// CheckOfflineACL evaluates ACLs through the same runtime policy and reader
// context used by online LDAP operations. The store is opened read-only by the
// command and this API uses only one View transaction.
func CheckOfflineACL(
	ctx context.Context,
	store storage.Store,
	request OfflineACLRequest,
) (OfflineACLReport, error) {
	if ctx == nil {
		return OfflineACLReport{}, errors.New("offline ACL context is required")
	}
	if store == nil {
		return OfflineACLReport{}, errors.New("offline ACL store is required")
	}
	if strings.TrimSpace(request.TargetDN) == "" {
		return OfflineACLReport{}, errors.New("offline ACL target DN is required")
	}
	if request.AuthenticationDN != "" && request.AuthenticationID != "" {
		return OfflineACLReport{}, errors.New("authentication DN and ID are mutually exclusive")
	}
	if request.AuthorizationDN != "" && request.AuthorizationID != "" {
		return OfflineACLReport{}, errors.New("authorization DN and ID are mutually exclusive")
	}
	for name, value := range map[string]int{
		"ssf": request.SSF, "transport_ssf": request.TransportSSF,
		"tls_ssf": request.TLSSSF, "sasl_ssf": request.SASLSSF,
	} {
		if value < 0 {
			return OfflineACLReport{}, fmt.Errorf("%s must be non-negative", name)
		}
	}

	var report OfflineACLReport
	err := store.View(ctx, func(reader storage.Reader) error {
		instance, runtime, err := buildOfflineRuntime(reader, store)
		if err != nil {
			return err
		}
		target, err := parseRuntimeConnectionDN(runtime, request.TargetDN)
		if err != nil || target.Depth() == 0 {
			if err == nil {
				err = errors.New("target DN must not be empty")
			}
			return fmt.Errorf("normalize target DN %q: %w", request.TargetDN, err)
		}
		database := databaseForDN(runtime, target)
		if database == nil {
			return fmt.Errorf("no configured database contains target DN %q", request.TargetDN)
		}
		target, err = parseRuntimeDN(request.TargetDN, database.dnNormalizer)
		if err != nil {
			return fmt.Errorf("normalize target DN %q: %w", request.TargetDN, err)
		}

		authenticationDN, err := resolveOfflineACLAuthenticationDN(
			ctx, instance, runtime, request,
		)
		if err != nil {
			return err
		}
		authorizationDN, err := resolveOfflineACLAuthorizationDN(
			ctx, instance, runtime, request,
		)
		if err != nil {
			return err
		}
		effectiveDN := authenticationDN
		if authorizationDN != "" {
			effectiveDN = authorizationDN
		}
		realDN := authenticationDN
		if realDN == "" {
			realDN = effectiveDN
		}
		report.AuthenticationDN = authenticationDN
		report.AuthorizationDN = authorizationDN

		if !request.DryRun && !offlineDatabaseReadable(*database) {
			return fmt.Errorf(
				"database %q does not support offline entry access; use -u",
				database.name,
			)
		}
		databaseReader := readerForDatabase(reader, *database, ctx)
		entry := directory.Entry{DN: target.String()}
		if !request.DryRun {
			entry, err = databaseReader.Get(target)
			if err != nil {
				if errors.Is(err, storage.ErrEntryNotFound) {
					return fmt.Errorf("target entry %q was not found", request.TargetDN)
				}
				return fmt.Errorf("read target entry %q: %w", request.TargetDN, err)
			}
		}
		subject := acl.Subject{
			DN: effectiveDN, RealDN: realDN,
			PeerName: request.PeerName, SockName: request.SockName,
			Domain: request.Domain, SockURL: request.SockURL,
			SSF: request.SSF, TransportSSF: request.TransportSSF,
			TLSSSF: request.TLSSSF, SASLSSF: request.SASLSSF,
		}
		contextualReader := accessContextReader{
			Reader:  databaseReader,
			subject: subject,
			ctx:     ctx,
		}
		checks := request.Checks
		if len(checks) == 0 && !request.DryRun {
			checks = defaultOfflineACLChecks(entry)
		}
		for _, check := range checks {
			result, err := evaluateOfflineACLCheck(
				instance,
				runtime,
				contextualReader,
				effectiveDN,
				entry,
				check,
			)
			if err != nil {
				return err
			}
			report.Checks = append(report.Checks, result)
		}
		return nil
	})
	return report, err
}

func resolveOfflineACLAuthenticationDN(
	ctx context.Context,
	instance *Server,
	runtime *runtimeState,
	request OfflineACLRequest,
) (string, error) {
	if request.AuthenticationID != "" {
		dn, err := instance.saslUserDN(
			ctx, runtime, "", request.AuthenticationID, runtime.sasl.realm,
		)
		if err != nil {
			return "", fmt.Errorf("map authentication ID %q: %w", request.AuthenticationID, err)
		}
		return dn.String(), nil
	}
	if request.AuthenticationDN == "" {
		return "", nil
	}
	dn, err := parseRuntimeConnectionDN(runtime, request.AuthenticationDN)
	if err != nil {
		return "", fmt.Errorf("normalize authentication DN %q: %w", request.AuthenticationDN, err)
	}
	return dn.String(), nil
}

func resolveOfflineACLAuthorizationDN(
	ctx context.Context,
	instance *Server,
	runtime *runtimeState,
	request OfflineACLRequest,
) (string, error) {
	if request.AuthorizationID != "" {
		dn, err := resolveOfflineAuthorizationID(
			ctx, instance, runtime, "", "", request.AuthorizationID,
		)
		if err != nil {
			return "", fmt.Errorf("map authorization ID %q: %w", request.AuthorizationID, err)
		}
		return dn.String(), nil
	}
	if request.AuthorizationDN == "" {
		return "", nil
	}
	dn, err := parseRuntimeConnectionDN(runtime, request.AuthorizationDN)
	if err != nil {
		return "", fmt.Errorf("normalize authorization DN %q: %w", request.AuthorizationDN, err)
	}
	return dn.String(), nil
}

func defaultOfflineACLChecks(entry directory.Entry) []OfflineACLCheckRequest {
	checks := []OfflineACLCheckRequest{{Attribute: "entry"}, {Attribute: "children"}}
	for _, attribute := range entry.Attributes {
		for _, value := range attribute.Values {
			checks = append(checks, OfflineACLCheckRequest{
				Attribute: attribute.Description,
				Value:     bytes.Clone(value),
				HasValue:  true,
			})
		}
	}
	return checks
}

func evaluateOfflineACLCheck(
	instance *Server,
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	entry directory.Entry,
	check OfflineACLCheckRequest,
) (OfflineACLCheckResult, error) {
	attribute, err := canonicalOfflineACLAttribute(runtime, check.Attribute)
	if err != nil {
		return OfflineACLCheckResult{}, err
	}
	result := OfflineACLCheckResult{
		Attribute: attribute,
		Access:    strings.ToLower(strings.TrimSpace(check.Access)),
		Value:     bytes.Clone(check.Value),
		HasValue:  check.HasValue,
	}
	var value []byte
	if check.HasValue {
		value = check.Value
	}
	if result.Access != "" {
		required, err := offlineACLAccessPrivilege(result.Access)
		if err != nil {
			return OfflineACLCheckResult{}, fmt.Errorf("attribute %q: %w", check.Attribute, err)
		}
		result.Allowed = instance.allowed(
			runtime, reader, subjectDN, entry, attribute, value, required,
		)
		return result, nil
	}
	var privileges acl.Privilege
	for _, privilege := range []acl.Privilege{
		acl.Disclose, acl.Auth, acl.Compare, acl.Search, acl.Read,
		acl.WriteAdd, acl.WriteDelete, acl.Manage,
	} {
		if instance.allowed(
			runtime, reader, subjectDN, entry, attribute, value, privilege,
		) {
			privileges |= privilege
		}
	}
	result.Mask = formatOfflineACLMask(privileges)
	return result, nil
}

func canonicalOfflineACLAttribute(runtime *runtimeState, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if err := validateConstraintAttributeDescription(raw); err != nil {
		return "", err
	}
	attribute, found := runtime.schema.AttributeType(strings.Split(raw, ";")[0])
	if !found {
		return "", fmt.Errorf("undefined attribute type %q", raw)
	}
	parts := strings.Split(raw, ";")
	parts[0] = attribute.Name()
	return strings.Join(parts, ";"), nil
}

func offlineACLAccessPrivilege(value string) (acl.Privilege, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "disclose":
		return acl.Disclose, nil
	case "auth":
		return acl.Auth, nil
	case "compare":
		return acl.Compare, nil
	case "search":
		return acl.Search, nil
	case "read":
		return acl.Read, nil
	case "write":
		return acl.Write, nil
	case "add":
		return acl.WriteAdd, nil
	case "delete":
		return acl.WriteDelete, nil
	case "manage":
		return acl.Manage, nil
	case "none":
		return 0, errors.New("access level none is not allowed")
	default:
		return 0, fmt.Errorf("unknown access level %q", value)
	}
}

func formatOfflineACLMask(privileges acl.Privilege) string {
	levels := []struct {
		privileges acl.Privilege
		name       string
		letters    string
	}{
		{acl.NoneLevel, "none", "0"},
		{acl.DiscloseLevel, "disclose", "d"},
		{acl.AuthLevel, "auth", "xd"},
		{acl.CompareLevel, "compare", "cxd"},
		{acl.SearchLevel, "search", "scxd"},
		{acl.ReadLevel, "read", "rscxd"},
		{acl.WriteLevel, "write", "wrscxd"},
		{acl.ManageLevel, "manage", "mwrscxd"},
	}
	for _, level := range levels {
		if privileges == level.privileges {
			return level.name + "(=" + level.letters + ")"
		}
	}
	var letters strings.Builder
	if privileges&acl.Manage != 0 {
		letters.WriteByte('m')
	}
	add := privileges&acl.WriteAdd != 0
	delete := privileges&acl.WriteDelete != 0
	switch {
	case add && delete:
		letters.WriteByte('w')
	case add:
		letters.WriteByte('a')
	case delete:
		letters.WriteByte('z')
	}
	for _, item := range []struct {
		privilege acl.Privilege
		letter    byte
	}{
		{acl.Read, 'r'}, {acl.Search, 's'}, {acl.Compare, 'c'},
		{acl.Auth, 'x'}, {acl.Disclose, 'd'},
	} {
		if privileges&item.privilege != 0 {
			letters.WriteByte(item.letter)
		}
	}
	if letters.Len() == 0 {
		letters.WriteByte('0')
	}
	return "=" + letters.String()
}
