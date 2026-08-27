package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultIncomingLimitAnonymous     uint64 = (1 << 18) - 1
	defaultIncomingLimitAuthenticated uint64 = (1 << 24) - 1

	incomingLimitAnonymousAttribute     = "olcSockbufMaxIncoming"
	incomingLimitAuthenticatedAttribute = "olcSockbufMaxIncomingAuth"
)

type incomingLimits struct {
	anonymous     uint64
	authenticated uint64
}

func defaultIncomingLimits() incomingLimits {
	return incomingLimits{
		anonymous:     defaultIncomingLimitAnonymous,
		authenticated: defaultIncomingLimitAuthenticated,
	}
}

func (limits incomingLimits) forAuthentication(authenticated bool) uint64 {
	if authenticated {
		return limits.authenticated
	}
	return limits.anonymous
}

func loadIncomingLimitRuntimeConfiguration(
	reader storage.Reader,
) (incomingLimits, error) {
	limits := defaultIncomingLimits()
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return limits, nil
	}
	if err != nil {
		return incomingLimits{}, fmt.Errorf(
			"load global incoming PDU limit configuration: %w",
			err,
		)
	}

	for _, attribute := range []struct {
		description string
		target      *uint64
	}{
		{incomingLimitAnonymousAttribute, &limits.anonymous},
		{incomingLimitAuthenticatedAttribute, &limits.authenticated},
	} {
		values := entry.Values(attribute.description)
		if len(values) == 0 {
			continue
		}
		if len(values) != 1 {
			return incomingLimits{}, fmt.Errorf(
				"%s must contain exactly one value",
				attribute.description,
			)
		}
		value, err := parseOpenLDAPIncomingLimit(string(values[0]))
		if err != nil {
			return incomingLimits{}, fmt.Errorf(
				"%s: %w",
				attribute.description,
				err,
			)
		}
		*attribute.target = value
	}
	return limits, nil
}

// parseOpenLDAPIncomingLimit mirrors lutil_atoulx(..., base=0) on a
// 64-bit platform. In particular, it accepts octal and hexadecimal input but
// rejects binary prefixes, separators, whitespace, and negative values.
func parseOpenLDAPIncomingLimit(raw string) (uint64, error) {
	if raw == "" || raw[0] == '-' || isIncomingLimitASCIIWhitespace(raw[0]) {
		return 0, errors.New("must be an unsigned 64-bit integer")
	}

	body := raw
	if body[0] == '+' {
		body = body[1:]
		if body == "" {
			return 0, errors.New("must be an unsigned 64-bit integer")
		}
	}

	base := 10
	digits := body
	if len(body) >= 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X') {
		base = 16
		digits = body[2:]
	} else if len(body) > 1 && body[0] == '0' {
		base = 8
	}
	if digits == "" {
		return 0, errors.New("must be an unsigned 64-bit integer")
	}
	value, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, errors.New("must be an unsigned 64-bit integer")
	}
	return value, nil
}

func isIncomingLimitASCIIWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

// validateIncomingLimitOnlineChanges validates cn=config modifications before
// the generic modifier mutates the candidate entry. Callers can then rebuild
// the runtime in the same storage transaction and retain the previous snapshot
// if either validation or rebuilding fails.
func validateIncomingLimitOnlineChanges(
	entry directory.Entry,
	changes []ldapwire.Modification,
) error {
	touched := false
	for _, change := range changes {
		if isIncomingLimitAttribute(change.Attribute.Description) {
			touched = true
			break
		}
	}
	if !touched {
		return nil
	}
	if !isGlobalConfigurationEntry(entry.DN) {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"olcSockbufMaxIncoming and olcSockbufMaxIncomingAuth are only allowed on cn=config",
		)
	}

	state := map[string][]string{
		strings.ToLower(incomingLimitAnonymousAttribute):     incomingLimitStrings(entry.Values(incomingLimitAnonymousAttribute)),
		strings.ToLower(incomingLimitAuthenticatedAttribute): incomingLimitStrings(entry.Values(incomingLimitAuthenticatedAttribute)),
	}
	for _, change := range changes {
		description := strings.SplitN(change.Attribute.Description, ";", 2)[0]
		key := strings.ToLower(description)
		current, applies := state[key]
		if !applies {
			continue
		}
		values := incomingLimitStrings(change.Attribute.Values)
		for _, value := range values {
			if err := validateOnlineIncomingLimit(value); err != nil {
				return err
			}
		}
		if change.Operation == ldapwire.ModificationAdd ||
			change.Operation == ldapwire.ModificationReplace {
			if duplicate := duplicateIncomingLimitValue(values); duplicate >= 0 {
				return operationFailed(
					ldapwire.ResultAttributeOrValueExists,
					fmt.Sprintf("%s: value #%d provided more than once", description, duplicate),
				)
			}
		}

		switch change.Operation {
		case ldapwire.ModificationAdd:
			if len(values) != 1 {
				return incomingLimitConstraint(description, "multiple values provided")
			}
			if len(current) != 0 {
				if stringValueIndex(current, values[0]) >= 0 {
					return operationFailed(
						ldapwire.ResultAttributeOrValueExists,
						"modify/add: "+description+": value #0 already exists",
					)
				}
				return incomingLimitConstraint(description, "multiple values provided")
			}
			state[key] = append([]string(nil), values...)

		case ldapwire.ModificationDelete:
			if len(values) == 0 {
				if len(current) == 0 {
					return operationFailed(
						ldapwire.ResultNoSuchAttribute,
						"modify/delete: "+description+": no such attribute",
					)
				}
				state[key] = nil
				continue
			}
			for _, value := range values {
				index := stringValueIndex(current, value)
				if index < 0 {
					return operationFailed(
						ldapwire.ResultNoSuchAttribute,
						"modify/delete: "+description+": no such value",
					)
				}
				current = append(current[:index], current[index+1:]...)
			}
			state[key] = current

		case ldapwire.ModificationReplace:
			if len(values) > 1 {
				return incomingLimitConstraint(description, "multiple values provided")
			}
			state[key] = append([]string(nil), values...)

		default:
			return incomingLimitConstraint(description, "unsupported modification")
		}
	}
	return nil
}

func validateOnlineIncomingLimit(value string) error {
	if !isCanonicalLDAPInteger(value) {
		return operationFailed(
			ldapwire.ResultInvalidAttributeSyntax,
			"incoming PDU limit value is not a valid LDAP integer",
		)
	}
	if strings.HasPrefix(value, "-") {
		return operationFailed(
			ldapwire.ResultConstraintViolation,
			"incoming PDU limit must be non-negative",
		)
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return operationFailed(
			ldapwire.ResultConstraintViolation,
			"incoming PDU limit must be an unsigned 64-bit integer",
		)
	}
	return nil
}

func duplicateIncomingLimitValue(values []string) int {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return index
		}
		seen[value] = struct{}{}
	}
	return -1
}

func isIncomingLimitAttribute(description string) bool {
	description = strings.SplitN(description, ";", 2)[0]
	return strings.EqualFold(description, incomingLimitAnonymousAttribute) ||
		strings.EqualFold(description, incomingLimitAuthenticatedAttribute)
}

func incomingLimitStrings(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}

func incomingLimitConstraint(description, diagnostic string) error {
	return operationFailed(
		ldapwire.ResultConstraintViolation,
		description+": "+diagnostic,
	)
}
