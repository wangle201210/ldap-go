package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	idleTimeoutAttribute  = "olcIdleTimeout"
	writeTimeoutAttribute = "olcWriteTimeout"
)

func loadConnectionTimeoutRuntimeConfiguration(
	reader storage.Reader,
) (time.Duration, time.Duration, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("load global connection timeout configuration: %w", err)
	}

	var idleTimeout, writeTimeout time.Duration
	for _, attribute := range []struct {
		description string
		target      *time.Duration
	}{
		{idleTimeoutAttribute, &idleTimeout},
		{writeTimeoutAttribute, &writeTimeout},
	} {
		values := entry.Values(attribute.description)
		if len(values) == 0 {
			continue
		}
		if len(values) != 1 {
			return 0, 0, fmt.Errorf(
				"%s must contain exactly one value",
				attribute.description,
			)
		}
		seconds, err := parseOpenLDAPConnectionTimeout(string(values[0]))
		if err != nil {
			return 0, 0, fmt.Errorf("%s: %w", attribute.description, err)
		}
		*attribute.target = time.Duration(seconds) * time.Second
	}
	return idleTimeout, writeTimeout, nil
}

// parseOpenLDAPConnectionTimeout mirrors lutil_atoix(..., base=0) for a
// 32-bit int. Non-positive runtime values disable the corresponding timeout.
func parseOpenLDAPConnectionTimeout(raw string) (int32, error) {
	token := strings.TrimLeft(raw, " \t\n\v\f\r")
	if token == "" {
		return 0, errors.New("must be a 32-bit integer")
	}

	negative := false
	body := token
	if body[0] == '+' || body[0] == '-' {
		negative = body[0] == '-'
		body = body[1:]
	}
	if body == "" {
		return 0, errors.New("must be a 32-bit integer")
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
		return 0, errors.New("must be a 32-bit integer")
	}

	parseToken := digits
	if negative {
		parseToken = "-" + parseToken
	}
	value, err := strconv.ParseInt(parseToken, base, 32)
	if err != nil {
		return 0, errors.New("must be a 32-bit integer")
	}
	return int32(value), nil
}

func validateConnectionTimeoutOnlineChanges(
	entry directory.Entry,
	changes []ldapwire.Modification,
) error {
	touched := false
	for _, change := range changes {
		if isConnectionTimeoutAttribute(change.Attribute.Description) {
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
			"olcIdleTimeout and olcWriteTimeout are only allowed on cn=config",
		)
	}

	state := map[string][]string{
		strings.ToLower(idleTimeoutAttribute):  connectionTimeoutStrings(entry.Values(idleTimeoutAttribute)),
		strings.ToLower(writeTimeoutAttribute): connectionTimeoutStrings(entry.Values(writeTimeoutAttribute)),
	}
	for _, change := range changes {
		description := strings.SplitN(change.Attribute.Description, ";", 2)[0]
		key := strings.ToLower(description)
		current, ok := state[key]
		if !ok {
			continue
		}
		values := connectionTimeoutStrings(change.Attribute.Values)
		for _, value := range values {
			if err := validateOnlineConnectionTimeout(value); err != nil {
				return err
			}
		}

		switch change.Operation {
		case ldapwire.ModificationAdd:
			if len(values) != 1 {
				return connectionTimeoutConstraint(description, "multiple values provided")
			}
			for _, existing := range current {
				if existing == values[0] {
					return operationFailed(
						ldapwire.ResultAttributeOrValueExists,
						"modify/add: "+description+": value #0 already exists",
					)
				}
			}
			if len(current) != 0 {
				return connectionTimeoutConstraint(description, "multiple values provided")
			}
			state[key] = append([]string(nil), values...)

		case ldapwire.ModificationDelete:
			if len(values) == 0 {
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
				return connectionTimeoutConstraint(description, "multiple values provided")
			}
			state[key] = append([]string(nil), values...)

		default:
			return connectionTimeoutConstraint(description, "unsupported modification")
		}
	}
	return nil
}

func validateOnlineConnectionTimeout(value string) error {
	if !isCanonicalLDAPInteger(value) {
		return operationFailed(
			ldapwire.ResultInvalidAttributeSyntax,
			"connection timeout value is not a valid LDAP integer",
		)
	}
	_, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return operationFailed(
			ldapwire.ResultConstraintViolation,
			"connection timeout must be a 32-bit integer",
		)
	}
	return nil
}

func isCanonicalLDAPInteger(value string) bool {
	if value == "0" {
		return true
	}
	if value == "" || value[0] == '+' || value[0] == '0' {
		return false
	}
	start := 0
	if value[0] == '-' {
		if len(value) == 1 || value[1] == '0' {
			return false
		}
		start = 1
	}
	for index := start; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func isConnectionTimeoutAttribute(description string) bool {
	description = strings.SplitN(description, ";", 2)[0]
	return strings.EqualFold(description, idleTimeoutAttribute) ||
		strings.EqualFold(description, writeTimeoutAttribute)
}

func connectionTimeoutStrings(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}

func stringValueIndex(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return -1
}

func connectionTimeoutConstraint(description, diagnostic string) error {
	return operationFailed(
		ldapwire.ResultConstraintViolation,
		description+": "+diagnostic,
	)
}
