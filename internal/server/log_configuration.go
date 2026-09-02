package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type logLevelConfigurationError struct {
	code       ldapwire.ResultCode
	diagnostic string
}

func (failure *logLevelConfigurationError) Error() string {
	return failure.diagnostic
}

func logLevelConfigurationFailure(
	code ldapwire.ResultCode,
	diagnostic string,
) error {
	return &logLevelConfigurationError{code: code, diagnostic: diagnostic}
}

func logLevelConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *logLevelConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(failure.code, failure.diagnostic), true
}

func loadOpenLDAPLogLevels(reader storage.Reader) ([]string, bool, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load olcLogLevel: %w", err)
	}
	rawValues := entry.Values("olcLogLevel")
	if len(rawValues) == 0 {
		return nil, false, nil
	}
	levels := make([]string, 0, len(rawValues))
	for _, raw := range rawValues {
		fields := strings.Fields(string(raw))
		if len(fields) == 0 {
			return nil, false, logLevelConfigurationFailure(
				ldapwire.ResultOther, "olcLogLevel contains an empty value",
			)
		}
		for _, field := range fields {
			if _, known := monitorLogCategories[strings.ToLower(field)]; !known {
				if _, numeric := parseMonitorLogMaskNumber(field); !numeric {
					return nil, false, logLevelConfigurationFailure(
						ldapwire.ResultOther,
						fmt.Sprintf("olcLogLevel has unknown level %q", field),
					)
				}
			}
			levels = append(levels, field)
		}
	}
	return levels, true, nil
}
