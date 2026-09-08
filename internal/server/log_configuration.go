package server

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type logConfigurationError struct {
	code       ldapwire.ResultCode
	diagnostic string
}

func (failure *logConfigurationError) Error() string {
	return failure.diagnostic
}

func logConfigurationFailure(
	code ldapwire.ResultCode,
	diagnostic string,
) error {
	return &logConfigurationError{code: code, diagnostic: diagnostic}
}

func logConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *logConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(failure.code, failure.diagnostic), true
}

type openLDAPLogFileFormat uint8

const (
	openLDAPLogFileFormatDebug openLDAPLogFileFormat = iota
	openLDAPLogFileFormatSyslogUTC
	openLDAPLogFileFormatSyslogLocaltime
	openLDAPLogFileFormatRFC3339UTC
)

type openLDAPLogFileRotation struct {
	maximum int
	bytes   int64
	age     time.Duration
}

type openLDAPLogFileConfiguration struct {
	path     string
	format   openLDAPLogFileFormat
	only     bool
	rotation openLDAPLogFileRotation
}

func loadOpenLDAPLogFileConfiguration(
	reader storage.Reader,
) (openLDAPLogFileConfiguration, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return openLDAPLogFileConfiguration{}, nil
	}
	if err != nil {
		return openLDAPLogFileConfiguration{}, fmt.Errorf(
			"load OpenLDAP logfile configuration: %w",
			err,
		)
	}

	configuration := openLDAPLogFileConfiguration{}
	if values := entry.Values("olcLogFile"); len(values) != 0 {
		if len(values) != 1 {
			return configuration, invalidLogConfiguration(
				"olcLogFile must be single-valued",
			)
		}
		configuration.path = string(values[0])
		if configuration.path == "" {
			return configuration, invalidLogConfiguration(
				"olcLogFile cannot be empty",
			)
		}
	}

	if values := entry.Values("olcLogFileFormat"); len(values) != 0 {
		if len(values) != 1 {
			return configuration, invalidLogConfiguration(
				"olcLogFileFormat must be single-valued",
			)
		}
		fields, err := openLDAPLogConfigurationFields(string(values[0]))
		if err != nil {
			return configuration, err
		}
		if len(fields) != 1 {
			return configuration, logConfigurationFailure(ldapwire.ResultConstraintViolation,
				"olcLogFileFormat requires one format")
		}
		switch strings.ToLower(fields[0]) {
		case "default", "debug":
			configuration.format = openLDAPLogFileFormatDebug
		case "syslog-utc":
			configuration.format = openLDAPLogFileFormatSyslogUTC
		case "syslog-localtime":
			configuration.format = openLDAPLogFileFormatSyslogLocaltime
		case "rfc3339-utc":
			configuration.format = openLDAPLogFileFormatRFC3339UTC
		default:
			return configuration, invalidLogConfiguration(fmt.Sprintf(
				"olcLogFileFormat has unknown format %q",
				values[0],
			))
		}
	}

	only, present, err := singleBoolean(entry, "olcLogFileOnly")
	if err != nil {
		return configuration, logConfigurationFailure(
			ldapwire.ResultInvalidAttributeSyntax,
			err.Error(),
		)
	}
	if present {
		configuration.only = only
	}

	if values := entry.Values("olcLogFileRotate"); len(values) != 0 {
		if len(values) != 1 {
			return configuration, invalidLogConfiguration(
				"olcLogFileRotate must be single-valued",
			)
		}
		rotation, err := parseOpenLDAPLogFileRotation(string(values[0]))
		if err != nil {
			return configuration, err
		}
		configuration.rotation = rotation
	}
	return configuration, nil
}

func parseOpenLDAPLogFileRotation(value string) (openLDAPLogFileRotation, error) {
	fields, err := openLDAPLogConfigurationFields(value)
	if err != nil {
		return openLDAPLogFileRotation{}, err
	}
	if len(fields) != 3 {
		return openLDAPLogFileRotation{}, logConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"olcLogFileRotate requires max, Mbytes, and hours",
		)
	}
	numbers := [3]uint64{}
	for index, field := range fields {
		// OpenLDAP uses strtoul(base=0): decimal, octal, hexadecimal and an
		// optional plus sign, without Go's binary prefixes or digit separators.
		digits := strings.TrimPrefix(field, "+")
		base := 10
		if strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0X") {
			base, digits = 16, digits[2:]
		} else if strings.HasPrefix(digits, "0") {
			base = 8
		}
		number, err := strconv.ParseUint(digits, base, 32)
		if err != nil {
			return openLDAPLogFileRotation{}, invalidLogConfiguration(fmt.Sprintf(
				"olcLogFileRotate has invalid value %q",
				field,
			))
		}
		numbers[index] = number
	}
	if numbers[0] == 0 || numbers[0] > 99 {
		return openLDAPLogFileRotation{}, invalidLogConfiguration(
			"olcLogFileRotate max must be in the range 1-99",
		)
	}
	if numbers[1] == 0 && numbers[2] == 0 {
		return openLDAPLogFileRotation{}, invalidLogConfiguration(
			"olcLogFileRotate Mbytes and hours cannot both be zero",
		)
	}
	if numbers[1] > math.MaxInt64/(1<<20) ||
		numbers[2] > uint64(math.MaxInt64/int64(time.Hour)) {
		return openLDAPLogFileRotation{}, invalidLogConfiguration(
			"olcLogFileRotate value exceeds the supported range",
		)
	}
	return openLDAPLogFileRotation{
		maximum: int(numbers[0]),
		bytes:   int64(numbers[1]) << 20,
		age:     time.Duration(numbers[2]) * time.Hour,
	}, nil
}

func openLDAPLogConfigurationFields(value string) ([]string, error) {
	// cn=config passes backslashes through literally; none of the accepted
	// logfile format names or rotation numbers contain one.
	if strings.ContainsRune(value, '\\') {
		return nil, invalidLogConfiguration("invalid backslash in logfile setting")
	}
	fields, err := splitOpenLDAPModuleFields(value)
	if err != nil {
		return nil, invalidLogConfiguration("invalid quoted logfile setting")
	}
	return fields, nil
}

func invalidLogConfiguration(diagnostic string) error {
	return logConfigurationFailure(ldapwire.ResultOther, diagnostic)
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
			return nil, false, logConfigurationFailure(
				ldapwire.ResultOther, "olcLogLevel contains an empty value",
			)
		}
		for _, field := range fields {
			if _, known := monitorLogCategories[strings.ToLower(field)]; !known {
				if _, numeric := parseMonitorLogMaskNumber(field); !numeric {
					return nil, false, logConfigurationFailure(
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
