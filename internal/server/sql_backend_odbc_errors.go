//go:build !freebsd

package server

import (
	"errors"
	"strings"

	"github.com/slingdata-io/godbc"
)

func sqlBackendIsODBCParameterError(err error) bool {
	var parameterError *godbc.ParameterError
	return errors.As(err, &parameterError)
}

func sqlBackendODBCExecutionErrorDisposition(err error) (bool, bool) {
	var single *godbc.Error
	if errors.As(err, &single) {
		return sqlBackendIgnorableODBCExecutionError(*single), true
	}
	var multiple godbc.Errors
	if !errors.As(err, &multiple) {
		return false, false
	}
	if len(multiple) == 0 {
		return false, true
	}
	for _, item := range multiple {
		if !sqlBackendIgnorableODBCExecutionError(item) {
			return false, true
		}
	}
	return true, true
}

func sqlBackendIgnorableODBCExecutionError(err godbc.Error) bool {
	state := strings.ToUpper(strings.TrimSpace(err.SQLState))
	if len(state) != 5 {
		return false
	}
	switch state {
	case "HY000":
		return err.NativeError&0xff == 4 || err.NativeError&0xff == 19
	case "HY008", "HY009", "HY010", "HY013", "HY021", "HY090", "HY104", "HYC00":
		return false
	}
	switch state[:2] {
	case "07", "08":
		return false
	case "23", "27", "40", "42", "44":
		return true
	default:
		return false
	}
}
