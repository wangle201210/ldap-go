//go:build freebsd

package server

func sqlBackendIsODBCParameterError(error) bool {
	return false
}

func sqlBackendODBCExecutionErrorDisposition(error) (bool, bool) {
	return false, false
}
