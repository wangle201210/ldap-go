//go:build freebsd

package server

import (
	"database/sql/driver"
	"errors"
)

func newSQLBackendODBCConnector(string) (driver.Connector, error) {
	return nil, errors.New("ODBC connector is unavailable on FreeBSD pure-Go builds")
}
