//go:build !freebsd

package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/slingdata-io/godbc"
)

type sqlBackendODBCConnector struct {
	connector driver.Connector
}

func newSQLBackendODBCConnector(dsn string) (driver.Connector, error) {
	connector, err := (&godbc.Driver{}).OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return &sqlBackendODBCConnector{connector: connector}, nil
}

func (connector *sqlBackendODBCConnector) Connect(
	ctx context.Context,
) (driver.Conn, error) {
	connection, err := connector.connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &sqlBackendODBCConnection{Conn: connection}, nil
}

func (connector *sqlBackendODBCConnector) Driver() driver.Driver {
	return sqlBackendODBCDriver{driver: connector.connector.Driver()}
}

type sqlBackendODBCDriver struct {
	driver driver.Driver
}

func (wrapper sqlBackendODBCDriver) Open(name string) (driver.Conn, error) {
	connection, err := wrapper.driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &sqlBackendODBCConnection{Conn: connection}, nil
}

type sqlBackendODBCConnection struct {
	driver.Conn
}

func (connection *sqlBackendODBCConnection) Prepare(query string) (driver.Stmt, error) {
	statement, err := connection.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &sqlBackendODBCStatement{Stmt: statement}, nil
}

func (connection *sqlBackendODBCConnection) PrepareContext(
	ctx context.Context,
	query string,
) (driver.Stmt, error) {
	preparer, ok := connection.Conn.(driver.ConnPrepareContext)
	if !ok {
		return connection.Prepare(query)
	}
	statement, err := preparer.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	return &sqlBackendODBCStatement{Stmt: statement}, nil
}

func (connection *sqlBackendODBCConnection) BeginTx(
	ctx context.Context,
	options driver.TxOptions,
) (driver.Tx, error) {
	beginner, ok := connection.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	return beginner.BeginTx(ctx, options)
}

func (connection *sqlBackendODBCConnection) Ping(ctx context.Context) error {
	pinger, ok := connection.Conn.(driver.Pinger)
	if !ok {
		return nil
	}
	return pinger.Ping(ctx)
}

func (connection *sqlBackendODBCConnection) ResetSession(ctx context.Context) error {
	resetter, ok := connection.Conn.(driver.SessionResetter)
	if !ok {
		return nil
	}
	return resetter.ResetSession(ctx)
}

func (connection *sqlBackendODBCConnection) IsValid() bool {
	validator, ok := connection.Conn.(driver.Validator)
	return !ok || validator.IsValid()
}

func (connection *sqlBackendODBCConnection) CheckNamedValue(
	value *driver.NamedValue,
) error {
	if _, ok := value.Value.(sql.Out); ok {
		return validateSQLBackendODBCOutput(value.Value.(sql.Out))
	}
	if checker, ok := connection.Conn.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

func (connection *sqlBackendODBCConnection) ExecContext(
	ctx context.Context,
	query string,
	arguments []driver.NamedValue,
) (driver.Result, error) {
	execer, ok := connection.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	converted, outputs, err := convertSQLBackendODBCArguments(arguments)
	if err != nil {
		return nil, err
	}
	result, err := execer.ExecContext(ctx, query, converted)
	if err != nil {
		return nil, err
	}
	if err := assignSQLBackendODBCOutputs(result, outputs); err != nil {
		return nil, err
	}
	return result, nil
}

func (connection *sqlBackendODBCConnection) QueryContext(
	ctx context.Context,
	query string,
	arguments []driver.NamedValue,
) (driver.Rows, error) {
	queryer, ok := connection.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, arguments)
}

type sqlBackendODBCStatement struct {
	driver.Stmt
}

func (statement *sqlBackendODBCStatement) CheckNamedValue(
	value *driver.NamedValue,
) error {
	if output, ok := value.Value.(sql.Out); ok {
		return validateSQLBackendODBCOutput(output)
	}
	if checker, ok := statement.Stmt.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

func (statement *sqlBackendODBCStatement) ExecContext(
	ctx context.Context,
	arguments []driver.NamedValue,
) (driver.Result, error) {
	executor, ok := statement.Stmt.(driver.StmtExecContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	converted, outputs, err := convertSQLBackendODBCArguments(arguments)
	if err != nil {
		return nil, err
	}
	result, err := executor.ExecContext(ctx, converted)
	if err != nil {
		return nil, err
	}
	if err := assignSQLBackendODBCOutputs(result, outputs); err != nil {
		return nil, err
	}
	return result, nil
}

func (statement *sqlBackendODBCStatement) QueryContext(
	ctx context.Context,
	arguments []driver.NamedValue,
) (driver.Rows, error) {
	queryer, ok := statement.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, arguments)
}

type sqlBackendODBCOutput struct {
	index       int
	destination any
}

type sqlBackendODBCOutputResult interface {
	OutputParam(int) any
}

func convertSQLBackendODBCArguments(
	arguments []driver.NamedValue,
) ([]driver.NamedValue, []sqlBackendODBCOutput, error) {
	converted := append([]driver.NamedValue(nil), arguments...)
	var outputs []sqlBackendODBCOutput
	for index := range converted {
		output, ok := converted[index].Value.(sql.Out)
		if !ok {
			continue
		}
		if converted[index].Name != "" {
			return nil, nil, errors.New("named SQL output parameters are not supported")
		}
		if err := validateSQLBackendODBCOutput(output); err != nil {
			return nil, nil, err
		}
		destination := reflect.ValueOf(output.Dest).Elem().Interface()
		if output.In {
			converted[index].Value = godbc.NewInputOutputParam(destination)
		} else {
			converted[index].Value = godbc.NewOutputParam(destination)
		}
		outputs = append(outputs, sqlBackendODBCOutput{
			index:       index,
			destination: output.Dest,
		})
	}
	return converted, outputs, nil
}

func validateSQLBackendODBCOutput(output sql.Out) error {
	if output.Dest == nil {
		return errors.New("SQL output destination is nil")
	}
	destination := reflect.ValueOf(output.Dest)
	if destination.Kind() != reflect.Pointer || destination.IsNil() {
		return fmt.Errorf("SQL output destination %T is not a non-nil pointer", output.Dest)
	}
	target := destination.Elem()
	if !supportedSQLBackendODBCOutputType(target.Type()) {
		return fmt.Errorf("SQL output destination %T is not supported by godbc", output.Dest)
	}
	return nil
}

func supportedSQLBackendODBCOutputType(value reflect.Type) bool {
	if value == reflect.TypeFor[time.Time]() {
		return true
	}
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64, reflect.String, reflect.Bool:
		return true
	case reflect.Slice:
		return value.Elem().Kind() == reflect.Uint8
	default:
		return false
	}
}

func assignSQLBackendODBCOutputs(
	result driver.Result,
	outputs []sqlBackendODBCOutput,
) error {
	if len(outputs) == 0 {
		return nil
	}
	provider, ok := result.(sqlBackendODBCOutputResult)
	if !ok {
		return fmt.Errorf("ODBC result %T does not expose output parameters", result)
	}
	for _, output := range outputs {
		if err := assignSQLBackendODBCOutput(
			output.destination,
			provider.OutputParam(output.index),
		); err != nil {
			return err
		}
	}
	return nil
}

func assignSQLBackendODBCOutput(destination, value any) error {
	target := reflect.ValueOf(destination).Elem()
	if value == nil {
		return fmt.Errorf("ODBC output value for %T is NULL or missing", destination)
	}
	source := reflect.ValueOf(value)
	switch {
	case source.Type().AssignableTo(target.Type()):
		target.Set(source)
	case source.Type().ConvertibleTo(target.Type()):
		target.Set(source.Convert(target.Type()))
	default:
		return fmt.Errorf(
			"ODBC output value %T cannot be assigned to %T",
			value,
			destination,
		)
	}
	return nil
}
