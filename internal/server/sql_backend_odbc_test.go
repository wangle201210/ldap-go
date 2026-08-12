package server

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/slingdata-io/godbc"
)

func TestSQLBackendODBCConnectorAdaptsStandardOutputParameters(t *testing.T) {
	state := &sqlBackendODBCAdapterTestState{}
	database := sql.OpenDB(&sqlBackendODBCConnector{
		connector: sqlBackendODBCAdapterTestConnector{state: state},
	})
	defer database.Close()

	var output int64
	if _, err := database.ExecContext(
		context.Background(),
		"call procedure",
		sql.Out{Dest: &output},
		"input",
	); err != nil {
		t.Fatalf("ExecContext(): %v", err)
	}
	if output != 42 {
		t.Fatalf("output = %d, want 42", output)
	}
	if !state.sawOutput || state.input != "input" {
		t.Fatalf("driver arguments = output:%t input:%q", state.sawOutput, state.input)
	}
}

func TestSQLBackendODBCOutputValidation(t *testing.T) {
	tests := []sql.Out{
		{},
		{Dest: int64(0)},
		{Dest: (*int64)(nil)},
		{Dest: new(uint64)},
		{Dest: new(sql.NullInt64)},
	}
	for _, output := range tests {
		if err := validateSQLBackendODBCOutput(output); err == nil {
			t.Fatalf("validateSQLBackendODBCOutput(%#v) succeeded", output)
		}
	}
}

func TestSQLBackendODBCRejectsNullOrMissingOutput(t *testing.T) {
	var output int64
	if err := assignSQLBackendODBCOutput(&output, nil); err == nil {
		t.Fatal("nil ODBC output was accepted")
	}
}

func TestSQLBackendODBCRejectsNamedOutput(t *testing.T) {
	var output int64
	_, _, err := convertSQLBackendODBCArguments([]driver.NamedValue{{
		Name:  "result",
		Value: sql.Out{Dest: &output},
	}})
	if err == nil {
		t.Fatal("named ODBC output was accepted")
	}
}

type sqlBackendODBCAdapterTestState struct {
	sawOutput bool
	input     string
}

type sqlBackendODBCAdapterTestConnector struct {
	state *sqlBackendODBCAdapterTestState
}

func (connector sqlBackendODBCAdapterTestConnector) Connect(
	context.Context,
) (driver.Conn, error) {
	return &sqlBackendODBCAdapterTestConnection{state: connector.state}, nil
}

func (connector sqlBackendODBCAdapterTestConnector) Driver() driver.Driver {
	return sqlBackendODBCAdapterTestDriver{state: connector.state}
}

type sqlBackendODBCAdapterTestDriver struct {
	state *sqlBackendODBCAdapterTestState
}

func (driver sqlBackendODBCAdapterTestDriver) Open(string) (driver.Conn, error) {
	return &sqlBackendODBCAdapterTestConnection{state: driver.state}, nil
}

type sqlBackendODBCAdapterTestConnection struct {
	state *sqlBackendODBCAdapterTestState
}

func (connection *sqlBackendODBCAdapterTestConnection) Prepare(
	string,
) (driver.Stmt, error) {
	return nil, errors.New("prepare is not implemented")
}

func (connection *sqlBackendODBCAdapterTestConnection) Close() error {
	return nil
}

func (connection *sqlBackendODBCAdapterTestConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not implemented")
}

func (connection *sqlBackendODBCAdapterTestConnection) CheckNamedValue(
	*driver.NamedValue,
) error {
	return nil
}

func (connection *sqlBackendODBCAdapterTestConnection) ExecContext(
	_ context.Context,
	_ string,
	arguments []driver.NamedValue,
) (driver.Result, error) {
	if len(arguments) != 2 {
		return nil, errors.New("unexpected argument count")
	}
	output, ok := arguments[0].Value.(godbc.OutputParam)
	if !ok || output.Direction != godbc.ParamOutput {
		return nil, errors.New("first argument is not a godbc output parameter")
	}
	connection.state.sawOutput = true
	connection.state.input, _ = arguments[1].Value.(string)
	return sqlBackendODBCAdapterTestResult{}, nil
}

type sqlBackendODBCAdapterTestResult struct{}

func (sqlBackendODBCAdapterTestResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (sqlBackendODBCAdapterTestResult) RowsAffected() (int64, error) {
	return 1, nil
}

func (sqlBackendODBCAdapterTestResult) OutputParam(index int) any {
	if index == 0 {
		return int64(42)
	}
	return nil
}
