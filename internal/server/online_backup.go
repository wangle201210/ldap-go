package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const onlineBackupOID = "1.3.6.1.4.1.4203.666.11.21"

type OnlineBackupReport struct {
	Filename string `json:"filename"`
	Entries  int    `json:"entries"`
	FileSize int64  `json:"file_size"`
}

func (server *Server) handleOnlineBackup(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	writeResult := func(result ldapwire.Result, report *OnlineBackupReport) error {
		var value []byte
		if report != nil {
			value, _ = json.Marshal(report)
		}
		return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			message.ID,
			result,
			onlineBackupOID,
			value,
			nil,
		))
	}
	if request.HasValue {
		return writeResult(
			ldapwire.ResultError(ldapwire.ResultProtocolError, "online backup request value must be absent"),
			nil,
		)
	}
	if server.config.OnlineBackup == nil || server.config.OnlineBackupDir == "" {
		return writeResult(
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "online backup is not configured"),
			nil,
		)
	}
	if state == nil || state.connection == nil || state.connection.LocalAddr() == nil ||
		state.connection.LocalAddr().Network() != "unix" {
		return writeResult(
			ldapwire.ResultError(ldapwire.ResultConfidentialityRequired, "online backup requires LDAPI"),
			nil,
		)
	}
	if state.boundDN == "" || !server.isRoot(state.runtime, state.boundDN, "", "children") {
		return writeResult(
			ldapwire.ResultError(ldapwire.ResultInsufficientAccessRights, "database root authentication is required"),
			nil,
		)
	}
	if !server.onlineBackupMu.TryLock() {
		return writeResult(ldapwire.ResultError(ldapwire.ResultBusy, "online backup is already running"), nil)
	}
	defer server.onlineBackupMu.Unlock()

	filename, err := server.onlineBackupFilename()
	if err != nil {
		return writeResult(ldapwire.ResultError(ldapwire.ResultOther, "generate online backup name"), nil)
	}
	path := filepath.Join(server.config.OnlineBackupDir, filename)
	report, err := server.config.OnlineBackup(ctx, path)
	if err != nil {
		server.config.Logger.Error("online backup failed", "error", err)
		return writeResult(ldapwire.ResultError(ldapwire.ResultOther, "online backup failed"), nil)
	}
	return writeResult(ldapwire.Result{Code: ldapwire.ResultSuccess}, &OnlineBackupReport{
		Filename: filename,
		Entries:  report.Entries,
		FileSize: report.FileSize,
	})
}

func (server *Server) onlineBackupFilename() (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"ldap-go-%s-%s.db",
		server.clock().UTC().Format("20060102T150405.000000000Z"),
		hex.EncodeToString(random),
	), nil
}

func onlineBackupConfigured(config Config) bool {
	return config.OnlineBackup != nil && config.OnlineBackupDir != ""
}

type OnlineBackupFunc func(context.Context, string) (storage.CheckReport, error)
