package server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func (server *Server) handleSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
) error {
	if hasUnsupportedCriticalControl(message.Controls) {
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultUnavailableCriticalExtension, "unsupported critical control"),
		)
	}

	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}

	if base.Depth() == 0 && request.Scope == directory.ScopeBase {
		return server.searchRootDSE(ctx, connection, message.ID, request)
	}

	limit := effectiveSearchLimit(server.config.MaxSearchEntries, request.SizeLimit)
	deadline := timeLimitDeadline(request.TimeLimit)
	entries := make([]directory.Entry, 0)
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}

	err = server.config.Store.View(ctx, func(tx storage.Reader) error {
		if _, err := tx.Get(base); err != nil {
			if errors.Is(err, storage.ErrEntryNotFound) {
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = nearestExistingAncestor(tx, base)
				return nil
			}
			return err
		}

		return tx.ForEach(func(entry directory.Entry) error {
			if expired(deadline) {
				result.Code = ldapwire.ResultTimeLimitExceeded
				return errStopSearch
			}
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !directory.InScope(base, candidate, request.Scope) {
				return nil
			}
			matches, err := request.Filter.Match(entry)
			if err != nil {
				result.Code = ldapwire.ResultInappropriateMatching
				result.DiagnosticMessage = err.Error()
				return errStopSearch
			}
			if !matches {
				return nil
			}
			if len(entries) >= limit {
				result.Code = ldapwire.ResultSizeLimitExceeded
				return errStopSearch
			}
			selected := entry.Select(request.Attributes, request.TypesOnly)
			if !server.isRoot(state.boundDN) {
				selected = selected.Without("userPassword")
			}
			entries = append(entries, selected)
			return nil
		})
	})
	if err != nil && !errors.Is(err, errStopSearch) {
		return fmt.Errorf("search directory: %w", err)
	}

	for _, entry := range entries {
		if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(message.ID, entry, nil)); err != nil {
			return err
		}
	}
	return server.writeSearchDone(connection, message.ID, result)
}

func (server *Server) searchRootDSE(
	ctx context.Context,
	connection net.Conn,
	messageID int64,
	request ldapwire.SearchRequest,
) error {
	var namingContexts []string
	if err := server.config.Store.View(ctx, func(tx storage.Reader) error {
		var err error
		namingContexts, err = tx.NamingContexts()
		return err
	}); err != nil {
		return fmt.Errorf("read naming contexts: %w", err)
	}

	entry := rootDSE(namingContexts)
	matches, err := request.Filter.Match(entry)
	if err != nil {
		return server.writeSearchDone(
			connection,
			messageID,
			ldapwire.ResultError(ldapwire.ResultInappropriateMatching, err.Error()),
		)
	}
	if matches {
		selected := entry.Select(request.Attributes, request.TypesOnly)
		if err := ldapwire.Write(connection, ldapwire.EncodeSearchResultEntry(messageID, selected, nil)); err != nil {
			return err
		}
	}
	return server.writeSearchDone(connection, messageID, ldapwire.Result{Code: ldapwire.ResultSuccess})
}

func rootDSE(namingContexts []string) directory.Entry {
	contextValues := make([][]byte, len(namingContexts))
	for i := range namingContexts {
		contextValues[i] = []byte(namingContexts[i])
	}
	return directory.Entry{
		DN: "",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top")}},
			{Description: "supportedLDAPVersion", Values: [][]byte{[]byte("3")}},
			{Description: "namingContexts", Values: contextValues},
			{Description: "vendorName", Values: [][]byte{[]byte("ldap-go")}},
			{Description: "vendorVersion", Values: [][]byte{[]byte("0.1-dev")}},
		},
	}
}

func nearestExistingAncestor(reader storage.Reader, dn directory.DN) string {
	current := dn
	for {
		parent, ok := current.Parent()
		if !ok || parent.Depth() == 0 {
			return ""
		}
		if entry, err := reader.Get(parent); err == nil {
			return entry.DN
		}
		current = parent
	}
}

func (server *Server) writeSearchDone(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
) error {
	return ldapwire.Write(connection, ldapwire.EncodeSearchResultDone(messageID, result, nil))
}

var errStopSearch = errors.New("stop search")
