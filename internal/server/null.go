package server

import (
	"context"
	"net"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func nullSearchEntry(database runtimeDatabase) (directory.Entry, bool) {
	if !database.nullDoSearch || len(database.suffixes) == 0 {
		return directory.Entry{}, false
	}
	suffix := database.suffixes[0]
	rdn := suffix.RDNValues()
	if len(rdn) == 0 {
		return directory.Entry{}, false
	}
	entry := directory.Entry{
		DN: suffix.String(),
		Attributes: []directory.Attribute{
			{Description: rdn[0].Type, Values: [][]byte{rdn[0].Value}},
			{Description: "objectClass", Values: stringValues("extensibleObject")},
			{Description: "entryDN", Values: stringValues(suffix.String())},
		},
	}
	return withSubschemaReference(entry), true
}

func (server *Server) searchNull(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	database runtimeDatabase,
	controls requestControls,
	paging *pagedSearchContext,
	sorting *serverSideSortContext,
) error {
	var entries []directory.Entry
	if entry, exists := nullSearchEntry(database); exists {
		err := server.config.Store.View(ctx, func(reader storage.Reader) error {
			tx := storage.ReaderInPartition(reader, database.partition)
			if !server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				"entry",
				nil,
				acl.Read,
			) {
				return nil
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				acl.Read,
				request.TypesOnly,
			)
			entries = []directory.Entry{server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			)}
			return nil
		})
		if err != nil {
			return server.internalOperationError(
				connection,
				messageID,
				ldapwire.ApplicationSearchResultDone,
				err,
			)
		}
	}

	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	if controls.assertion != nil {
		result.Code = ldapwire.ResultAssertionFailed
	}
	return server.writeSearchResult(
		connection,
		messageID,
		state,
		paging,
		sorting,
		entries,
		result,
		pagedSearchCursor{},
		false,
	)
}

func (server *Server) writeNullOperationResult(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	responseTag uint64,
	dn directory.DN,
	controls requestControls,
	preRead,
	postRead bool,
) error {
	if controls.assertion != nil {
		return server.writeOperationResult(
			connection,
			messageID,
			responseTag,
			ldapwire.Result{Code: ldapwire.ResultAssertionFailed},
		)
	}

	var responseControls []ldapwire.Control
	if preRead || postRead {
		entry := withSubschemaReference(directory.Entry{
			DN: dn.String(),
			Attributes: []directory.Attribute{{
				Description: "entryDN",
				Values:      stringValues(dn.String()),
			}},
		})
		err := server.config.Store.View(ctx, func(reader storage.Reader) error {
			if preRead {
				control, err := server.readResponseControl(
					state.runtime,
					reader,
					state.boundDN,
					entry,
					controls.preRead,
					preReadControlOID,
				)
				if err != nil {
					return err
				}
				if control != nil {
					responseControls = append(responseControls, *control)
				}
			}
			if postRead {
				control, err := server.readResponseControl(
					state.runtime,
					reader,
					state.boundDN,
					entry,
					controls.postRead,
					postReadControlOID,
				)
				if err != nil {
					return err
				}
				if control != nil {
					responseControls = append(responseControls, *control)
				}
			}
			return nil
		})
		if err != nil {
			return server.finishOperationWithControls(
				connection,
				messageID,
				responseTag,
				err,
				responseControls,
			)
		}
	}

	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	if controls.noOp {
		result.Code = ldapwire.ResultNoOperation
	}
	return server.writeOperationResultWithControls(
		connection,
		messageID,
		responseTag,
		result,
		responseControls,
	)
}

func noOperationFailure() error {
	return operationFailed(ldapwire.ResultNoOperation, "")
}
