package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/wangle201210/ldap-go/internal/acl"
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
		return server.searchRootDSE(ctx, connection, state, message.ID, request)
	}
	if isSubschemaDN(base) {
		return server.searchSubschema(ctx, connection, state, message.ID, request)
	}
	database := databaseForDN(state.runtime, base)
	if database == nil {
		return server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultReferral},
		)
	}

	limit := effectiveSearchLimit(server.config.MaxSearchEntries, request.SizeLimit)
	deadline := timeLimitDeadline(request.TimeLimit)
	entries := make([]directory.Entry, 0)
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}

	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
		baseEntry, err := tx.Get(base)
		if err != nil {
			if errors.Is(err, storage.ErrEntryNotFound) {
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = server.disclosedAncestor(
					state.runtime,
					tx,
					state.boundDN,
					base,
				)
				return nil
			}
			return err
		}
		baseEntry = withSubschemaReference(baseEntry)
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			baseEntry,
			"entry",
			nil,
			acl.Search,
		) {
			if server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				baseEntry,
				"entry",
				nil,
				acl.Disclose,
			) {
				result.Code = ldapwire.ResultInsufficientAccessRights
			} else {
				result.Code = ldapwire.ResultNoSuchObject
			}
			return nil
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
			entry = withSubschemaReference(entry)
			matches, err := server.filterMatches(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				request.Filter,
			)
			if err != nil {
				result.Code = ldapwire.ResultInappropriateMatching
				result.DiagnosticMessage = err.Error()
				return errStopSearch
			}
			if !matches {
				return nil
			}
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
			if len(entries) >= limit {
				result.Code = ldapwire.ResultSizeLimitExceeded
				return errStopSearch
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				tx,
				state.boundDN,
				entry,
				acl.Read,
				request.TypesOnly,
			)
			selected := server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			)
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
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
) error {
	entry := rootDSE(state.runtime)
	var selected *directory.Entry
	err := server.config.Store.View(ctx, func(tx storage.Reader) error {
		matches, err := server.filterMatches(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			request.Filter,
		)
		if err != nil {
			return err
		}
		if !matches || !server.allowed(
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
		value := server.selectEntry(
			state.runtime,
			readable,
			request.Attributes,
			request.TypesOnly,
		)
		selected = &value
		return nil
	})
	if err != nil {
		return server.writeSearchDone(
			connection,
			messageID,
			ldapwire.ResultError(ldapwire.ResultInappropriateMatching, err.Error()),
		)
	}
	if selected != nil {
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultEntry(messageID, *selected, nil),
		); err != nil {
			return err
		}
	}
	return server.writeSearchDone(connection, messageID, ldapwire.Result{Code: ldapwire.ResultSuccess})
}

func (server *Server) searchSubschema(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
) error {
	entry := server.subschemaEntry(state.runtime)
	candidate, err := directory.ParseDN(entry.DN)
	if err != nil {
		return fmt.Errorf("parse subschema DN: %w", err)
	}
	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return server.writeSearchDone(
			connection,
			messageID,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if !directory.InScope(base, candidate, request.Scope) {
		return server.writeSearchDone(
			connection,
			messageID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
		)
	}
	var selected *directory.Entry
	err = server.config.Store.View(ctx, func(tx storage.Reader) error {
		matches, err := server.filterMatches(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			request.Filter,
		)
		if err != nil {
			return err
		}
		if !matches || !server.allowed(
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
		value := server.selectEntry(
			state.runtime,
			readable,
			request.Attributes,
			request.TypesOnly,
		)
		selected = &value
		return nil
	})
	if err != nil {
		return server.writeSearchDone(
			connection,
			messageID,
			ldapwire.ResultError(ldapwire.ResultInappropriateMatching, err.Error()),
		)
	}
	if selected != nil {
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultEntry(messageID, *selected, nil),
		); err != nil {
			return err
		}
	}
	return server.writeSearchDone(
		connection,
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
}

func rootDSE(runtime *runtimeState) directory.Entry {
	var namingContexts []string
	var configContexts []string
	var monitorContexts []string
	for _, database := range runtime.databases {
		if database.hidden || len(database.suffixes) == 0 {
			continue
		}
		switch {
		case isConfigDatabase(database):
			for _, suffix := range database.suffixes {
				configContexts = append(configContexts, suffix.String())
			}
		case isMonitorDatabase(database):
			for _, suffix := range database.suffixes {
				monitorContexts = append(monitorContexts, suffix.String())
			}
		default:
			for _, suffix := range database.suffixes {
				namingContexts = append(namingContexts, suffix.String())
			}
		}
	}
	sort.Strings(namingContexts)
	sort.Strings(configContexts)
	sort.Strings(monitorContexts)

	entry := directory.Entry{
		DN: "",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: [][]byte{[]byte("top")}},
			{Description: "subschemaSubentry", Values: [][]byte{[]byte("cn=Subschema")}},
			{Description: "supportedLDAPVersion", Values: [][]byte{[]byte("3")}},
			{Description: "vendorName", Values: [][]byte{[]byte("ldap-go")}},
			{Description: "vendorVersion", Values: [][]byte{[]byte("0.1-dev")}},
		},
	}
	if len(namingContexts) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "namingContexts",
			Values:      stringValues(namingContexts...),
		})
	}
	if len(configContexts) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "configContext",
			Values:      stringValues(configContexts...),
		})
	}
	if len(monitorContexts) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "monitorContext",
			Values:      stringValues(monitorContexts...),
		})
	}
	return entry
}

func (server *Server) subschemaEntry(runtime *runtimeState) directory.Entry {
	registry := runtime.schema
	return directory.Entry{
		DN: "cn=Subschema",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "subschema")},
			{Description: "cn", Values: stringValues("Subschema")},
			{
				Description: "attributeTypes",
				Values:      stringValues(registry.AttributeTypeDescriptions()...),
			},
			{
				Description: "objectClasses",
				Values:      stringValues(registry.ObjectClassDescriptions()...),
			},
		},
	}
}

func (server *Server) selectEntry(
	runtime *runtimeState,
	entry directory.Entry,
	requested []string,
	typesOnly bool,
) directory.Entry {
	return entry.SelectWith(requested, typesOnly, runtime.schema.IsOperational)
}

func withSubschemaReference(entry directory.Entry) directory.Entry {
	if entry.HasAttribute("subschemaSubentry") {
		return entry
	}
	entry = entry.Clone()
	entry.ReplaceValues("subschemaSubentry", stringValues("cn=Subschema"))
	return entry
}

func stringValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = []byte(values[i])
	}
	return result
}

func isSubschemaDN(dn directory.DN) bool {
	subSchema, err := directory.ParseDN("cn=Subschema")
	return err == nil && dn.Equal(subSchema)
}

func (server *Server) disclosedAncestor(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	dn directory.DN,
) string {
	current := dn
	for {
		parent, ok := current.Parent()
		if !ok || parent.Depth() == 0 {
			return ""
		}
		if entry, err := reader.Get(parent); err == nil {
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				entry,
				"entry",
				nil,
				acl.Disclose,
			) {
				return entry.DN
			}
			return ""
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
