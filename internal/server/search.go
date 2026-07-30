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
	routes := databaseSearchRoutes(state.runtime.databases, base, request.Scope)
	if len(routes) == 0 {
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
		primary := routes[0]
		primaryDatabase := &state.runtime.databases[primary.databaseIndex]
		primaryReader := storage.ReaderInPartition(reader, primaryDatabase.partition)
		baseEntry, err := primaryReader.Get(base)
		if err != nil {
			if errors.Is(err, storage.ErrEntryNotFound) {
				result.Code = ldapwire.ResultNoSuchObject
				result.MatchedDN = server.disclosedAncestor(
					state.runtime,
					primaryReader,
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
			primaryReader,
			state.boundDN,
			baseEntry,
			"entry",
			nil,
			acl.Search,
		) {
			if server.allowed(
				state.runtime,
				primaryReader,
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

		for routeIndex, route := range routes {
			database := &state.runtime.databases[route.databaseIndex]
			tx := storage.ReaderInPartition(reader, database.partition)
			if routeIndex > 0 {
				routeBaseEntry, err := tx.Get(route.base)
				if errors.Is(err, storage.ErrEntryNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				routeBaseEntry = withSubschemaReference(routeBaseEntry)
				if !server.allowed(
					state.runtime,
					tx,
					state.boundDN,
					routeBaseEntry,
					"entry",
					nil,
					acl.Search,
				) {
					continue
				}
			}

			err := tx.ForEach(func(entry directory.Entry) error {
				if expired(deadline) {
					result.Code = ldapwire.ResultTimeLimitExceeded
					return errStopSearch
				}
				candidate, err := directory.ParseDN(entry.DN)
				if err != nil {
					return err
				}
				if !directory.InScope(route.base, candidate, route.scope) {
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
			if err != nil {
				return err
			}
		}
		return nil
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

type databaseSearchRoute struct {
	databaseIndex int
	base          directory.DN
	scope         directory.Scope
}

func databaseSearchRoutes(
	databases []runtimeDatabase,
	base directory.DN,
	scope directory.Scope,
) []databaseSearchRoute {
	primaryIndex := databaseIndexForDN(databases, base)
	if primaryIndex < 0 {
		return nil
	}

	superiorIndex := primaryIndex
	if databases[primaryIndex].subordinate {
		superiorIndex = glueSuperiorDatabaseIndex(databases, primaryIndex)
		if superiorIndex < 0 {
			return nil
		}
	}
	routes := []databaseSearchRoute{{
		databaseIndex: primaryIndex,
		base:          base,
		scope:         scope,
	}}
	if scope == directory.ScopeBase {
		return routes
	}

	var subordinateRoutes []databaseSearchRoute
	for index := range databases {
		database := &databases[index]
		if index == primaryIndex ||
			database.hidden ||
			database.disabled ||
			!database.subordinate ||
			len(database.suffixes) != 1 ||
			glueSuperiorDatabaseIndex(databases, index) != superiorIndex {
			continue
		}

		suffix := database.suffixes[0]
		route := databaseSearchRoute{
			databaseIndex: index,
			base:          suffix,
		}
		switch scope {
		case directory.ScopeSingleLevel:
			parent, ok := suffix.Parent()
			if !ok || !parent.Equal(base) {
				continue
			}
			route.scope = directory.ScopeBase
		case directory.ScopeWholeSubtree:
			if !base.Equal(suffix) && !base.AncestorOf(suffix) {
				continue
			}
			route.scope = directory.ScopeWholeSubtree
		default:
			continue
		}
		subordinateRoutes = append(subordinateRoutes, route)
	}
	sort.SliceStable(subordinateRoutes, func(i, j int) bool {
		return subordinateRoutes[i].base.Depth() >
			subordinateRoutes[j].base.Depth()
	})
	return append(routes, subordinateRoutes...)
}

func (server *Server) searchRootDSE(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
) error {
	entry := server.rootDSE(state.runtime)
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

func (server *Server) rootDSE(runtime *runtimeState) directory.Entry {
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
			if database.subordinate && !database.advertise {
				continue
			}
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
	supportedExtensions := []string{passwordModifyOID}
	if server.secureTransport != nil {
		supportedExtensions = append([]string{startTLSOID}, supportedExtensions...)
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "supportedExtension",
		Values:      stringValues(supportedExtensions...),
	})
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
