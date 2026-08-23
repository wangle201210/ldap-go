package server

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

type sqlBackendAttributeSelection struct {
	all            bool
	allUser        bool
	allOperational bool
	attributes     []string
}

func (selection *sqlBackendAttributeSelection) includes(
	registry *schema.Registry,
	attribute string,
) bool {
	if selection == nil || selection.all {
		return true
	}
	if selection.allOperational && registry.IsOperational(attribute) {
		return true
	}
	if selection.allUser && !registry.IsOperational(attribute) {
		return true
	}
	for _, requested := range selection.attributes {
		if registry.AttributeDescriptionSubtype(attribute, requested) {
			return true
		}
	}
	return false
}

func (reader *sqlBackendReader) sqlBackendSearchRequirements() (
	sqlBackendSearchRequirements,
	bool,
) {
	if reader.ctx == nil {
		return sqlBackendSearchRequirements{}, false
	}
	requirements, specified := reader.ctx.Value(
		sqlBackendSearchRequirementsContextKey{},
	).(sqlBackendSearchRequirements)
	return requirements, specified
}

func (reader *sqlBackendReader) sqlBackendAttributeSelection() (
	*sqlBackendAttributeSelection,
	bool,
	error,
) {
	requirements, specified := reader.sqlBackendSearchRequirements()
	if !specified || reader.configuration.fetchAllAttrs {
		return nil, specified, nil
	}
	selection := &sqlBackendAttributeSelection{}
	if len(requirements.attributes) == 0 {
		selection.allUser = true
	}
	for _, raw := range requirements.attributes {
		attribute := strings.TrimSpace(raw)
		switch attribute {
		case "":
			continue
		case "*":
			selection.allUser = true
		case "+":
			selection.allOperational = true
		case "1.1":
			continue
		default:
			selection.attributes = append(selection.attributes, attribute)
		}
	}
	if requirements.hasFilter {
		if sqlBackendCollectFilterAttributes(requirements.filter, selection) {
			selection.all = true
		}
	}
	for _, attribute := range reader.configuration.fetchAttrs {
		switch attribute {
		case "*":
			selection.allUser = true
		case "+":
			selection.allOperational = true
		default:
			selection.attributes = append(selection.attributes, attribute)
		}
	}
	selection.attributes = uniqueSQLAttributeDescriptions(selection.attributes)
	return selection, true, nil
}

func sqlBackendCollectFilterAttributes(
	filter directory.Filter,
	selection *sqlBackendAttributeSelection,
) bool {
	if filter.Attribute != "" {
		selection.attributes = append(selection.attributes, filter.Attribute)
	} else if filter.Kind == directory.FilterExtensible {
		return true
	}
	for _, child := range filter.Children {
		if sqlBackendCollectFilterAttributes(child, selection) {
			return true
		}
	}
	return false
}

func uniqueSQLAttributeDescriptions(attributes []string) []string {
	result := make([]string, 0, len(attributes))
	seen := make(map[string]struct{}, len(attributes))
	for _, attribute := range attributes {
		key := strings.ToLower(strings.TrimSpace(attribute))
		if key == "" {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, strings.TrimSpace(attribute))
	}
	return result
}

func (configuration *sqlBackendRuntimeConfiguration) prepareBaseObject() error {
	if configuration.registry == nil {
		return errors.New("SQL-backend schema registry is not initialized")
	}
	for _, attribute := range configuration.fetchAttrs {
		if attribute == "*" || attribute == "+" {
			continue
		}
		if _, found := configuration.registry.AttributeType(attribute); !found {
			return fmt.Errorf(
				"SQL-backend olcSqlFetchAttrs references undefined attribute %q",
				attribute,
			)
		}
	}
	if configuration.baseObject == "" {
		configuration.baseObjectEntry = nil
		return nil
	}
	dn, err := configuration.registry.NormalizeDN(configuration.baseObjectSuffix)
	if err != nil {
		return fmt.Errorf("SQL-backend olcSqlBaseObject suffix: %w", err)
	}
	entry := directory.Entry{DN: dn.String()}
	appendSQLAttributeValue(&entry, "objectClass", []byte("extensibleObject"))
	appendSQLAttributeValue(&entry, "description", []byte("builtin baseObject for back-sql"))
	appendSQLAttributeValue(
		&entry,
		"description",
		[]byte("all entries mapped in table \"ldap_entries\" must have \"baseObject\" in the \"parent\" column"),
	)
	for _, value := range dn.RDNValues() {
		if err := configuration.registry.ValidateAttributeValue(value.Type, value.Value); err != nil {
			return fmt.Errorf("SQL-backend olcSqlBaseObject naming value: %w", err)
		}
		appendSQLAttributeValue(&entry, value.Type, value.Value)
	}
	configuration.baseObjectEntry = &entry
	return nil
}

func (configuration *sqlBackendRuntimeConfiguration) baseObjectClone() *directory.Entry {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	if configuration.baseObjectEntry == nil {
		return nil
	}
	entry := configuration.baseObjectEntry.Clone()
	return &entry
}

func (configuration *sqlBackendRuntimeConfiguration) baseObjectForDN(
	dn directory.DN,
) (directory.Entry, bool, error) {
	entry := configuration.baseObjectClone()
	if entry == nil {
		return directory.Entry{}, false, nil
	}
	requested, err := configuration.registry.NormalizeDN(dn.String())
	if err != nil {
		return directory.Entry{}, false, err
	}
	base, err := configuration.registry.NormalizeDN(entry.DN)
	if err != nil {
		return directory.Entry{}, false, err
	}
	return *entry, requested.Equal(base), nil
}

func (configuration *sqlBackendRuntimeConfiguration) baseObjectMatches(
	dn directory.DN,
) bool {
	_, found, err := configuration.baseObjectForDN(dn)
	return err == nil && found
}

func (reader *sqlBackendReader) scanSQLBackendEntryIDs(
	queryer sqlBackendQueryer,
) ([]sqlEntryID, error) {
	return reader.querySQLBackendEntryIDs(
		queryer,
		"SELECT id,keyval,oc_map_id,dn FROM ldap_entries ORDER BY id",
	)
}

func (reader *sqlBackendReader) querySQLBackendEntryIDs(
	queryer sqlBackendQueryer,
	query string,
	arguments ...any,
) ([]sqlEntryID, error) {
	rows, err := queryer.QueryContext(reader.ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("SQL-backend candidate query: %w", err)
	}
	defer rows.Close()
	var ids []sqlEntryID
	for rows.Next() {
		var id sqlEntryID
		if err := rows.Scan(&id.id, &id.keyValue, &id.objectClassID, &id.dn); err != nil {
			return nil, fmt.Errorf("SQL-backend candidate row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SQL-backend candidate rows: %w", err)
	}
	return ids, nil
}

type sqlBackendCandidateSet map[int64]sqlEntryID

func (reader *sqlBackendReader) sqlBackendFilterCandidates(
	queryer sqlBackendQueryer,
) ([]sqlEntryID, bool, error) {
	requirements, specified := reader.sqlBackendSearchRequirements()
	if !specified || !requirements.hasFilter {
		return nil, false, nil
	}
	candidates, planned, err := reader.planSQLBackendFilter(queryer, requirements.filter)
	if err != nil || !planned {
		return nil, planned, err
	}
	ids := make([]sqlEntryID, 0, len(candidates))
	for _, id := range candidates {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left].id < ids[right].id })
	return ids, true, nil
}

func (reader *sqlBackendReader) planSQLBackendFilter(
	queryer sqlBackendQueryer,
	filter directory.Filter,
) (sqlBackendCandidateSet, bool, error) {
	switch filter.Kind {
	case directory.FilterEquality, directory.FilterPresent:
		return reader.planSQLBackendPrimitive(queryer, filter)
	case directory.FilterAnd:
		var result sqlBackendCandidateSet
		plannedAny := false
		for _, child := range filter.Children {
			candidates, planned, err := reader.planSQLBackendFilter(queryer, child)
			if err != nil {
				return nil, false, err
			}
			if !planned {
				continue
			}
			if !plannedAny {
				result = cloneSQLBackendCandidateSet(candidates)
				plannedAny = true
				continue
			}
			for id := range result {
				if _, found := candidates[id]; !found {
					delete(result, id)
				}
			}
		}
		return result, plannedAny, nil
	case directory.FilterOr:
		result := make(sqlBackendCandidateSet)
		for _, child := range filter.Children {
			candidates, planned, err := reader.planSQLBackendFilter(queryer, child)
			if err != nil {
				return nil, false, err
			}
			if !planned {
				return nil, false, nil
			}
			for id, candidate := range candidates {
				result[id] = candidate
			}
		}
		return result, true, nil
	default:
		return nil, false, nil
	}
}

func cloneSQLBackendCandidateSet(source sqlBackendCandidateSet) sqlBackendCandidateSet {
	result := make(sqlBackendCandidateSet, len(source))
	for id, candidate := range source {
		result[id] = candidate
	}
	return result
}

func (reader *sqlBackendReader) planSQLBackendPrimitive(
	queryer sqlBackendQueryer,
	filter directory.Filter,
) (sqlBackendCandidateSet, bool, error) {
	attribute, found := reader.configuration.registry.AttributeType(filter.Attribute)
	if !found {
		return make(sqlBackendCandidateSet), true, nil
	}
	switch strings.ToLower(attribute.OID) {
	case "2.5.4.0":
		return reader.planSQLBackendObjectClass(queryer, filter, false)
	case "2.5.21.9":
		return reader.planSQLBackendObjectClass(queryer, filter, true)
	}
	return reader.planSQLBackendMappedAttribute(queryer, filter)
}

func (reader *sqlBackendReader) planSQLBackendObjectClass(
	queryer sqlBackendQueryer,
	filter directory.Filter,
	structuralOnly bool,
) (sqlBackendCandidateSet, bool, error) {
	if filter.Kind == directory.FilterPresent {
		ids, err := reader.scanSQLBackendEntryIDs(queryer)
		return sqlBackendCandidateSetFromIDs(ids), true, err
	}
	requested, found := reader.configuration.registry.ObjectClass(string(filter.Assertion))
	if !found {
		return make(sqlBackendCandidateSet), true, nil
	}
	result := make(sqlBackendCandidateSet)
	for _, mapping := range reader.configuration.objectClasses {
		matches := strings.EqualFold(mapping.name, requested.Name()) ||
			strings.EqualFold(mapping.name, requested.OID)
		if !structuralOnly && !matches {
			entry := directory.Entry{Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      [][]byte{[]byte(mapping.name)},
			}}}
			matches = reader.configuration.registry.EntryHasObjectClass(entry, requested.Name())
		}
		if !matches {
			continue
		}
		ids, err := reader.querySQLBackendEntryIDs(
			queryer,
			"SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE oc_map_id=? ORDER BY id",
			mapping.id,
		)
		if err != nil {
			return nil, false, err
		}
		mergeSQLBackendCandidateIDs(result, ids)
	}
	if !structuralOnly {
		ids, err := reader.querySQLBackendEntryIDs(
			queryer,
			"SELECT DISTINCT ldap_entries.id,ldap_entries.keyval,"+
				"ldap_entries.oc_map_id,ldap_entries.dn FROM ldap_entries "+
				"JOIN ldap_entry_objclasses ON "+
				"ldap_entry_objclasses.entry_id=ldap_entries.id "+
				"WHERE UPPER(ldap_entry_objclasses.oc_name)=UPPER(?) "+
				"ORDER BY ldap_entries.id",
			requested.Name(),
		)
		if err != nil {
			return nil, false, err
		}
		mergeSQLBackendCandidateIDs(result, ids)
	}
	return result, true, nil
}

func (reader *sqlBackendReader) planSQLBackendMappedAttribute(
	queryer sqlBackendQueryer,
	filter directory.Filter,
) (sqlBackendCandidateSet, bool, error) {
	effective, found, err := reader.configuration.registry.EffectiveAttributeType(filter.Attribute)
	if err != nil {
		return nil, false, err
	}
	if !found || filter.Kind == directory.FilterEquality && effective.Equality == "" {
		return make(sqlBackendCandidateSet), true, nil
	}
	type mappedQuery struct {
		objectClass *sqlObjectClassMapping
		mapping     sqlAttributeMapping
	}
	var queries []mappedQuery
	foundMapping := false
	for _, objectClass := range reader.configuration.objectClasses {
		for _, mappings := range objectClass.attributes {
			for _, mapping := range mappings {
				if !reader.configuration.registry.AttributeDescriptionSubtype(
					mapping.name,
					filter.Attribute,
				) {
					continue
				}
				foundMapping = true
				query := mappedQuery{objectClass: objectClass, mapping: mapping}
				if filter.Kind == directory.FilterEquality {
					// Mapping metadata does not prove the SQL column type or
					// comparison semantics. Even byte-identical TEXT and BLOB
					// values compare unequal in SQLite, so an equality predicate
					// could omit entries that satisfy the LDAP matching rule.
					return nil, false, nil
				}
				queries = append(queries, query)
			}
		}
	}
	if !foundMapping {
		// Operational attributes and overlays may synthesize values that are
		// intentionally absent from ldap_attr_mappings.
		return nil, false, nil
	}
	result := make(sqlBackendCandidateSet)
	for _, planned := range queries {
		fromTables := mergeSQLFromTable(
			planned.mapping.fromTables,
			planned.objectClass.keyTable,
		)
		query := "SELECT DISTINCT ldap_entries.id,ldap_entries.keyval," +
			"ldap_entries.oc_map_id,ldap_entries.dn FROM ldap_entries," +
			fromTables + " WHERE ldap_entries.oc_map_id=? AND " +
			planned.objectClass.keyTable + "." + planned.objectClass.keyColumn +
			"=ldap_entries.keyval"
		arguments := []any{planned.objectClass.id}
		if planned.mapping.joinWhere != "" {
			query += " AND " + planned.mapping.joinWhere
		}
		if filter.Kind == directory.FilterPresent {
			query += " AND " + planned.mapping.selectExpression + " IS NOT NULL"
		}
		query += " ORDER BY ldap_entries.id"
		ids, err := reader.querySQLBackendEntryIDs(queryer, query, arguments...)
		if err != nil {
			return nil, false, err
		}
		mergeSQLBackendCandidateIDs(result, ids)
	}
	return result, true, nil
}

func sqlBackendCandidateSetFromIDs(ids []sqlEntryID) sqlBackendCandidateSet {
	result := make(sqlBackendCandidateSet, len(ids))
	mergeSQLBackendCandidateIDs(result, ids)
	return result
}

func mergeSQLBackendCandidateIDs(result sqlBackendCandidateSet, ids []sqlEntryID) {
	for _, id := range ids {
		result[id.id] = id
	}
}
