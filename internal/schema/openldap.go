package schema

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type LoadResult struct {
	Syntaxes       int
	AttributeTypes int
	ObjectClasses  int
	ContentRules   int
}

var openLDAPBuiltinObjectIdentifiers = []string{
	"OLcfg 1.3.6.1.4.1.4203.1.12.2",
	"OLcfgAt OLcfg:3",
	"OLcfgGlAt OLcfgAt:0",
	"OLcfgBkAt OLcfgAt:1",
	"OLcfgDbAt OLcfgAt:2",
	"OLcfgOvAt OLcfgAt:3",
	"OLcfgCtAt OLcfgAt:4",
	"OLcfgOc OLcfg:4",
	"OLcfgGlOc OLcfgOc:0",
	"OLcfgBkOc OLcfgOc:1",
	"OLcfgDbOc OLcfgOc:2",
	"OLcfgOvOc OLcfgOc:3",
	"OLcfgCtOc OLcfgOc:4",
	"OMsyn 1.3.6.1.4.1.1466.115.121.1",
	"OMsBoolean OMsyn:7",
	"OMsDN OMsyn:12",
	"OMsDirectoryString OMsyn:15",
	"OMsIA5String OMsyn:26",
	"OMsInteger OMsyn:27",
	"OMsOID OMsyn:38",
	"OMsOctetString OMsyn:40",
}

// LoadOpenLDAPConfig loads schema descriptions from cn=config-style entries.
// Attribute types are registered before object classes regardless of entry
// order, matching slapd's schema dependency model.
func LoadOpenLDAPConfig(
	ctx context.Context,
	store storage.Store,
	registry *Registry,
) (LoadResult, error) {
	var result LoadResult
	err := store.View(ctx, func(reader storage.Reader) error {
		var err error
		result, err = LoadOpenLDAPConfigReader(reader, registry)
		return err
	})
	return result, err
}

func LoadOpenLDAPConfigReader(
	reader storage.Reader,
	registry *Registry,
) (LoadResult, error) {
	if registry == nil {
		return LoadResult{}, fmt.Errorf("schema registry is required")
	}
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return LoadResult{}, err
	}

	var attributeDescriptions []string
	var objectClassDescriptions []string
	var contentRuleDescriptions []string
	var objectIdentifierEntries []openLDAPObjectIdentifierEntry
	var syntaxEntries []openLDAPObjectIdentifierEntry
	var attributeOptionDescriptions []string
	if err := reader.ForEachIn(storage.OpenLDAPConfigPartition, func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse configuration entry DN %q: %w", entry.DN, err)
		}
		if !configSuffix.Equal(entryDN) && !configSuffix.AncestorOf(entryDN) {
			return nil
		}
		objectIdentifiers := entry.Values("olcObjectIdentifier")
		if len(objectIdentifiers) > 0 {
			descriptions := make([]string, len(objectIdentifiers))
			for index, value := range objectIdentifiers {
				descriptions[index] = string(value)
			}
			objectIdentifierEntries = append(
				objectIdentifierEntries,
				openLDAPObjectIdentifierEntry{
					order:        openLDAPConfigDNOrder(entryDN),
					descriptions: descriptions,
				},
			)
		}
		ldapSyntaxes := entry.Values("olcLdapSyntaxes")
		if len(ldapSyntaxes) > 0 {
			descriptions := make([]string, len(ldapSyntaxes))
			for index, value := range ldapSyntaxes {
				descriptions[index] = string(value)
			}
			syntaxEntries = append(
				syntaxEntries,
				openLDAPObjectIdentifierEntry{
					order:        openLDAPConfigDNOrder(entryDN),
					descriptions: descriptions,
				},
			)
		}
		for _, value := range entry.Values("olcAttributeOptions") {
			attributeOptionDescriptions = append(
				attributeOptionDescriptions,
				string(value),
			)
		}
		for _, value := range entry.Values("olcAttributeTypes") {
			attributeDescriptions = append(attributeDescriptions, string(value))
		}
		for _, value := range entry.Values("olcObjectClasses") {
			objectClassDescriptions = append(objectClassDescriptions, string(value))
		}
		for _, value := range entry.Values("olcDitContentRules") {
			contentRuleDescriptions = append(
				contentRuleDescriptions,
				string(value),
			)
		}
		return nil
	}); err != nil {
		return LoadResult{}, fmt.Errorf("scan OpenLDAP schema entries: %w", err)
	}
	if err := registry.configureAttributeOptions(attributeOptionDescriptions); err != nil {
		return LoadResult{}, fmt.Errorf("parse olcAttributeOptions: %w", err)
	}
	resolver := newOpenLDAPObjectIdentifierResolver()
	for _, definition := range openLDAPBuiltinObjectIdentifiers {
		if err := resolver.add(definition); err != nil {
			return LoadResult{}, fmt.Errorf(
				"initialize OpenLDAP object identifier %q: %w",
				definition,
				err,
			)
		}
	}
	sort.SliceStable(objectIdentifierEntries, func(left, right int) bool {
		return compareOpenLDAPConfigDNOrder(
			objectIdentifierEntries[left].order,
			objectIdentifierEntries[right].order,
		) < 0
	})
	for _, entry := range objectIdentifierEntries {
		for _, definition := range entry.descriptions {
			if err := resolver.add(definition); err != nil {
				return LoadResult{}, fmt.Errorf(
					"parse olcObjectIdentifier %q: %w",
					definition,
					err,
				)
			}
		}
	}

	result := LoadResult{}
	sort.SliceStable(syntaxEntries, func(left, right int) bool {
		return compareOpenLDAPConfigDNOrder(
			syntaxEntries[left].order,
			syntaxEntries[right].order,
		) < 0
	})
	for _, entry := range syntaxEntries {
		descriptions, err := orderOpenLDAPSchemaValues(entry.descriptions)
		if err != nil {
			return LoadResult{}, fmt.Errorf("order olcLdapSyntaxes: %w", err)
		}
		for _, description := range descriptions {
			ldapSyntax, err := parseLDAPSyntax(description, resolver.resolve)
			if err != nil {
				return LoadResult{}, fmt.Errorf("parse olcLdapSyntaxes: %w", err)
			}
			if err := registry.registerLDAPSyntax(ldapSyntax); err != nil {
				return LoadResult{}, fmt.Errorf(
					"register olcLdapSyntaxes %q: %w",
					ldapSyntax.OID,
					err,
				)
			}
			result.Syntaxes++
		}
	}
	for _, description := range attributeDescriptions {
		attribute, err := parseAttributeType(description, resolver.resolve)
		if err != nil {
			return LoadResult{}, fmt.Errorf("parse olcAttributeTypes: %w", err)
		}
		if err := registry.UpsertAttributeType(attribute); err != nil {
			return LoadResult{}, fmt.Errorf("register olcAttributeTypes %q: %w", attribute.Name(), err)
		}
		result.AttributeTypes++
	}
	for _, description := range objectClassDescriptions {
		objectClass, err := parseObjectClass(description, resolver.resolve)
		if err != nil {
			return LoadResult{}, fmt.Errorf("parse olcObjectClasses: %w", err)
		}
		if err := registry.UpsertObjectClass(objectClass); err != nil {
			return LoadResult{}, fmt.Errorf("register olcObjectClasses %q: %w", objectClass.Name(), err)
		}
		result.ObjectClasses++
	}
	for _, description := range contentRuleDescriptions {
		contentRule, err := parseDITContentRule(description, resolver.resolve)
		if err != nil {
			return LoadResult{}, fmt.Errorf(
				"parse olcDitContentRules: %w",
				err,
			)
		}
		if err := registry.RegisterDITContentRule(contentRule); err != nil {
			return LoadResult{}, fmt.Errorf(
				"register olcDitContentRules %q: %w",
				contentRule.Name(),
				err,
			)
		}
		result.ContentRules++
	}
	return result, nil
}

type openLDAPObjectIdentifierEntry struct {
	order        []openLDAPConfigDNComponent
	descriptions []string
}

type openLDAPOrderedSchemaValue struct {
	order       int
	description string
}

func orderOpenLDAPSchemaValues(values []string) ([]string, error) {
	ordered := make([]openLDAPOrderedSchemaValue, len(values))
	hasIndex := false
	hasUnindexed := false
	for index, value := range values {
		order, description, present, err := parseOpenLDAPOrderingPrefix(value)
		if err != nil {
			return nil, err
		}
		if present {
			hasIndex = true
		} else {
			hasUnindexed = true
		}
		ordered[index] = openLDAPOrderedSchemaValue{
			order:       order,
			description: description,
		}
	}
	if hasIndex && hasUnindexed {
		return nil, fmt.Errorf("indexed and unindexed values cannot be mixed")
	}
	if hasIndex {
		sort.SliceStable(ordered, func(left, right int) bool {
			return ordered[left].order < ordered[right].order
		})
	}
	descriptions := make([]string, len(ordered))
	for index := range ordered {
		descriptions[index] = ordered[index].description
	}
	return descriptions, nil
}

type openLDAPConfigDNComponent struct {
	attribute string
	value     string
	order     int
	ordered   bool
}

func openLDAPConfigDNOrder(dn directory.DN) []openLDAPConfigDNComponent {
	components := make([]openLDAPConfigDNComponent, 0, dn.Depth())
	for dn.Depth() > 0 {
		values := dn.RDNValues()
		component := openLDAPConfigDNComponent{}
		if len(values) > 0 {
			component.attribute = strings.ToLower(values[0].Type)
			component.value = strings.ToLower(string(values[0].Value))
			if order, remainder, present, err := parseOpenLDAPOrderingPrefix(
				component.value,
			); err == nil && present {
				component.order = order
				component.ordered = true
				component.value = strings.ToLower(remainder)
			}
		}
		components = append(components, component)
		parent, ok := dn.Parent()
		if !ok {
			break
		}
		dn = parent
	}
	for left, right := 0, len(components)-1; left < right; left, right = left+1, right-1 {
		components[left], components[right] = components[right], components[left]
	}
	return components
}

func compareOpenLDAPConfigDNOrder(
	left,
	right []openLDAPConfigDNComponent,
) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if comparison := strings.Compare(
			left[index].attribute,
			right[index].attribute,
		); comparison != 0 {
			return comparison
		}
		if left[index].ordered && right[index].ordered &&
			left[index].order != right[index].order {
			if left[index].order < right[index].order {
				return -1
			}
			return 1
		}
		if comparison := strings.Compare(
			left[index].value,
			right[index].value,
		); comparison != 0 {
			return comparison
		}
		if left[index].ordered != right[index].ordered {
			if left[index].ordered {
				return 1
			}
			return -1
		}
	}
	return len(left) - len(right)
}

type openLDAPObjectIdentifierResolver struct {
	definitions map[string]string
}

func newOpenLDAPObjectIdentifierResolver() *openLDAPObjectIdentifierResolver {
	return &openLDAPObjectIdentifierResolver{
		definitions: make(map[string]string),
	}
}

func (resolver *openLDAPObjectIdentifierResolver) add(raw string) error {
	value, err := stripOpenLDAPOrderingPrefix(raw)
	if err != nil {
		return err
	}
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return fmt.Errorf("expected descriptor and OID expression")
	}
	if !validOpenLDAPOIDDescriptor(fields[0]) {
		return fmt.Errorf("invalid object identifier descriptor %q", fields[0])
	}
	resolved, err := resolver.resolve(fields[1])
	if err != nil {
		return err
	}
	key := strings.ToLower(fields[0])
	if previous, exists := resolver.definitions[key]; exists &&
		previous != resolved {
		return fmt.Errorf(
			"object identifier descriptor %q is already defined as %q",
			fields[0],
			previous,
		)
	}
	resolver.definitions[key] = resolved
	return nil
}

func (resolver *openLDAPObjectIdentifierResolver) resolve(value string) (string, error) {
	value = strings.TrimSpace(value)
	if validObjectIdentifier(value) && value != "" && value[0] >= '0' && value[0] <= '9' {
		return value, nil
	}
	name, suffix, hasSuffix := strings.Cut(value, ":")
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return "", fmt.Errorf("invalid OID expression %q", value)
	}
	resolved, exists := resolver.definitions[key]
	if !exists {
		return "", fmt.Errorf("undefined object identifier descriptor %q", name)
	}
	return appendOpenLDAPOIDSuffix(resolved, suffix, hasSuffix)
}

func appendOpenLDAPOIDSuffix(base, suffix string, present bool) (string, error) {
	if !present {
		return base, nil
	}
	if suffix == "" {
		return "", fmt.Errorf("empty OID macro suffix")
	}
	resolved := base + "." + suffix
	if !validObjectIdentifier(resolved) {
		return "", fmt.Errorf("invalid OID macro suffix %q", suffix)
	}
	return resolved, nil
}

func stripOpenLDAPOrderingPrefix(value string) (string, error) {
	_, remainder, _, err := parseOpenLDAPOrderingPrefix(value)
	return remainder, err
}

func parseOpenLDAPOrderingPrefix(
	value string,
) (order int, remainder string, present bool, err error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return 0, value, false, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, "", true, fmt.Errorf("invalid OpenLDAP ordering prefix")
	}
	order, err = strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return 0, "", true, fmt.Errorf(
			"invalid OpenLDAP ordering prefix %q",
			value[:end+1],
		)
	}
	return order, strings.TrimSpace(value[end+1:]), true, nil
}

func validOpenLDAPOIDDescriptor(value string) bool {
	if value == "" || !isASCIILetter(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isASCIILetter(value[index]) &&
			(value[index] < '0' || value[index] > '9') &&
			value[index] != '-' {
			return false
		}
	}
	return true
}
