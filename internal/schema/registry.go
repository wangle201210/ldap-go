package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/aci"
	"github.com/wangle201210/ldap-go/internal/directory"
)

type Registry struct {
	mu               sync.RWMutex
	syntaxes         map[string]*LDAPSyntax
	attributes       map[string]*AttributeType
	objectClasses    map[string]*ObjectClass
	contentRules     map[string]*DITContentRule
	nameForms        map[string]*NameForm
	structureRules   map[string]*DITStructureRule
	attributeOptions []string
}

type lockedRegistryDNNormalizer struct {
	registry *Registry
}

func (normalizer lockedRegistryDNNormalizer) NormalizeDNAttribute(
	attributeName string,
	value []byte,
) (string, []byte, error) {
	return normalizer.registry.normalizeDNAttributeLocked(attributeName, value)
}

func (normalizer lockedRegistryDNNormalizer) CanonicalDNAttributeName(
	attributeName string,
) (string, error) {
	return normalizer.registry.canonicalDNAttributeNameLocked(attributeName)
}

func NewRegistry() *Registry {
	registry := &Registry{
		syntaxes:         make(map[string]*LDAPSyntax),
		attributes:       make(map[string]*AttributeType),
		objectClasses:    make(map[string]*ObjectClass),
		contentRules:     make(map[string]*DITContentRule),
		nameForms:        make(map[string]*NameForm),
		structureRules:   make(map[string]*DITStructureRule),
		attributeOptions: []string{"lang-"},
	}
	registry.installBuiltinLDAPSyntaxes()
	return registry
}

func (registry *Registry) Clone() *Registry {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	cloned := NewRegistry()
	cloned.syntaxes = make(map[string]*LDAPSyntax, len(registry.syntaxes))
	for key, syntax := range registry.syntaxes {
		copy := cloneLDAPSyntax(*syntax)
		cloned.syntaxes[key] = &copy
	}
	attributeCopies := make(map[*AttributeType]*AttributeType)
	for key, attribute := range registry.attributes {
		copy, exists := attributeCopies[attribute]
		if !exists {
			value := cloneAttributeType(*attribute)
			copy = &value
			attributeCopies[attribute] = copy
		}
		cloned.attributes[key] = copy
	}
	objectClassCopies := make(map[*ObjectClass]*ObjectClass)
	for key, objectClass := range registry.objectClasses {
		copy, exists := objectClassCopies[objectClass]
		if !exists {
			value := cloneObjectClass(*objectClass)
			copy = &value
			objectClassCopies[objectClass] = copy
		}
		cloned.objectClasses[key] = copy
	}
	contentRuleCopies := make(map[*DITContentRule]*DITContentRule)
	for key, contentRule := range registry.contentRules {
		copy, exists := contentRuleCopies[contentRule]
		if !exists {
			value := cloneDITContentRule(*contentRule)
			copy = &value
			contentRuleCopies[contentRule] = copy
		}
		cloned.contentRules[key] = copy
	}
	nameFormCopies := make(map[*NameForm]*NameForm)
	for key, nameForm := range registry.nameForms {
		copy, exists := nameFormCopies[nameForm]
		if !exists {
			value := cloneNameForm(*nameForm)
			copy = &value
			nameFormCopies[nameForm] = copy
		}
		cloned.nameForms[key] = copy
	}
	structureRuleCopies := make(map[*DITStructureRule]*DITStructureRule)
	for key, structureRule := range registry.structureRules {
		copy, exists := structureRuleCopies[structureRule]
		if !exists {
			value := cloneDITStructureRule(*structureRule)
			copy = &value
			structureRuleCopies[structureRule] = copy
		}
		cloned.structureRules[key] = copy
	}
	cloned.attributeOptions = append([]string(nil), registry.attributeOptions...)
	return cloned
}

func (registry *Registry) RegisterAttributeType(attribute AttributeType) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if attribute.Usage == "" {
		attribute.Usage = UsageUserApplications
	}
	keys := schemaKeys(attribute.OID, attribute.Names)
	if len(keys) == 0 {
		return errors.New("attribute type requires an OID")
	}
	for _, key := range keys {
		if _, exists := registry.attributes[key]; exists {
			return fmt.Errorf("attribute type %q is already registered", key)
		}
	}
	if err := registry.validateCollectiveAttributeType(attribute); err != nil {
		return err
	}
	copy := attribute
	for _, key := range keys {
		registry.attributes[key] = &copy
	}
	return nil
}

func cloneAttributeType(attribute AttributeType) AttributeType {
	attribute.Names = append([]string(nil), attribute.Names...)
	attribute.Extensions = cloneExtensions(attribute.Extensions)
	return attribute
}

func cloneObjectClass(objectClass ObjectClass) ObjectClass {
	objectClass.Names = append([]string(nil), objectClass.Names...)
	objectClass.Superiors = append([]string(nil), objectClass.Superiors...)
	objectClass.Must = append([]string(nil), objectClass.Must...)
	objectClass.May = append([]string(nil), objectClass.May...)
	objectClass.Extensions = cloneExtensions(objectClass.Extensions)
	return objectClass
}

func cloneDITContentRule(contentRule DITContentRule) DITContentRule {
	contentRule.Names = append([]string(nil), contentRule.Names...)
	contentRule.Auxiliary = append([]string(nil), contentRule.Auxiliary...)
	contentRule.Must = append([]string(nil), contentRule.Must...)
	contentRule.May = append([]string(nil), contentRule.May...)
	contentRule.Not = append([]string(nil), contentRule.Not...)
	contentRule.Extensions = cloneExtensions(contentRule.Extensions)
	return contentRule
}

func cloneNameForm(nameForm NameForm) NameForm {
	nameForm.Names = append([]string(nil), nameForm.Names...)
	nameForm.Must = append([]string(nil), nameForm.Must...)
	nameForm.May = append([]string(nil), nameForm.May...)
	nameForm.Extensions = cloneExtensions(nameForm.Extensions)
	return nameForm
}

func cloneDITStructureRule(structureRule DITStructureRule) DITStructureRule {
	structureRule.Names = append([]string(nil), structureRule.Names...)
	structureRule.Superiors = append([]int(nil), structureRule.Superiors...)
	structureRule.Extensions = cloneExtensions(structureRule.Extensions)
	return structureRule
}

func cloneExtensions(extensions map[string][]string) map[string][]string {
	if extensions == nil {
		return nil
	}
	cloned := make(map[string][]string, len(extensions))
	for key, values := range extensions {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func (registry *Registry) RegisterObjectClass(objectClass ObjectClass) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	keys := schemaKeys(objectClass.OID, objectClass.Names)
	if len(keys) == 0 {
		return errors.New("object class requires an OID")
	}
	for _, key := range keys {
		if _, exists := registry.objectClasses[key]; exists {
			return fmt.Errorf("object class %q is already registered", key)
		}
	}
	if err := registry.validateObjectClassCollectiveAttributes(objectClass); err != nil {
		return err
	}
	copy := objectClass
	for _, key := range keys {
		registry.objectClasses[key] = &copy
	}
	return nil
}

func (registry *Registry) RegisterDITContentRule(
	contentRule DITContentRule,
) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if structural, ok := registry.objectClasses[schemaKey(contentRule.OID)]; ok {
		contentRule.OID = structural.OID
	}
	keys := schemaKeys(contentRule.OID, contentRule.Names)
	if len(keys) == 0 {
		return errors.New("DIT content rule requires an OID")
	}
	seenKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, duplicate := seenKeys[key]; duplicate {
			return fmt.Errorf(
				"DIT content rule %q repeats identifier %q",
				contentRule.Name(),
				key,
			)
		}
		seenKeys[key] = struct{}{}
		if _, exists := registry.contentRules[key]; exists {
			return fmt.Errorf(
				"DIT content rule %q is already registered",
				key,
			)
		}
	}
	if err := registry.validateDITContentRule(contentRule); err != nil {
		return err
	}
	copy := cloneDITContentRule(contentRule)
	for _, key := range keys {
		registry.contentRules[key] = &copy
	}
	return nil
}

func (registry *Registry) RegisterNameForm(nameForm NameForm) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	normalized, err := registry.normalizeNameForm(nameForm)
	if err != nil {
		return err
	}
	keys := schemaKeys(normalized.OID, normalized.Names)
	if err := validateSchemaDefinitionKeys("name form", normalized.Name(), keys); err != nil {
		return err
	}
	for _, key := range keys {
		if _, exists := registry.nameForms[key]; exists {
			return fmt.Errorf("name form %q is already registered", key)
		}
	}
	copy := cloneNameForm(normalized)
	for _, key := range keys {
		registry.nameForms[key] = &copy
	}
	return nil
}

func (registry *Registry) RegisterDITStructureRule(
	structureRule DITStructureRule,
) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	normalized, err := registry.normalizeDITStructureRule(structureRule)
	if err != nil {
		return err
	}
	keys := structureRuleKeys(normalized.RuleID, normalized.Names)
	if err := validateSchemaDefinitionKeys(
		"DIT structure rule",
		normalized.Name(),
		keys,
	); err != nil {
		return err
	}
	for _, key := range keys {
		if _, exists := registry.structureRules[key]; exists {
			return fmt.Errorf(
				"DIT structure rule %q is already registered",
				key,
			)
		}
	}
	if err := registry.validateDITStructureRuleGraph(normalized, false); err != nil {
		return err
	}
	copy := cloneDITStructureRule(normalized)
	for _, key := range keys {
		registry.structureRules[key] = &copy
	}
	return nil
}

func (registry *Registry) UpsertAttributeType(attribute AttributeType) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if attribute.Usage == "" {
		attribute.Usage = UsageUserApplications
	}
	keys := schemaKeys(attribute.OID, attribute.Names)
	if len(keys) == 0 {
		return errors.New("attribute type requires an OID")
	}
	for _, key := range keys {
		if existing, ok := registry.attributes[key]; ok &&
			!strings.EqualFold(existing.OID, attribute.OID) {
			return fmt.Errorf(
				"attribute type name %q conflicts with OID %q",
				key,
				existing.OID,
			)
		}
	}
	if err := registry.validateCollectiveAttributeType(attribute); err != nil {
		return err
	}
	for key, existing := range registry.attributes {
		if strings.EqualFold(existing.OID, attribute.OID) {
			delete(registry.attributes, key)
		}
	}
	copy := attribute
	for _, key := range keys {
		registry.attributes[key] = &copy
	}
	return nil
}

func (registry *Registry) UpsertObjectClass(objectClass ObjectClass) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	keys := schemaKeys(objectClass.OID, objectClass.Names)
	if len(keys) == 0 {
		return errors.New("object class requires an OID")
	}
	for _, key := range keys {
		if existing, ok := registry.objectClasses[key]; ok &&
			!strings.EqualFold(existing.OID, objectClass.OID) {
			return fmt.Errorf(
				"object class name %q conflicts with OID %q",
				key,
				existing.OID,
			)
		}
	}
	if err := registry.validateObjectClassCollectiveAttributes(objectClass); err != nil {
		return err
	}
	for key, existing := range registry.objectClasses {
		if strings.EqualFold(existing.OID, objectClass.OID) {
			delete(registry.objectClasses, key)
		}
	}
	copy := objectClass
	for _, key := range keys {
		registry.objectClasses[key] = &copy
	}
	return nil
}

func (registry *Registry) UpsertDITContentRule(
	contentRule DITContentRule,
) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if structural, ok := registry.objectClasses[schemaKey(contentRule.OID)]; ok {
		contentRule.OID = structural.OID
	}
	keys := schemaKeys(contentRule.OID, contentRule.Names)
	if len(keys) == 0 {
		return errors.New("DIT content rule requires an OID")
	}
	seenKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, duplicate := seenKeys[key]; duplicate {
			return fmt.Errorf(
				"DIT content rule %q repeats identifier %q",
				contentRule.Name(),
				key,
			)
		}
		seenKeys[key] = struct{}{}
		if existing, ok := registry.contentRules[key]; ok &&
			!strings.EqualFold(existing.OID, contentRule.OID) {
			return fmt.Errorf(
				"DIT content rule name %q conflicts with OID %q",
				key,
				existing.OID,
			)
		}
	}
	if err := registry.validateDITContentRule(contentRule); err != nil {
		return err
	}
	for key, existing := range registry.contentRules {
		if strings.EqualFold(existing.OID, contentRule.OID) {
			delete(registry.contentRules, key)
		}
	}
	copy := cloneDITContentRule(contentRule)
	for _, key := range keys {
		registry.contentRules[key] = &copy
	}
	return nil
}

func (registry *Registry) UpsertNameForm(nameForm NameForm) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	normalized, err := registry.normalizeNameForm(nameForm)
	if err != nil {
		return err
	}
	keys := schemaKeys(normalized.OID, normalized.Names)
	if err := validateSchemaDefinitionKeys("name form", normalized.Name(), keys); err != nil {
		return err
	}
	for _, key := range keys {
		if existing, ok := registry.nameForms[key]; ok &&
			!strings.EqualFold(existing.OID, normalized.OID) {
			return fmt.Errorf(
				"name form name %q conflicts with OID %q",
				key,
				existing.OID,
			)
		}
	}
	for key, existing := range registry.nameForms {
		if strings.EqualFold(existing.OID, normalized.OID) {
			delete(registry.nameForms, key)
		}
	}
	copy := cloneNameForm(normalized)
	for _, key := range keys {
		registry.nameForms[key] = &copy
	}
	return nil
}

func (registry *Registry) UpsertDITStructureRule(
	structureRule DITStructureRule,
) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	normalized, err := registry.normalizeDITStructureRule(structureRule)
	if err != nil {
		return err
	}
	keys := structureRuleKeys(normalized.RuleID, normalized.Names)
	if err := validateSchemaDefinitionKeys(
		"DIT structure rule",
		normalized.Name(),
		keys,
	); err != nil {
		return err
	}
	for _, key := range keys {
		if existing, ok := registry.structureRules[key]; ok &&
			existing.RuleID != normalized.RuleID {
			return fmt.Errorf(
				"DIT structure rule name %q conflicts with rule ID %d",
				key,
				existing.RuleID,
			)
		}
	}
	if err := registry.validateDITStructureRuleGraph(normalized, true); err != nil {
		return err
	}
	for key, existing := range registry.structureRules {
		if existing.RuleID == normalized.RuleID {
			delete(registry.structureRules, key)
		}
	}
	copy := cloneDITStructureRule(normalized)
	for _, key := range keys {
		registry.structureRules[key] = &copy
	}
	return nil
}

func (registry *Registry) AttributeType(name string) (AttributeType, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return AttributeType{}, false
	}
	return *attribute, true
}

func (registry *Registry) HasAttributeType(name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	return ok
}

func (registry *Registry) EffectiveAttributeType(
	name string,
) (AttributeType, bool, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return AttributeType{}, false, nil
	}
	effective, err := registry.effectiveAttributeType(
		attribute,
		make(map[string]bool),
	)
	return effective, true, err
}

// AttributeDescriptionSubtype reports whether candidate is the requested
// description itself or one of its attribute-type or tagging-option subtypes.
func (registry *Registry) AttributeDescriptionSubtype(
	candidate,
	requested string,
) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.attributeDescriptionSubtype(candidate, requested)
}

func (registry *Registry) AttributeValues(
	entry directory.Entry,
	description string,
) [][]byte {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	return registry.attributeValues(entry, description)
}

// NormalizedEqualityAttributeValues returns all values selected by an
// AttributeDescription after applying that attribute's equality rule. It
// resolves the schema once for callers that need every normalized value.
func (registry *Registry) NormalizedEqualityAttributeValues(
	entry directory.Entry,
	description string,
) ([][]byte, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(description))]
	if !ok {
		return nil, fmt.Errorf("undefined attribute type %q", description)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	var values [][]byte
	for _, candidate := range entry.Attributes {
		if !registry.attributeDescriptionSubtype(candidate.Description, description) {
			continue
		}
		for _, value := range candidate.Values {
			normalized := bytes.Clone(value)
			if effective.Equality != "" {
				normalized, err = registry.normalizeWithRuleLocked(effective.Equality, value)
				if err != nil {
					return nil, err
				}
			}
			values = append(values, normalized)
		}
	}
	return values, nil
}

func (registry *Registry) attributeValues(
	entry directory.Entry,
	description string,
) [][]byte {
	var values [][]byte
	for _, attribute := range entry.Attributes {
		if !registry.attributeDescriptionSubtype(
			attribute.Description,
			description,
		) {
			continue
		}
		for _, value := range attribute.Values {
			values = append(values, bytes.Clone(value))
		}
	}
	return values
}

func (registry *Registry) HasAttributeDescription(
	entry directory.Entry,
	description string,
) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	for _, attribute := range entry.Attributes {
		if registry.attributeDescriptionSubtype(
			attribute.Description,
			description,
		) {
			return true
		}
	}
	return false
}

func (registry *Registry) ObjectClass(name string) (ObjectClass, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	objectClass, ok := registry.objectClasses[schemaKey(name)]
	if !ok {
		return ObjectClass{}, false
	}
	return *objectClass, true
}

// ObjectClassAttributeDescriptions returns the canonical inherited MUST and
// MAY attribute descriptions for an exact RFC 4512 object identifier.
func (registry *Registry) ObjectClassAttributeDescriptions(
	name string,
) (attributes []string, extensible, known bool) {
	if !validObjectIdentifier(name) {
		return nil, false, false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	objectClass, ok := registry.objectClasses[strings.ToLower(name)]
	if !ok {
		return nil, false, false
	}
	if strings.EqualFold(objectClass.OID, "1.3.6.1.4.1.1466.101.120.111") {
		return nil, true, true
	}
	classes := make(map[string]*ObjectClass)
	if err := registry.collectObjectClass(
		objectClass,
		classes,
		make(map[string]bool),
	); err != nil {
		return nil, false, true
	}
	seen := make(map[string]struct{})
	for _, class := range classes {
		for _, descriptions := range [][]string{class.Must, class.May} {
			for _, description := range descriptions {
				attribute, found := registry.attributes[schemaKey(description)]
				key := schemaKey(description)
				if found {
					key = schemaKey(attribute.OID)
					description = attribute.Name()
				}
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
				attributes = append(attributes, description)
			}
		}
	}
	sort.Slice(attributes, func(left, right int) bool {
		return strings.ToLower(attributes[left]) < strings.ToLower(attributes[right])
	})
	return attributes, false, true
}

// ObjectClassAllowsAttribute reports whether an attribute is included in an
// object class's inherited MUST or MAY set. The second result distinguishes an
// unknown class from a known class that does not include the attribute.
func (registry *Registry) ObjectClassAllowsAttribute(
	objectClassName,
	attributeName string,
) (bool, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	objectClass, ok := registry.objectClasses[schemaKey(objectClassName)]
	if !ok {
		return false, false
	}
	if strings.EqualFold(objectClass.OID, "1.3.6.1.4.1.1466.101.120.111") {
		return true, true
	}
	classes := make(map[string]*ObjectClass)
	if err := registry.collectObjectClass(
		objectClass,
		classes,
		make(map[string]bool),
	); err != nil {
		return false, true
	}
	for _, class := range classes {
		for _, description := range append(class.Must, class.May...) {
			if registry.attributeDescriptionSubtype(attributeName, description) {
				return true, true
			}
		}
	}
	return false, true
}

func (registry *Registry) DITContentRule(name string) (DITContentRule, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	contentRule, ok := registry.contentRules[schemaKey(name)]
	if !ok {
		return DITContentRule{}, false
	}
	return cloneDITContentRule(*contentRule), true
}

func (registry *Registry) NameForm(name string) (NameForm, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	nameForm, ok := registry.nameForms[schemaKey(name)]
	if !ok {
		return NameForm{}, false
	}
	return cloneNameForm(*nameForm), true
}

func (registry *Registry) DITStructureRule(
	identifier string,
) (DITStructureRule, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	structureRule, ok := registry.structureRules[schemaKey(identifier)]
	if !ok {
		return DITStructureRule{}, false
	}
	return cloneDITStructureRule(*structureRule), true
}

func (registry *Registry) EntryHasObjectClass(
	entry directory.Entry,
	name string,
) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	target, ok := registry.objectClasses[schemaKey(name)]
	if !ok {
		return false
	}
	for _, value := range registry.attributeValues(entry, "objectClass") {
		candidate, ok := registry.objectClasses[schemaKey(string(value))]
		if ok && registry.isSubclass(candidate, target, make(map[string]bool)) {
			return true
		}
	}
	return false
}

// PreparedObjectClassMatcher resolves a fixed set of object classes once and
// classifies each entry with one objectClass scan. Bit i corresponds to names[i].
type PreparedObjectClassMatcher struct {
	attributes map[string]struct{}
	flags      map[string]uint64
}

// PreparedAttributeSelection handles explicit, option-free attribute lists.
// Wildcards and option-qualified requests retain the general selection path.
type PreparedAttributeSelection struct {
	attributes map[string]struct{}
	empty      bool
}

func (registry *Registry) PrepareExplicitAttributeSelection(
	requested []string,
) (*PreparedAttributeSelection, bool) {
	if len(requested) == 1 && requested[0] == "1.1" {
		return &PreparedAttributeSelection{empty: true}, true
	}
	if len(requested) == 0 {
		return nil, false
	}
	for _, description := range requested {
		if description == "" || description == "*" || description == "+" ||
			strings.Contains(description, ";") || strings.HasPrefix(description, "@") {
			return nil, false
		}
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	selected := make(map[string]struct{})
	for _, description := range requested {
		requestedType, known := registry.attributes[schemaKey(description)]
		if !known {
			selected[schemaKey(description)] = struct{}{}
			continue
		}
		for key, candidate := range registry.attributes {
			if registry.attributeTypeSubtype(
				candidate,
				requestedType,
				make(map[string]bool),
			) {
				selected[key] = struct{}{}
			}
		}
	}
	return &PreparedAttributeSelection{attributes: selected}, true
}

func (selection *PreparedAttributeSelection) Select(
	entry directory.Entry,
	typesOnly bool,
) directory.Entry {
	result := directory.Entry{DN: entry.DN}
	if selection == nil || selection.empty {
		return result
	}
	for _, attribute := range entry.Attributes {
		description, _, _ := strings.Cut(attribute.Description, ";")
		if _, selected := selection.attributes[schemaKey(description)]; !selected {
			continue
		}
		value := directory.Attribute{Description: attribute.Description}
		if !typesOnly {
			value.Values = clonePreparedValues(attribute.Values)
		}
		result.Attributes = append(result.Attributes, value)
	}
	return result
}

func (registry *Registry) PrepareObjectClassMatcher(
	names ...string,
) (*PreparedObjectClassMatcher, error) {
	if len(names) > 64 {
		return nil, fmt.Errorf("at most 64 object classes can be prepared")
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	targets := make([]*ObjectClass, len(names))
	for index, name := range names {
		target, ok := registry.objectClasses[schemaKey(name)]
		if !ok {
			return nil, fmt.Errorf("undefined object class %q", name)
		}
		targets[index] = target
	}
	objectClassAttribute, ok := registry.attributes[schemaKey("objectClass")]
	if !ok {
		return nil, errors.New("undefined objectClass attribute")
	}
	attributes := make(map[string]struct{})
	for key, candidate := range registry.attributes {
		if registry.attributeTypeSubtype(
			candidate,
			objectClassAttribute,
			make(map[string]bool),
		) {
			attributes[key] = struct{}{}
		}
	}
	flags := make(map[string]uint64, len(registry.objectClasses))
	for key, candidate := range registry.objectClasses {
		var value uint64
		for index, target := range targets {
			if registry.isSubclass(candidate, target, make(map[string]bool)) {
				value |= uint64(1) << index
			}
		}
		flags[key] = value
	}
	return &PreparedObjectClassMatcher{attributes: attributes, flags: flags}, nil
}

func (matcher *PreparedObjectClassMatcher) Match(entry directory.Entry) uint64 {
	if matcher == nil {
		return 0
	}
	var result uint64
	for _, attribute := range entry.Attributes {
		description, _, _ := strings.Cut(attribute.Description, ";")
		if _, ok := matcher.attributes[schemaKey(description)]; !ok {
			continue
		}
		for _, value := range attribute.Values {
			result |= matcher.flags[schemaKey(string(value))]
		}
	}
	return result
}

func (registry *Registry) IsOperational(attributeName string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return attribute.Usage != UsageUserApplications
	}
	return effective.Usage != UsageUserApplications
}

func (registry *Registry) IsDNValued(attributeName string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	return err == nil && effective.Syntax == SyntaxDistinguishedName
}

func (registry *Registry) IsDNReferenceValued(attributeName string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return false
	}
	return effective.Syntax == SyntaxDistinguishedName ||
		effective.Syntax == SyntaxNameAndOptionalUID
}

func (registry *Registry) IsACIValued(attributeName string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	return err == nil && effective.Syntax == SyntaxOpenLDAPACI
}

func (registry *Registry) IsCollective(attributeName string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false
	}
	collective, err := registry.attributeTypeIsCollective(attribute, make(map[string]bool))
	return err == nil && collective
}

func (registry *Registry) HasCollectiveAttributeTypes() bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	for _, attribute := range uniqueAttributeTypes(registry.attributes) {
		if attribute.Collective {
			return true
		}
	}
	return false
}

func (registry *Registry) AttributeTypeDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attributes := uniqueAttributeTypes(registry.attributes)
	result := make([]string, 0, len(attributes))
	for i := range attributes {
		if attributes[i].Hidden {
			continue
		}
		result = append(result, FormatAttributeType(attributes[i]))
	}
	return result
}

// DNIdentityFingerprint identifies every schema input that can affect a
// naming attribute's canonical type or equality normalization. It deliberately
// includes hidden attribute types and a format label so an implementation
// change can force one explicit storage migration.
func (registry *Registry) DNIdentityFingerprint() [sha256.Size]byte {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	hash := sha256.New()
	_, _ = hash.Write([]byte("ldap-go:dn-identity:v2\x00"))
	var length [8]byte
	writeString := func(value string) {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	for _, attribute := range uniqueAttributeTypes(registry.attributes) {
		writeString(attribute.OID)
		binary.BigEndian.PutUint64(length[:], uint64(len(attribute.Names)))
		_, _ = hash.Write(length[:])
		for _, name := range attribute.Names {
			writeString(name)
		}
		writeString(attribute.Superior)
		writeString(attribute.Equality)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (registry *Registry) ObjectClassDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	objectClasses := uniqueObjectClasses(registry.objectClasses)
	result := make([]string, 0, len(objectClasses))
	for i := range objectClasses {
		if objectClasses[i].Hidden {
			continue
		}
		result = append(result, FormatObjectClass(objectClasses[i]))
	}
	return result
}

func (registry *Registry) DITContentRuleDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	contentRules := uniqueDITContentRules(registry.contentRules)
	result := make([]string, len(contentRules))
	for i := range contentRules {
		result[i] = FormatDITContentRule(contentRules[i])
	}
	return result
}

func (registry *Registry) NameFormDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	nameForms := uniqueNameForms(registry.nameForms)
	result := make([]string, len(nameForms))
	for i := range nameForms {
		result[i] = FormatNameForm(nameForms[i])
	}
	return result
}

func (registry *Registry) DITStructureRuleDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	structureRules := uniqueDITStructureRules(registry.structureRules)
	result := make([]string, len(structureRules))
	for i := range structureRules {
		result[i] = FormatDITStructureRule(structureRules[i])
	}
	return result
}

func (registry *Registry) StructuralObjectClass(entry directory.Entry) (string, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	objectClass, err := registry.structuralObjectClass(entry)
	if err != nil {
		return "", err
	}
	return objectClass.Name(), nil
}

func (registry *Registry) GoverningStructureRule(
	entry directory.Entry,
	parent *directory.Entry,
) (int, bool, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	structural, err := registry.structuralObjectClass(entry)
	if err != nil {
		return 0, false, err
	}
	structureRules := uniqueDITStructureRules(registry.structureRules)
	regulated := false
	valid := make([]DITStructureRule, 0)
	for _, structureRule := range structureRules {
		nameForm := registry.nameForms[schemaKey(structureRule.Form)]
		if nameForm == nil ||
			!strings.EqualFold(nameForm.ObjectClass, structural.OID) {
			continue
		}
		regulated = true
		if structureRule.Obsolete || nameForm.Obsolete {
			continue
		}
		if !registry.nameFormMatchesRDN(*nameForm, entry) {
			continue
		}
		allowed, err := registry.structureRuleAllowsParent(
			structureRule,
			parent,
		)
		if err != nil {
			return 0, false, err
		}
		if allowed {
			valid = append(valid, structureRule)
		}
	}
	if !regulated {
		return 0, false, nil
	}
	if len(valid) == 0 {
		message := fmt.Sprintf(
			"no active DIT structure rule permits entry '%s' with structural object class '%s'",
			entry.DN,
			structural.Name(),
		)
		if parent != nil {
			message += fmt.Sprintf(" below '%s'", parent.DN)
		}
		return 0, false, &Violation{
			Kind:    ViolationNaming,
			Message: message,
		}
	}

	for _, value := range registry.attributeValues(entry, "governingStructureRule") {
		ruleID, err := strconv.Atoi(string(value))
		if err != nil {
			continue
		}
		for _, candidate := range valid {
			if candidate.RuleID == ruleID {
				return ruleID, true, nil
			}
		}
	}
	return valid[0].RuleID, true, nil
}

func (registry *Registry) structuralObjectClass(
	entry directory.Entry,
) (*ObjectClass, error) {

	classes := make(map[string]*ObjectClass)
	for _, value := range registry.attributeValues(entry, "objectClass") {
		objectClass, ok := registry.objectClasses[schemaKey(string(value))]
		if !ok {
			return nil, &Violation{
				Kind:      ViolationUnknownObjectClass,
				Attribute: "objectClass",
				Message:   fmt.Sprintf("unknown object class %q", value),
			}
		}
		if err := registry.collectObjectClass(objectClass, classes, make(map[string]bool)); err != nil {
			return nil, err
		}
	}
	if err := registry.validateStructuralClasses(classes); err != nil {
		return nil, err
	}
	for _, candidate := range classes {
		if candidate.Kind != ObjectClassStructural {
			continue
		}
		mostSpecific := true
		for _, other := range classes {
			if other.Kind == ObjectClassStructural &&
				!registry.isSubclass(candidate, other, make(map[string]bool)) {
				mostSpecific = false
				break
			}
		}
		if mostSpecific {
			return candidate, nil
		}
	}
	return nil, &Violation{
		Kind:    ViolationStructuralObjectClass,
		Message: "entry has no structural object class",
	}
}

func (registry *Registry) nameFormMatchesRDN(
	nameForm NameForm,
	entry directory.Entry,
) bool {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil || dn.Depth() == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(nameForm.Must)+len(nameForm.May))
	required := make(map[string]struct{}, len(nameForm.Must))
	for _, name := range nameForm.Must {
		key := registry.attributeIdentifierKey(name)
		allowed[key] = struct{}{}
		required[key] = struct{}{}
	}
	for _, name := range nameForm.May {
		allowed[registry.attributeIdentifierKey(name)] = struct{}{}
	}
	for _, value := range dn.RDNValues() {
		attribute, ok := registry.attributes[schemaKey(value.Type)]
		if !ok {
			return false
		}
		key := schemaKey(attribute.OID)
		if _, ok := allowed[key]; !ok {
			return false
		}
		delete(required, key)
	}
	return len(required) == 0
}

func (registry *Registry) structureRuleAllowsParent(
	structureRule DITStructureRule,
	parent *directory.Entry,
) (bool, error) {
	if parent == nil {
		return len(structureRule.Superiors) == 0, nil
	}
	if len(structureRule.Superiors) == 0 {
		return false, nil
	}

	parentRuleValues := registry.attributeValues(*parent, "governingStructureRule")
	if len(parentRuleValues) == 1 {
		parentRuleID, err := strconv.Atoi(string(parentRuleValues[0]))
		if err == nil {
			allowedSuperior := false
			for _, superior := range structureRule.Superiors {
				if superior == parentRuleID {
					allowedSuperior = true
					break
				}
			}
			if !allowedSuperior {
				return false, nil
			}
			return registry.entryConformsToStructureRule(
				*parent,
				parentRuleID,
			)
		}
	}

	for _, superior := range structureRule.Superiors {
		matches, err := registry.entryConformsToStructureRule(*parent, superior)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func (registry *Registry) entryConformsToStructureRule(
	entry directory.Entry,
	ruleID int,
) (bool, error) {
	structureRule := registry.structureRules[strconv.Itoa(ruleID)]
	if structureRule == nil || structureRule.Obsolete {
		return false, nil
	}
	nameForm := registry.nameForms[schemaKey(structureRule.Form)]
	if nameForm == nil || nameForm.Obsolete {
		return false, nil
	}
	structural, err := registry.structuralObjectClass(entry)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(nameForm.ObjectClass, structural.OID) &&
		registry.nameFormMatchesRDN(*nameForm, entry), nil
}

func (registry *Registry) ParseAndRegisterAttributeType(description string) error {
	attribute, err := ParseAttributeType(description)
	if err != nil {
		return err
	}
	return registry.RegisterAttributeType(attribute)
}

func (registry *Registry) ParseAndRegisterObjectClass(description string) error {
	objectClass, err := ParseObjectClass(description)
	if err != nil {
		return err
	}
	return registry.RegisterObjectClass(objectClass)
}

func (registry *Registry) ParseAndRegisterDITContentRule(
	description string,
) error {
	contentRule, err := ParseDITContentRule(description)
	if err != nil {
		return err
	}
	return registry.RegisterDITContentRule(contentRule)
}

func (registry *Registry) ParseAndRegisterNameForm(description string) error {
	nameForm, err := ParseNameForm(description)
	if err != nil {
		return err
	}
	return registry.RegisterNameForm(nameForm)
}

func (registry *Registry) ParseAndRegisterDITStructureRule(
	description string,
) error {
	structureRule, err := ParseDITStructureRule(description)
	if err != nil {
		return err
	}
	return registry.RegisterDITStructureRule(structureRule)
}

func (registry *Registry) Compare(
	attributeName, matchingRule string,
	left, right []byte,
) (int, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return 0, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return 0, err
	}
	rule := matchingRule
	if rule == "" {
		rule = effective.Equality
	}
	if rule == "" {
		return 0, fmt.Errorf("attribute %q has no equality matching rule", attributeName)
	}
	if strings.EqualFold(attribute.OID, "2.5.4.0") &&
		canonicalMatchingRule(rule) == "objectidentifiermatch" {
		candidate, candidateFound := registry.objectClasses[schemaKey(strings.TrimSpace(string(left)))]
		ancestor, ancestorFound := registry.objectClasses[schemaKey(strings.TrimSpace(string(right)))]
		if candidateFound && ancestorFound &&
			registry.isSubclass(candidate, ancestor, make(map[string]bool)) {
			return 0, nil
		}
	}
	return registry.compareWithRuleLocked(rule, left, right)
}

// NormalizeEqualityValue returns the normalized value used by an attribute's
// equality matching rule. Attributes without an equality rule retain their
// wire value, matching OpenLDAP's a_nvals behavior.
func (registry *Registry) NormalizeEqualityValue(
	attributeName string,
	value []byte,
) ([]byte, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return nil, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if effective.Equality == "" {
		return bytes.Clone(value), nil
	}
	return registry.normalizeWithRuleLocked(effective.Equality, value)
}

// NormalizeDNAttribute implements directory.DNAttributeNormalizer. Attribute
// aliases collapse to the numeric OID and values follow the effective equality
// matching rule, which is the identity behavior OpenLDAP applies to naming
// attributes.
func (registry *Registry) NormalizeDNAttribute(
	attributeName string,
	value []byte,
) (string, []byte, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.normalizeDNAttributeLocked(attributeName, value)
}

func (registry *Registry) normalizeDNAttributeLocked(
	attributeName string,
	value []byte,
) (string, []byte, error) {
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return "", nil, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return "", nil, err
	}
	if effective.Equality == "" {
		return "", nil, fmt.Errorf(
			"attribute %q has no equality matching rule",
			attributeName,
		)
	}
	normalized, err := registry.normalizeWithRuleLocked(effective.Equality, value)
	if err != nil {
		return "", nil, err
	}
	return attribute.OID, normalized, nil
}

// CanonicalDNAttributeName returns the attribute description OpenLDAP uses in
// the pretty form of a DN. Attribute aliases and options collapse to the
// primary schema name, matching OpenLDAP's ad_cname rewrite.
func (registry *Registry) CanonicalDNAttributeName(
	attributeName string,
) (string, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.canonicalDNAttributeNameLocked(attributeName)
}

func (registry *Registry) canonicalDNAttributeNameLocked(
	attributeName string,
) (string, error) {
	baseName := baseAttributeDescription(attributeName)
	attribute, ok := registry.attributes[schemaKey(baseName)]
	if !ok {
		return "", fmt.Errorf("undefined attribute type %q", attributeName)
	}
	return attribute.Name(), nil
}

// NormalizeDN parses a DN and assigns its schema-aware v2 identity key.
func (registry *Registry) NormalizeDN(value string) (directory.DN, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.normalizeDNLocked(value)
}

func (registry *Registry) normalizeDNLocked(value string) (directory.DN, error) {
	return directory.ParseDNWithNormalizer(
		value,
		lockedRegistryDNNormalizer{registry: registry},
	)
}

func (registry *Registry) normalizeWithRuleLocked(
	rule string,
	value []byte,
) ([]byte, error) {
	switch canonicalMatchingRule(rule) {
	case "distinguishednamematch":
		dn, err := registry.normalizeDNLocked(string(value))
		if err != nil {
			return nil, errors.New("distinguishedNameMatch received invalid DN")
		}
		return []byte(dn.NormalizedString()), nil
	case "uniquemembermatch":
		return registry.normalizeUniqueMemberLocked(value)
	default:
		return normalizeWithRule(rule, value)
	}
}

func (registry *Registry) compareWithRuleLocked(
	rule string,
	left, right []byte,
) (int, error) {
	switch canonicalMatchingRule(rule) {
	case "distinguishednamematch":
		normalizedLeft, leftErr := registry.normalizeWithRuleLocked(rule, left)
		normalizedRight, rightErr := registry.normalizeWithRuleLocked(rule, right)
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("distinguishedNameMatch received invalid DN")
		}
		return bytes.Compare(normalizedLeft, normalizedRight), nil
	case "uniquemembermatch":
		return registry.compareUniqueMemberLocked(left, right)
	default:
		return compareWithRule(rule, left, right)
	}
}

func (registry *Registry) compareUniqueMemberLocked(left, right []byte) (int, error) {
	leftDNValue, leftUID, leftHasUID := splitNameAndOptionalUID(left)
	rightDNValue, rightUID, rightHasUID := splitNameAndOptionalUID(right)
	switch {
	case leftHasUID && rightHasUID:
		if len(leftUID) != len(rightUID) {
			return len(leftUID) - len(rightUID), nil
		}
		if comparison := bytes.Compare(leftUID, rightUID); comparison != 0 {
			return comparison, nil
		}
	case leftHasUID:
		return -1, nil
	case rightHasUID:
		return 1, nil
	}
	leftDN, leftErr := registry.normalizeDNLocked(string(leftDNValue))
	rightDN, rightErr := registry.normalizeDNLocked(string(rightDNValue))
	if leftErr != nil || rightErr != nil {
		return 0, errors.New(
			"uniqueMemberMatch received invalid name and optional UID",
		)
	}
	return strings.Compare(leftDN.NormalizedString(), rightDN.NormalizedString()), nil
}

func (registry *Registry) normalizeUniqueMemberLocked(value []byte) ([]byte, error) {
	dnValue, uid, hasUID := splitNameAndOptionalUID(value)
	dn, err := registry.normalizeDNLocked(string(dnValue))
	if err != nil {
		return nil, errors.New("uniqueMemberMatch received invalid name and optional UID")
	}
	normalized := []byte(dn.NormalizedString())
	if hasUID {
		normalized = append(normalized, '#')
		normalized = append(normalized, uid...)
	}
	return normalized, nil
}

// NormalizeEqualityAssertion validates and normalizes an assertion using the
// assertion syntax of an attribute's equality matching rule.
func (registry *Registry) NormalizeEqualityAssertion(
	attributeName string,
	value []byte,
) ([]byte, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return nil, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if effective.Equality == "" {
		return nil, fmt.Errorf("attribute %q has no equality matching rule", attributeName)
	}

	assertionSyntax := effective.Syntax
	assertionLength := effective.SyntaxLength
	switch canonicalMatchingRule(effective.Equality) {
	case "integerfirstcomponentmatch":
		assertionSyntax = SyntaxInteger
		assertionLength = 0
	case "objectidentifierfirstcomponentmatch":
		assertionSyntax = SyntaxOID
		assertionLength = 0
	}
	if err := registry.validateSyntax(assertionSyntax, assertionLength, value); err != nil {
		return nil, fmt.Errorf("attribute %q assertion: %w", attributeName, err)
	}
	return registry.normalizeWithRuleLocked(effective.Equality, value)
}

// ValidateAttributeValue checks a single value against the effective syntax
// and optional length constraint of an attribute type.
func (registry *Registry) ValidateAttributeValue(
	attributeName string,
	value []byte,
) error {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return err
	}
	if err := registry.validateSyntax(effective.Syntax, effective.SyntaxLength, value); err != nil {
		return fmt.Errorf("attribute %q: %w", attributeName, err)
	}
	return nil
}

func (registry *Registry) OrderingRule(
	attributeName,
	matchingRule string,
) (string, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return "", fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return "", err
	}
	rule := matchingRule
	if rule == "" {
		rule = effective.Ordering
	}
	if rule == "" {
		return "", fmt.Errorf("attribute %q has no ordering matching rule", attributeName)
	}
	rule = canonicalMatchingRule(rule)
	if !supportedMatchingRule(rule) {
		return "", fmt.Errorf("unsupported matching rule %q", rule)
	}
	return rule, nil
}

func (registry *Registry) CompareOrdering(
	attributeName,
	matchingRule string,
	left,
	right []byte,
) (int, error) {
	rule, err := registry.OrderingRule(attributeName, matchingRule)
	if err != nil {
		return 0, err
	}
	return compareWithRule(rule, left, right)
}

func (registry *Registry) MatchSubstring(
	attributeName string,
	value []byte,
	substring directory.Substring,
) (bool, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return false, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return false, err
	}
	if effective.Substring == "" {
		return false, fmt.Errorf("attribute %q has no substring matching rule", attributeName)
	}
	return matchSubstringWithRule(effective.Substring, value, substring)
}

// PreparedSubstringMatcher resolves an attribute and normalizes the fixed
// assertion parts once for repeated matching within one immutable runtime.
type PreparedSubstringMatcher struct {
	attributes     map[string]struct{}
	normalize      func([]byte) []byte
	substring      directory.Substring
	rawSubstring   directory.Substring
	caseIgnoreList bool
}

func (registry *Registry) PrepareSubstringMatcher(
	attributeName string,
	substring directory.Substring,
) (*PreparedSubstringMatcher, error) {
	if strings.Contains(attributeName, ";") {
		return nil, fmt.Errorf("option-qualified substring filters use the general matcher")
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(attributeName))]
	if !ok {
		return nil, fmt.Errorf("undefined attribute type %q", attributeName)
	}
	effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	attributes := make(map[string]struct{})
	for key, candidate := range registry.attributes {
		if registry.attributeTypeSubtype(candidate, attribute, make(map[string]bool)) {
			attributes[key] = struct{}{}
		}
	}
	matcher := &PreparedSubstringMatcher{
		attributes: attributes,
		rawSubstring: directory.Substring{
			Initial: bytes.Clone(substring.Initial),
			Any:     clonePreparedValues(substring.Any),
			Final:   bytes.Clone(substring.Final),
		},
	}
	switch strings.ToLower(effective.Substring) {
	case "caseignoresubstringsmatch", "caseignoreia5substringsmatch":
		matcher.normalize = normalizeCaseIgnore
	case "caseignorelistsubstringsmatch":
		matcher.caseIgnoreList = true
	case "caseexactsubstringsmatch", "caseexactia5substringsmatch":
		matcher.normalize = normalizeSpace
	case "telephonenumbersubstringsmatch":
		matcher.normalize = normalizeTelephoneNumber
	case "numericstringsubstringsmatch":
		matcher.normalize = normalizeNumericString
	case "":
		return nil, fmt.Errorf("attribute %q has no substring matching rule", attributeName)
	default:
		return nil, fmt.Errorf("unsupported substring matching rule %q", effective.Substring)
	}
	if !matcher.caseIgnoreList {
		matcher.substring = normalizeSubstringAssertion(matcher.normalize, substring)
	}
	return matcher, nil
}

func (matcher *PreparedSubstringMatcher) Match(entry directory.Entry) (bool, error) {
	if matcher == nil {
		return false, errors.New("prepared substring matcher is nil")
	}
	for _, attribute := range entry.Attributes {
		description, _, _ := strings.Cut(attribute.Description, ";")
		if _, ok := matcher.attributes[schemaKey(description)]; !ok {
			continue
		}
		for _, value := range attribute.Values {
			var matches bool
			var err error
			if matcher.caseIgnoreList {
				matches, err = matchCaseIgnoreListSubstring(value, matcher.rawSubstring)
			} else {
				matches = matchNormalizedSubstring(
					matcher.normalize(value),
					matcher.substring,
				)
			}
			if err != nil || matches {
				return matches, err
			}
		}
	}
	return false, nil
}

func normalizeSubstringAssertion(
	normalize func([]byte) []byte,
	substring directory.Substring,
) directory.Substring {
	result := directory.Substring{Any: make([][]byte, len(substring.Any))}
	if substring.Initial != nil {
		result.Initial = normalize(substring.Initial)
	}
	for index, value := range substring.Any {
		result.Any[index] = normalize(value)
	}
	if substring.Final != nil {
		result.Final = normalize(substring.Final)
	}
	return result
}

func clonePreparedValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func matchNormalizedSubstring(candidate []byte, substring directory.Substring) bool {
	position := 0
	if substring.Initial != nil {
		if !bytes.HasPrefix(candidate, substring.Initial) {
			return false
		}
		position = len(substring.Initial)
	}
	for _, part := range substring.Any {
		index := bytes.Index(candidate[position:], part)
		if index < 0 {
			return false
		}
		position += index + len(part)
	}
	if substring.Final != nil {
		return bytes.HasSuffix(candidate[position:], substring.Final)
	}
	return true
}

func (registry *Registry) ValidateEntry(entry directory.Entry) error {
	return registry.ValidateEntryWithOptions(entry, EntryValidationOptions{})
}

func (registry *Registry) ValidateEntryWithOptions(
	entry directory.Entry,
	options EntryValidationOptions,
) error {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	classValues := registry.attributeValues(entry, "objectClass")
	if len(classValues) == 0 {
		return &Violation{
			Kind:      ViolationMissingRequiredAttribute,
			Attribute: "objectClass",
			Message:   "required attribute is missing",
		}
	}

	classes := make(map[string]*ObjectClass)
	for _, value := range classValues {
		objectClass, ok := registry.objectClasses[schemaKey(string(value))]
		if !ok {
			return &Violation{
				Kind:      ViolationUnknownObjectClass,
				Attribute: "objectClass",
				Message:   fmt.Sprintf("unknown object class %q", value),
			}
		}
		if objectClass.Obsolete {
			return &Violation{
				Kind:      ViolationStructuralObjectClass,
				Attribute: "objectClass",
				Message: fmt.Sprintf(
					"object class '%s' is obsolete",
					objectClass.Name(),
				),
			}
		}
		if err := registry.collectObjectClass(objectClass, classes, make(map[string]bool)); err != nil {
			return err
		}
	}

	if err := registry.validateStructuralClasses(classes); err != nil {
		return err
	}
	structuralClass, err := registry.mostSpecificStructuralClass(classes)
	if err != nil {
		return err
	}
	contentRule := registry.contentRules[schemaKey(structuralClass.OID)]
	if contentRule != nil {
		if contentRule.Obsolete {
			return &Violation{
				Kind: ViolationStructuralObjectClass,
				Message: fmt.Sprintf(
					"content rule '%s' is obsolete",
					contentRule.Name(),
				),
			}
		}
		presentAttributes := make(map[string]struct{}, len(entry.Attributes))
		for _, attribute := range entry.Attributes {
			if attributeType, ok := registry.attributes[schemaKey(
				baseAttributeDescription(attribute.Description),
			)]; ok {
				presentAttributes[schemaKey(attributeType.OID)] = struct{}{}
			}
		}
		for _, name := range contentRule.Must {
			key := registry.attributeIdentifierKey(name)
			if _, present := presentAttributes[key]; !present {
				return &Violation{
					Kind: ViolationMissingRequiredAttribute,
					Message: fmt.Sprintf(
						"content rule '%s' requires attribute '%s'",
						contentRule.Name(),
						registry.attributeTypeName(name),
					),
				}
			}
		}
		for _, name := range contentRule.Not {
			key := registry.attributeIdentifierKey(name)
			if _, present := presentAttributes[key]; present {
				return &Violation{
					Kind: ViolationDisallowedAttribute,
					Message: fmt.Sprintf(
						"content rule '%s' precluded attribute '%s'",
						contentRule.Name(),
						registry.attributeTypeName(name),
					),
				}
			}
		}
		allowedAuxiliary := make(map[string]struct{}, len(contentRule.Auxiliary))
		for _, name := range contentRule.Auxiliary {
			objectClass := registry.objectClasses[schemaKey(name)]
			allowedAuxiliary[schemaKey(objectClass.OID)] = struct{}{}
		}
		for _, value := range classValues {
			objectClass := registry.objectClasses[schemaKey(string(value))]
			if objectClass.Kind != ObjectClassAuxiliary {
				continue
			}
			if _, ok := allowedAuxiliary[schemaKey(objectClass.OID)]; !ok {
				return &Violation{
					Kind: ViolationStructuralObjectClass,
					Message: fmt.Sprintf(
						"class '%s' not allowed by content rule '%s'",
						objectClass.Name(),
						contentRule.Name(),
					),
				}
			}
		}
	}
	subentry := registry.hasCollectedObjectClass(classes, "subentry")
	collectiveSubentry := registry.hasCollectedObjectClass(
		classes,
		"collectiveAttributeSubentry",
	)
	if collectiveSubentry && !subentry {
		return &Violation{
			Kind:      ViolationStructuralObjectClass,
			Attribute: "objectClass",
			Message:   "collectiveAttributeSubentry requires the subentry object class",
		}
	}
	specialAttributes := []struct {
		key         string
		attribute   string
		objectClass string
	}{
		{
			key:         "aliasedobjectname",
			attribute:   "aliasedObjectName",
			objectClass: "alias",
		},
		{key: "ref", attribute: "ref", objectClass: "referral"},
		{
			key:         "subtreespecification",
			attribute:   "subtreeSpecification",
			objectClass: "subentry",
		},
	}
	for _, special := range specialAttributes {
		present := false
		for _, attribute := range entry.Attributes {
			if schemaKey(baseAttributeDescription(attribute.Description)) ==
				special.key {
				present = true
				break
			}
		}
		if !present {
			continue
		}
		objectClass, ok := registry.objectClasses[schemaKey(special.objectClass)]
		if !ok {
			return &Violation{
				Kind:      ViolationDisallowedAttribute,
				Attribute: special.attribute,
				Message: fmt.Sprintf(
					"attribute requires the %s object class",
					special.objectClass,
				),
			}
		}
		if _, ok := classes[schemaKey(objectClass.OID)]; !ok {
			return &Violation{
				Kind:      ViolationDisallowedAttribute,
				Attribute: special.attribute,
				Message: fmt.Sprintf(
					"attribute requires the %s object class",
					special.objectClass,
				),
			}
		}
	}
	type requiredAttribute struct {
		name        string
		objectClass string
		contentRule *DITContentRule
	}
	required := make(map[string]requiredAttribute)
	allowed := map[string]struct{}{
		registry.attributeIdentifierKey("objectClass"): {},
	}
	extensible := false
	for _, objectClass := range classes {
		if strings.EqualFold(objectClass.Name(), "extensibleObject") {
			extensible = true
		}
		for _, name := range objectClass.Must {
			key := registry.attributeIdentifierKey(name)
			requiringClass := structuralClass.Name()
			if objectClass.Kind == ObjectClassAuxiliary {
				requiringClass = objectClass.Name()
			}
			required[key] = requiredAttribute{
				name:        registry.attributeTypeName(name),
				objectClass: requiringClass,
			}
			allowed[key] = struct{}{}
		}
		for _, name := range objectClass.May {
			allowed[registry.attributeIdentifierKey(name)] = struct{}{}
		}
	}
	if contentRule != nil {
		for _, name := range contentRule.Must {
			key := registry.attributeIdentifierKey(name)
			required[key] = requiredAttribute{
				name:        registry.attributeTypeName(name),
				contentRule: contentRule,
			}
			allowed[key] = struct{}{}
		}
		for _, name := range contentRule.May {
			allowed[registry.attributeIdentifierKey(name)] = struct{}{}
		}
	}

	present := make(map[string]struct{}, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		baseName := baseAttributeDescription(attribute.Description)
		lookupKey := schemaKey(baseName)
		attributeType, ok := registry.attributes[lookupKey]
		if !ok {
			return &Violation{
				Kind:      ViolationUndefinedAttribute,
				Attribute: attribute.Description,
				Message:   "undefined attribute type",
			}
		}
		key := schemaKey(attributeType.OID)
		present[key] = struct{}{}
		collective, err := registry.attributeTypeIsCollective(
			attributeType,
			make(map[string]bool),
		)
		if err != nil {
			return err
		}
		if collective && !collectiveSubentry {
			return &Violation{
				Kind:      ViolationDisallowedAttribute,
				Attribute: attribute.Description,
				Message:   "collective attribute requires a collectiveAttributeSubentry",
			}
		}
		if !collective &&
			!extensible &&
			attributeType.Usage == UsageUserApplications {
			if _, ok := allowed[key]; !ok {
				return &Violation{
					Kind: ViolationDisallowedAttribute,
					Message: fmt.Sprintf(
						"attribute '%s' not allowed",
						attributeType.Name(),
					),
				}
			}
		}
		if attributeType.SingleValue && len(attribute.Values) > 1 {
			return &Violation{
				Kind:      ViolationSingleValue,
				Attribute: attribute.Description,
				Message:   "single-valued attribute has multiple values",
			}
		}
		effective, err := registry.effectiveAttributeType(attributeType, make(map[string]bool))
		if err != nil {
			return err
		}
		if err := registry.validateAttributeDescription(
			attribute.Description,
			effective,
		); err != nil {
			return &Violation{
				Kind:      ViolationUndefinedAttribute,
				Attribute: attribute.Description,
				Message:   err.Error(),
			}
		}
		for _, value := range attribute.Values {
			if options.SkipValueSyntax {
				if err := registry.validateStoredEqualityNormalizationLocked(
					effective.Equality,
					value,
				); err != nil {
					return &Violation{
						Kind:      ViolationSyntax,
						Attribute: attribute.Description,
						Message:   err.Error(),
					}
				}
				continue
			}
			if err := registry.validateSyntax(effective.Syntax, effective.SyntaxLength, value); err != nil {
				return &Violation{
					Kind:      ViolationSyntax,
					Attribute: attribute.Description,
					Message:   err.Error(),
				}
			}
			if effective.Syntax == SyntaxOpenLDAPACI {
				parsed, _ := aci.Parse(string(value))
				if err := registry.validateOpenLDAPACI(parsed); err != nil {
					return &Violation{
						Kind:      ViolationSyntax,
						Attribute: attribute.Description,
						Message:   err.Error(),
					}
				}
			}
		}
	}
	if entry.DN != "" {
		entryDN, err := directory.ParseDN(entry.DN)
		if err == nil {
			for _, namingValue := range entryDN.RDNValues() {
				attributeType, ok := registry.attributes[schemaKey(namingValue.Type)]
				if !ok {
					continue
				}
				collective, err := registry.attributeTypeIsCollective(
					attributeType,
					make(map[string]bool),
				)
				if err != nil {
					return err
				}
				if collective {
					return &Violation{
						Kind:      ViolationNaming,
						Attribute: namingValue.Type,
						Message:   "collective attribute cannot be used for naming",
					}
				}
				if attributeType.Obsolete {
					return &Violation{
						Kind:      ViolationNaming,
						Attribute: namingValue.Type,
						Message:   "obsolete attribute cannot be used for naming",
					}
				}
			}
		}
	}
	for key, requiredAttribute := range required {
		if _, ok := present[key]; !ok {
			if requiredAttribute.contentRule != nil {
				return &Violation{
					Kind: ViolationMissingRequiredAttribute,
					Message: fmt.Sprintf(
						"content rule '%s' requires attribute '%s'",
						requiredAttribute.contentRule.Name(),
						requiredAttribute.name,
					),
				}
			}
			return &Violation{
				Kind: ViolationMissingRequiredAttribute,
				Message: fmt.Sprintf(
					"object class '%s' requires attribute '%s'",
					requiredAttribute.objectClass,
					requiredAttribute.name,
				),
			}
		}
	}
	return nil
}

func (registry *Registry) validateOpenLDAPACI(value aci.Value) error {
	for _, permission := range value.Permissions {
		for _, selector := range permission.Attributes {
			if selector.All {
				continue
			}
			if _, ok := registry.attributes[schemaKey(baseAttributeDescription(selector.Name))]; !ok {
				return fmt.Errorf("ACI references unknown attribute %q", selector.Name)
			}
		}
	}
	switch value.SubjectKind {
	case aci.SubjectDNAttribute:
		attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(value.Subject))]
		if !ok {
			return fmt.Errorf("ACI dnattr references unknown attribute %q", value.Subject)
		}
		effective, err := registry.effectiveAttributeType(attribute, make(map[string]bool))
		if err != nil || effective.Syntax != SyntaxDistinguishedName {
			return fmt.Errorf("ACI dnattr %q does not use DN syntax", value.Subject)
		}
	case aci.SubjectGroup, aci.SubjectRole:
		if _, ok := registry.objectClasses[schemaKey(value.ObjectClass)]; !ok {
			return fmt.Errorf("ACI references unknown group object class %q", value.ObjectClass)
		}
		if _, ok := registry.attributes[schemaKey(baseAttributeDescription(value.GroupAttribute))]; !ok {
			return fmt.Errorf("ACI references unknown group attribute %q", value.GroupAttribute)
		}
	}
	return nil
}

func (registry *Registry) hasCollectedObjectClass(
	classes map[string]*ObjectClass,
	name string,
) bool {
	objectClass, ok := registry.objectClasses[schemaKey(name)]
	if !ok {
		return false
	}
	_, ok = classes[schemaKey(objectClass.OID)]
	return ok
}

func (registry *Registry) validateCollectiveAttributeType(attribute AttributeType) error {
	if attribute.Collective {
		if attribute.Usage != UsageUserApplications {
			return fmt.Errorf(
				"collective attribute type %q must have userApplications usage",
				attribute.Name(),
			)
		}
		if attribute.SingleValue {
			return fmt.Errorf(
				"collective attribute type %q cannot be single-valued",
				attribute.Name(),
			)
		}
		for _, objectClass := range uniqueObjectClasses(registry.objectClasses) {
			for _, name := range append(
				append([]string(nil), objectClass.Must...),
				objectClass.May...,
			) {
				if attributeTypeIdentifierMatches(attribute, name) {
					return fmt.Errorf(
						"collective attribute type %q is referenced by object class %q",
						attribute.Name(),
						objectClass.Name(),
					)
				}
			}
		}
	}

	if attribute.Superior != "" {
		superior, ok := registry.attributes[schemaKey(attribute.Superior)]
		if ok {
			collective, err := registry.attributeTypeIsCollective(
				superior,
				make(map[string]bool),
			)
			if err != nil {
				return err
			}
			if collective && !attribute.Collective {
				return fmt.Errorf(
					"non-collective attribute type %q cannot subtype collective attribute %q",
					attribute.Name(),
					superior.Name(),
				)
			}
		}
	}
	if !attribute.Collective {
		return nil
	}
	candidateKeys := schemaKeys(attribute.OID, attribute.Names)
	for _, existing := range uniqueAttributeTypes(registry.attributes) {
		if existing.Collective {
			continue
		}
		for _, key := range candidateKeys {
			if schemaKey(existing.Superior) == key {
				return fmt.Errorf(
					"collective attribute type %q has non-collective subtype %q",
					attribute.Name(),
					existing.Name(),
				)
			}
		}
	}
	return nil
}

func (registry *Registry) validateObjectClassCollectiveAttributes(
	objectClass ObjectClass,
) error {
	attributes := append(append([]string(nil), objectClass.Must...), objectClass.May...)
	for _, name := range attributes {
		attribute, ok := registry.attributes[schemaKey(name)]
		if !ok {
			continue
		}
		collective, err := registry.attributeTypeIsCollective(
			attribute,
			make(map[string]bool),
		)
		if err != nil {
			return err
		}
		if collective {
			return fmt.Errorf(
				"object class %q cannot reference collective attribute type %q",
				objectClass.Name(),
				attribute.Name(),
			)
		}
	}
	return nil
}

func (registry *Registry) validateDITContentRule(
	contentRule DITContentRule,
) error {
	structural, ok := registry.objectClasses[schemaKey(contentRule.OID)]
	if !ok {
		return fmt.Errorf(
			"DIT content rule %q references unknown structural object class %q",
			contentRule.Name(),
			contentRule.OID,
		)
	}
	if structural.Kind != ObjectClassStructural {
		return fmt.Errorf(
			"DIT content rule %q references non-structural object class %q",
			contentRule.Name(),
			structural.Name(),
		)
	}

	for _, name := range contentRule.Auxiliary {
		auxiliary, ok := registry.objectClasses[schemaKey(name)]
		if !ok {
			return fmt.Errorf(
				"DIT content rule %q references unknown auxiliary object class %q",
				contentRule.Name(),
				name,
			)
		}
		if auxiliary.Kind != ObjectClassAuxiliary {
			return fmt.Errorf(
				"DIT content rule %q references non-auxiliary object class %q",
				contentRule.Name(),
				auxiliary.Name(),
			)
		}
	}

	seen := make(map[string]string)
	for _, field := range []struct {
		name   string
		values []string
	}{
		{name: "MUST", values: contentRule.Must},
		{name: "MAY", values: contentRule.May},
		{name: "NOT", values: contentRule.Not},
	} {
		for _, name := range field.values {
			attribute, ok := registry.attributes[schemaKey(name)]
			if !ok {
				return fmt.Errorf(
					"DIT content rule %q %s references unknown attribute type %q",
					contentRule.Name(),
					field.name,
					name,
				)
			}
			effective, err := registry.effectiveAttributeType(
				attribute,
				make(map[string]bool),
			)
			if err != nil {
				return err
			}
			if effective.Usage != UsageUserApplications {
				return fmt.Errorf(
					"DIT content rule %q %s references operational attribute type %q",
					contentRule.Name(),
					field.name,
					attribute.Name(),
				)
			}
			key := schemaKey(attribute.OID)
			if previous, duplicate := seen[key]; duplicate {
				return fmt.Errorf(
					"DIT content rule %q repeats attribute type %q in %s and %s",
					contentRule.Name(),
					attribute.Name(),
					previous,
					field.name,
				)
			}
			seen[key] = field.name
		}
	}
	return nil
}

func (registry *Registry) normalizeNameForm(nameForm NameForm) (NameForm, error) {
	if nameForm.OID == "" ||
		nameForm.OID[0] < '0' ||
		nameForm.OID[0] > '9' ||
		!validObjectIdentifier(nameForm.OID) {
		return NameForm{}, fmt.Errorf(
			"name form %q requires a numeric OID",
			nameForm.Name(),
		)
	}
	structural, ok := registry.objectClasses[schemaKey(nameForm.ObjectClass)]
	if !ok {
		return NameForm{}, fmt.Errorf(
			"name form %q references unknown object class %q",
			nameForm.Name(),
			nameForm.ObjectClass,
		)
	}
	if structural.Kind != ObjectClassStructural {
		return NameForm{}, fmt.Errorf(
			"name form %q references non-structural object class %q",
			nameForm.Name(),
			structural.Name(),
		)
	}
	if len(nameForm.Must) == 0 {
		return NameForm{}, fmt.Errorf(
			"name form %q requires at least one MUST attribute",
			nameForm.Name(),
		)
	}

	normalized := cloneNameForm(nameForm)
	normalized.ObjectClass = structural.OID
	seen := make(map[string]string)
	for _, field := range []struct {
		name   string
		values []string
	}{
		{name: "MUST", values: normalized.Must},
		{name: "MAY", values: normalized.May},
	} {
		for _, name := range field.values {
			attribute, ok := registry.attributes[schemaKey(name)]
			if !ok {
				return NameForm{}, fmt.Errorf(
					"name form %q %s references unknown attribute type %q",
					normalized.Name(),
					field.name,
					name,
				)
			}
			effective, err := registry.effectiveAttributeType(
				attribute,
				make(map[string]bool),
			)
			if err != nil {
				return NameForm{}, err
			}
			if effective.Usage != UsageUserApplications {
				return NameForm{}, fmt.Errorf(
					"name form %q %s references operational attribute type %q",
					normalized.Name(),
					field.name,
					attribute.Name(),
				)
			}
			collective, err := registry.attributeTypeIsCollective(
				attribute,
				make(map[string]bool),
			)
			if err != nil {
				return NameForm{}, err
			}
			if collective {
				return NameForm{}, fmt.Errorf(
					"name form %q %s references collective attribute type %q",
					normalized.Name(),
					field.name,
					attribute.Name(),
				)
			}
			key := schemaKey(attribute.OID)
			if previous, duplicate := seen[key]; duplicate {
				return NameForm{}, fmt.Errorf(
					"name form %q repeats attribute type %q in %s and %s",
					normalized.Name(),
					attribute.Name(),
					previous,
					field.name,
				)
			}
			seen[key] = field.name
		}
	}
	return normalized, nil
}

func (registry *Registry) normalizeDITStructureRule(
	structureRule DITStructureRule,
) (DITStructureRule, error) {
	if structureRule.RuleID < 0 {
		return DITStructureRule{}, fmt.Errorf(
			"DIT structure rule ID %d must not be negative",
			structureRule.RuleID,
		)
	}
	nameForm, ok := registry.nameForms[schemaKey(structureRule.Form)]
	if !ok {
		return DITStructureRule{}, fmt.Errorf(
			"DIT structure rule %q references unknown name form %q",
			structureRule.Name(),
			structureRule.Form,
		)
	}
	normalized := cloneDITStructureRule(structureRule)
	normalized.Form = nameForm.OID
	return normalized, nil
}

func (registry *Registry) validateDITStructureRuleGraph(
	candidate DITStructureRule,
	replace bool,
) error {
	rules := make(map[int]DITStructureRule)
	for _, structureRule := range uniqueDITStructureRules(registry.structureRules) {
		rules[structureRule.RuleID] = structureRule
	}
	if _, exists := rules[candidate.RuleID]; exists && !replace {
		return fmt.Errorf(
			"DIT structure rule ID %d is already registered",
			candidate.RuleID,
		)
	}
	rules[candidate.RuleID] = candidate
	for ruleID, structureRule := range rules {
		seen := make(map[int]struct{}, len(structureRule.Superiors))
		for _, superior := range structureRule.Superiors {
			if superior == ruleID {
				return fmt.Errorf(
					"DIT structure rule %d cannot be its own superior",
					ruleID,
				)
			}
			if _, duplicate := seen[superior]; duplicate {
				return fmt.Errorf(
					"DIT structure rule %d repeats superior rule %d",
					ruleID,
					superior,
				)
			}
			seen[superior] = struct{}{}
			if _, exists := rules[superior]; !exists {
				return fmt.Errorf(
					"DIT structure rule %d references unknown superior rule %d",
					ruleID,
					superior,
				)
			}
		}
	}

	state := make(map[int]uint8, len(rules))
	var visit func(int) error
	visit = func(ruleID int) error {
		switch state[ruleID] {
		case 1:
			return fmt.Errorf(
				"DIT structure rule hierarchy contains a cycle at rule %d",
				ruleID,
			)
		case 2:
			return nil
		}
		state[ruleID] = 1
		for _, superior := range rules[ruleID].Superiors {
			if err := visit(superior); err != nil {
				return err
			}
		}
		state[ruleID] = 2
		return nil
	}
	for ruleID := range rules {
		if err := visit(ruleID); err != nil {
			return err
		}
	}
	return nil
}

func attributeTypeIdentifierMatches(attribute AttributeType, identifier string) bool {
	identifier = schemaKey(identifier)
	for _, key := range schemaKeys(attribute.OID, attribute.Names) {
		if key == identifier {
			return true
		}
	}
	return false
}

func (registry *Registry) attributeTypeIsCollective(
	attribute *AttributeType,
	visiting map[string]bool,
) (bool, error) {
	if attribute.Collective {
		return true, nil
	}
	if attribute.Superior == "" {
		return false, nil
	}
	key := schemaKey(attribute.OID)
	if visiting[key] {
		return false, fmt.Errorf(
			"attribute type inheritance cycle at %q",
			attribute.Name(),
		)
	}
	visiting[key] = true
	superior, ok := registry.attributes[schemaKey(attribute.Superior)]
	if !ok {
		return false, nil
	}
	return registry.attributeTypeIsCollective(superior, visiting)
}

func (registry *Registry) collectObjectClass(
	objectClass *ObjectClass,
	classes map[string]*ObjectClass,
	visiting map[string]bool,
) error {
	key := schemaKey(objectClass.OID)
	if _, exists := classes[key]; exists {
		return nil
	}
	if visiting[key] {
		return fmt.Errorf("object class inheritance cycle at %q", objectClass.Name())
	}
	visiting[key] = true
	for _, superiorName := range objectClass.Superiors {
		superior, ok := registry.objectClasses[schemaKey(superiorName)]
		if !ok {
			return fmt.Errorf("object class %q has unknown superior %q", objectClass.Name(), superiorName)
		}
		if err := registry.collectObjectClass(superior, classes, visiting); err != nil {
			return err
		}
	}
	delete(visiting, key)
	classes[key] = objectClass
	return nil
}

func (registry *Registry) validateStructuralClasses(classes map[string]*ObjectClass) error {
	var structural []*ObjectClass
	for _, objectClass := range classes {
		if objectClass.Kind == ObjectClassStructural {
			structural = append(structural, objectClass)
		}
	}
	if len(structural) == 0 {
		return &Violation{
			Kind:    ViolationStructuralObjectClass,
			Message: "entry has no structural object class",
		}
	}
	for i := range structural {
		for j := i + 1; j < len(structural); j++ {
			if !registry.isSubclass(structural[i], structural[j], make(map[string]bool)) &&
				!registry.isSubclass(structural[j], structural[i], make(map[string]bool)) {
				return &Violation{
					Kind: ViolationStructuralObjectClass,
					Message: fmt.Sprintf(
						"unrelated structural object classes %q and %q",
						structural[i].Name(),
						structural[j].Name(),
					),
				}
			}
		}
	}
	return nil
}

func (registry *Registry) mostSpecificStructuralClass(
	classes map[string]*ObjectClass,
) (*ObjectClass, error) {
	for _, candidate := range classes {
		if candidate.Kind != ObjectClassStructural {
			continue
		}
		mostSpecific := true
		for _, other := range classes {
			if other.Kind == ObjectClassStructural &&
				!registry.isSubclass(candidate, other, make(map[string]bool)) {
				mostSpecific = false
				break
			}
		}
		if mostSpecific {
			return candidate, nil
		}
	}
	return nil, &Violation{
		Kind:    ViolationStructuralObjectClass,
		Message: "entry has no structural object class",
	}
}

func (registry *Registry) attributeIdentifierKey(name string) string {
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return schemaKey(baseAttributeDescription(name))
	}
	return schemaKey(attribute.OID)
}

func (registry *Registry) attributeTypeName(name string) string {
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return baseAttributeDescription(name)
	}
	return attribute.Name()
}

func (registry *Registry) isSubclass(
	candidate, ancestor *ObjectClass,
	visited map[string]bool,
) bool {
	if schemaKey(candidate.OID) == schemaKey(ancestor.OID) {
		return true
	}
	key := schemaKey(candidate.OID)
	if visited[key] {
		return false
	}
	visited[key] = true
	for _, superiorName := range candidate.Superiors {
		superior, ok := registry.objectClasses[schemaKey(superiorName)]
		if ok && registry.isSubclass(superior, ancestor, visited) {
			return true
		}
	}
	return false
}

func (registry *Registry) effectiveAttributeType(
	attribute *AttributeType,
	visiting map[string]bool,
) (AttributeType, error) {
	result := *attribute
	if attribute.Superior == "" {
		return result, nil
	}
	key := schemaKey(attribute.OID)
	if visiting[key] {
		return AttributeType{}, fmt.Errorf("attribute type inheritance cycle at %q", attribute.Name())
	}
	visiting[key] = true
	superior, ok := registry.attributes[schemaKey(attribute.Superior)]
	if !ok {
		return AttributeType{}, fmt.Errorf(
			"attribute type %q has unknown superior %q",
			attribute.Name(),
			attribute.Superior,
		)
	}
	inherited, err := registry.effectiveAttributeType(superior, visiting)
	if err != nil {
		return AttributeType{}, err
	}
	if result.Equality == "" {
		result.Equality = inherited.Equality
	}
	if result.Ordering == "" {
		result.Ordering = inherited.Ordering
	}
	if result.Substring == "" {
		result.Substring = inherited.Substring
	}
	if result.Syntax == "" {
		result.Syntax = inherited.Syntax
		result.SyntaxLength = inherited.SyntaxLength
	}
	return result, nil
}

func (registry *Registry) attributeDescriptionSubtype(
	candidate,
	requested string,
) bool {
	candidateTypeName, candidateOptions := splitAttributeDescription(candidate)
	requestedTypeName, requestedOptions := splitAttributeDescription(requested)
	candidateType, candidateKnown := registry.attributes[schemaKey(candidateTypeName)]
	requestedType, requestedKnown := registry.attributes[schemaKey(requestedTypeName)]
	if !candidateKnown || !requestedKnown {
		return schemaKey(candidateTypeName) == schemaKey(requestedTypeName) &&
			attributeOptionsSubtype(candidateOptions, requestedOptions)
	}
	if !registry.attributeTypeSubtype(
		candidateType,
		requestedType,
		make(map[string]bool),
	) {
		return false
	}
	return attributeOptionsSubtype(candidateOptions, requestedOptions)
}

func attributeOptionsSubtype(
	candidate,
	requested map[string]struct{},
) bool {
	for requestedOption := range requested {
		matched := false
		for candidateOption := range candidate {
			if candidateOption == requestedOption ||
				(strings.HasSuffix(requestedOption, "-") &&
					(candidateOption == strings.TrimSuffix(requestedOption, "-") ||
						strings.HasPrefix(candidateOption, requestedOption))) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (registry *Registry) attributeTypeSubtype(
	candidate,
	ancestor *AttributeType,
	visiting map[string]bool,
) bool {
	if strings.EqualFold(candidate.OID, ancestor.OID) {
		return true
	}
	key := schemaKey(candidate.OID)
	if visiting[key] || candidate.Superior == "" {
		return false
	}
	visiting[key] = true
	superior, ok := registry.attributes[schemaKey(candidate.Superior)]
	return ok && registry.attributeTypeSubtype(superior, ancestor, visiting)
}

func splitAttributeDescription(
	description string,
) (string, map[string]struct{}) {
	parts := strings.Split(strings.TrimSpace(description), ";")
	options := make(map[string]struct{}, len(parts)-1)
	for _, option := range parts[1:] {
		options[schemaKey(option)] = struct{}{}
	}
	return parts[0], options
}

func (registry *Registry) configureAttributeOptions(values []string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(values) == 0 {
		return nil
	}
	configured := make([]string, 0)
	for _, raw := range values {
		for _, option := range strings.Fields(raw) {
			key := strings.ToLower(option)
			if !validAttributeOptionDefinition(key) {
				return fmt.Errorf("invalid attribute option definition %q", option)
			}
			if key == "binary" {
				return errors.New("attribute option \"binary\" is already defined")
			}
			for _, existing := range configured {
				if attributeOptionDefinitionMatches(existing, key) ||
					attributeOptionDefinitionMatches(key, existing) {
					return fmt.Errorf(
						"attribute option %q conflicts with %q",
						option,
						existing,
					)
				}
			}
			configured = append(configured, key)
		}
	}
	registry.attributeOptions = configured
	return nil
}

func (registry *Registry) validateAttributeDescription(
	description string,
	attribute AttributeType,
) error {
	if description == "" || strings.TrimSpace(description) != description {
		return errors.New("invalid AttributeDescription")
	}
	parts := strings.Split(description, ";")
	if !validObjectIdentifier(parts[0]) {
		return errors.New("AttributeDescription contains inappropriate characters")
	}
	if len(parts) > 1 && attribute.Usage != UsageUserApplications {
		return errors.New("operational attribute with options undefined")
	}
	binarySyntax := registry.syntaxRequiresBinaryTransfer(attribute.Syntax)
	allowEquals := registry.attributeOptionsAllowEquals()
	binary := false
	seen := make(map[string]struct{}, len(parts)-1)
	tagBytes := 0
	for _, rawOption := range parts[1:] {
		option := strings.ToLower(rawOption)
		if !validAttributeOption(option, allowEquals) {
			return errors.New("invalid attribute option")
		}
		if option == "binary" {
			if binary {
				return errors.New("option \"binary\" specified multiple times")
			}
			if !binarySyntax {
				return errors.New("option \"binary\" not supported with type")
			}
			binary = true
			continue
		}
		if !registry.attributeOptionAllowed(option) {
			return fmt.Errorf("unrecognized attribute option %q", rawOption)
		}
		if _, duplicate := seen[option]; duplicate {
			continue
		}
		seen[option] = struct{}{}
		tagBytes += len(option) + 1
		if len(seen) > 128 || tagBytes > 1024 {
			return errors.New("too many or too long attribute options")
		}
	}
	if binarySyntax && !binary {
		return fmt.Errorf("attribute needs ';binary' transfer as required by syntax %s", attribute.Syntax)
	}
	return nil
}

func (registry *Registry) attributeOptionAllowed(option string) bool {
	for _, definition := range registry.attributeOptions {
		if attributeOptionDefinitionMatches(definition, option) {
			return true
		}
	}
	return false
}

func (registry *Registry) attributeOptionsAllowEquals() bool {
	for _, definition := range registry.attributeOptions {
		if strings.HasSuffix(definition, "=") {
			return true
		}
	}
	return false
}

func attributeOptionDefinitionMatches(definition, option string) bool {
	return option == definition ||
		((strings.HasSuffix(definition, "-") ||
			strings.HasSuffix(definition, "=")) &&
			strings.HasPrefix(option, definition))
}

func validAttributeOptionDefinition(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range []byte(value) {
		if character == '=' && index == len(value)-1 {
			continue
		}
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validAttributeOption(value string, allowEquals bool) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '.' {
			if allowEquals && character == '=' {
				continue
			}
			return false
		}
	}
	return true
}

func (registry *Registry) validateStoredEqualityNormalizationLocked(
	rule string,
	value []byte,
) error {
	switch canonicalMatchingRule(rule) {
	case "openldapacimatch":
		_, err := aci.Normalize(value)
		return err
	case "distinguishednamematch":
		_, err := registry.normalizeWithRuleLocked(rule, value)
		return err
	case "uniquemembermatch":
		_, err := registry.normalizeWithRuleLocked(rule, value)
		return err
	case "uuidmatch", "uuidorderingmatch":
		return validateSyntax(SyntaxUUID, 0, value)
	case "generalizedtimematch", "generalizedtimeorderingmatch":
		_, err := normalizeGeneralizedTime(value)
		return err
	case "authzmatch":
		return validateAuthzSyntax(value)
	case "csnmatch", "csnorderingmatch":
		_, ok := normalizeCSN(value)
		if !ok {
			return errors.New("CSN matching received an invalid value")
		}
		return nil
	case "caseignorematch", "caseignoreorderingmatch", "caseexactmatch",
		"caseexactorderingmatch":
		if !utf8.Valid(value) {
			return errors.New("matching rule normalization received invalid UTF-8")
		}
	case "caseignoreia5match", "caseignoreia5orderingmatch",
		"caseexactia5match", "caseexactia5orderingmatch":
		return nil
	}
	return nil
}

func validateSyntax(syntax string, maxLength int, value []byte) error {
	if maxLength > 0 && len(value) > maxLength {
		return fmt.Errorf("value exceeds syntax length %d", maxLength)
	}
	switch syntax {
	case "", SyntaxOctetString, SyntaxAuthenticationPassword:
		return nil
	case SyntaxOpenLDAPACI:
		if _, err := aci.Parse(string(value)); err != nil {
			return fmt.Errorf("value is not valid OpenLDAP ACI: %w", err)
		}
	case SyntaxDirectoryString:
		if len(value) == 0 || !utf8.Valid(value) {
			return errors.New("value is not a valid non-empty Directory String")
		}
	case SyntaxAuthz:
		if err := validateAuthzSyntax(value); err != nil {
			return err
		}
	case SyntaxIA5String:
		for _, character := range value {
			if character > 0x7f {
				return errors.New("value is not IA5")
			}
		}
	case SyntaxNumericString:
		if len(value) == 0 {
			return errors.New("value is not a non-empty Numeric String")
		}
		for _, character := range value {
			if character != ' ' && (character < '0' || character > '9') {
				return errors.New("value is not a Numeric String")
			}
		}
	case SyntaxPostalAddress:
		if !validPostalAddress(value) {
			return errors.New("value is not a postal address")
		}
	case SyntaxPrintableString:
		if !validPrintableString(value) {
			return errors.New("value is not a Printable String")
		}
	case SyntaxTelephoneNumber:
		if !validPrintableString(value) {
			return errors.New("value is not a telephone number")
		}
	case SyntaxTelexNumber, SyntaxFacsimileTelephone:
		if !validPrintableStringList(value) {
			return errors.New("value is not a printable string list")
		}
	case SyntaxInteger:
		if !validLDAPInteger(value) {
			return errors.New("value is not an integer")
		}
	case SyntaxBoolean:
		if string(value) != "TRUE" && string(value) != "FALSE" {
			return errors.New("value is not an LDAP boolean")
		}
	case SyntaxDistinguishedName:
		if _, err := directory.ParseDN(string(value)); err != nil {
			return errors.New("value is not a distinguished name")
		}
	case SyntaxNameAndOptionalUID:
		dn, _, _ := splitNameAndOptionalUID(value)
		if len(dn) > 0 {
			if _, err := directory.ParseDN(string(dn)); err != nil {
				return errors.New("value is not a name and optional UID")
			}
		}
	case SyntaxSubtreeSpecification:
		if _, err := ParseSubtreeSpecification(string(value)); err != nil {
			return fmt.Errorf("value is not a valid subtree specification: %w", err)
		}
	case SyntaxDITContentRule:
		if _, err := ParseDITContentRule(string(value)); err != nil {
			return fmt.Errorf("value is not a DIT content rule description: %w", err)
		}
	case SyntaxDITStructureRule:
		if _, err := ParseDITStructureRule(string(value)); err != nil {
			return fmt.Errorf("value is not a DIT structure rule description: %w", err)
		}
	case SyntaxNameForm:
		if _, err := ParseNameForm(string(value)); err != nil {
			return fmt.Errorf("value is not a name form description: %w", err)
		}
	case SyntaxAttributeType:
		if _, err := ParseAttributeType(string(value)); err != nil {
			return fmt.Errorf("value is not an attribute type description: %w", err)
		}
	case SyntaxObjectClass:
		if _, err := ParseObjectClass(string(value)); err != nil {
			return fmt.Errorf("value is not an object class description: %w", err)
		}
	case SyntaxOID:
		if !validObjectIdentifier(string(value)) {
			return errors.New("value is not an object identifier")
		}
	case SyntaxGeneralizedTime:
		if !validGeneralizedTime(value) {
			return errors.New("value is not generalized time")
		}
	case SyntaxUUID:
		if !validUUID(value) {
			return errors.New("value is not a UUID")
		}
	case SyntaxCSN:
		if _, ok := normalizeCSN(value); !ok {
			return errors.New("value is not a CSN")
		}
	case SyntaxCertificate:
		return validateCertificate(value)
	case SyntaxCertificateList:
		return validateCertificateList(value)
	case SyntaxCertificatePair:
		return validateCertificatePair(value)
	case SyntaxSupportedAlgorithm:
		return validateBlob(value)
	case SyntaxAttributeCertificate:
		return validateAttributeCertificate(value)
	case SyntaxPKCS8PrivateKey:
		return validatePKCS8PrivateKey(value)
	case SyntaxACIItem:
		return fmt.Errorf("no validator for syntax %s", syntax)
	case SyntaxOpenLDAPVoid:
		return nil
	default:
		return fmt.Errorf("unsupported syntax %q", syntax)
	}
	return nil
}

func validUUID(value []byte) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') &&
				(character < 'A' || character > 'F') {
				return false
			}
		}
	}
	return true
}

func normalizeCSN(value []byte) (string, bool) {
	parts := strings.Split(string(value), "#")
	if len(parts) != 4 ||
		len(parts[1]) != 6 ||
		(len(parts[2]) != 2 && len(parts[2]) != 3) ||
		len(parts[3]) != 6 {
		return "", false
	}
	timestamp, ok := normalizeCSNTimestamp(parts[0])
	if !ok {
		return "", false
	}
	for _, field := range parts[1:] {
		for index := range field {
			if !isHexDigit(field[index]) {
				return "", false
			}
		}
	}
	sid := strings.ToLower(parts[2])
	if len(sid) == 2 {
		sid = "0" + sid
	}
	return timestamp +
		"#" + strings.ToLower(parts[1]) +
		"#" + sid +
		"#" + strings.ToLower(parts[3]), true
}

func normalizeCSNTimestamp(value string) (string, bool) {
	var fraction string
	switch len(value) {
	case len("20060102150405Z"):
		if value[len(value)-1] != 'Z' {
			return "", false
		}
		fraction = "000000"
	case len("20060102150405.000000Z"):
		if (value[14] != '.' && value[14] != ',') ||
			value[len(value)-1] != 'Z' {
			return "", false
		}
		fraction = value[15 : len(value)-1]
		for index := range fraction {
			if fraction[index] < '0' || fraction[index] > '9' {
				return "", false
			}
		}
	default:
		return "", false
	}
	base := value[:14]
	for index := range base {
		if base[index] < '0' || base[index] > '9' {
			return "", false
		}
	}
	parseBase := base
	if base[12:] == "60" {
		parseBase = base[:12] + "59"
	}
	if _, err := time.Parse("20060102150405", parseBase); err != nil {
		return "", false
	}
	return base + "." + fraction + "Z", true
}

func isHexDigit(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}

// compareWithRule is the context-free fallback for matching rules whose
// semantics do not depend on a Registry. Registry.Compare intercepts DN-valued
// rules before reaching this function.
func compareWithRule(rule string, left, right []byte) (int, error) {
	switch canonicalMatchingRule(rule) {
	case "openldapacimatch":
		return aci.Compare(left, right)
	case "caseignorematch",
		"caseignoreia5match",
		"caseignoreorderingmatch",
		"caseignoreia5orderingmatch":
		return bytes.Compare(normalizeCaseIgnore(left), normalizeCaseIgnore(right)), nil
	case "caseexactmatch",
		"caseexactia5match",
		"caseexactorderingmatch",
		"caseexactia5orderingmatch":
		return bytes.Compare(normalizeSpace(left), normalizeSpace(right)), nil
	case "caseignorelistmatch":
		return bytes.Compare(
			normalizeCaseIgnoreList(left),
			normalizeCaseIgnoreList(right),
		), nil
	case "telephonenumbermatch":
		return bytes.Compare(
			normalizeTelephoneNumber(left),
			normalizeTelephoneNumber(right),
		), nil
	case "numericstringmatch", "numericstringorderingmatch":
		return bytes.Compare(
			normalizeNumericString(left),
			normalizeNumericString(right),
		), nil
	case "octetstringmatch", "octetstringorderingmatch":
		return bytes.Compare(left, right), nil
	case "authzmatch":
		normalizedLeft, leftErr := normalizeWithRule(rule, left)
		normalizedRight, rightErr := normalizeWithRule(rule, right)
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("authzMatch received an invalid value")
		}
		return bytes.Compare(normalizedLeft, normalizedRight), nil
	case "objectidentifiermatch":
		return strings.Compare(strings.ToLower(string(left)), strings.ToLower(string(right))), nil
	case "objectidentifierfirstcomponentmatch":
		firstComponent, err := schemaDescriptionFirstComponent(left)
		if err != nil {
			return 0, fmt.Errorf(
				"objectIdentifierFirstComponentMatch received an invalid description: %w",
				err,
			)
		}
		return strings.Compare(
			strings.ToLower(firstComponent),
			strings.ToLower(strings.TrimSpace(string(right))),
		), nil
	case "integermatch", "integerorderingmatch":
		return compareLDAPIntegers(left, right)
	case "integerfirstcomponentmatch":
		firstComponent, err := schemaDescriptionFirstComponent(left)
		if err != nil {
			return 0, fmt.Errorf(
				"integerFirstComponentMatch received an invalid description: %w",
				err,
			)
		}
		comparison, err := compareLDAPIntegers(
			[]byte(firstComponent),
			[]byte(strings.TrimSpace(string(right))),
		)
		if err != nil {
			return 0, errors.New(
				"integerFirstComponentMatch received an invalid integer",
			)
		}
		return comparison, nil
	case "booleanmatch":
		return strings.Compare(strings.ToUpper(string(left)), strings.ToUpper(string(right))), nil
	case "distinguishednamematch":
		leftDN, leftErr := directory.ParseDN(string(left))
		rightDN, rightErr := directory.ParseDN(string(right))
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("distinguishedNameMatch received invalid DN")
		}
		return strings.Compare(leftDN.Key(), rightDN.Key()), nil
	case "uniquemembermatch":
		return compareUniqueMember(left, right)
	case "uuidmatch", "uuidorderingmatch":
		return strings.Compare(strings.ToLower(string(left)), strings.ToLower(string(right))), nil
	case "generalizedtimematch", "generalizedtimeorderingmatch":
		normalizedLeft, leftErr := normalizeGeneralizedTime(left)
		normalizedRight, rightErr := normalizeGeneralizedTime(right)
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("generalized time matching received an invalid value")
		}
		if canonicalMatchingRule(rule) == "generalizedtimeorderingmatch" {
			leftTime := normalizedLeft[:len(normalizedLeft)-1]
			rightTime := normalizedRight[:len(normalizedRight)-1]
			return bytes.Compare(leftTime, rightTime), nil
		}
		return bytes.Compare(normalizedLeft, normalizedRight), nil
	case "csnmatch", "csnorderingmatch":
		normalizedLeft, leftOK := normalizeCSN(left)
		normalizedRight, rightOK := normalizeCSN(right)
		if !leftOK || !rightOK {
			return 0, errors.New("CSN matching received an invalid value")
		}
		return strings.Compare(normalizedLeft, normalizedRight), nil
	default:
		return 0, fmt.Errorf("unsupported matching rule %q", rule)
	}
}

// normalizeWithRule is the context-free fallback for matching rules whose
// semantics do not depend on a Registry. Registry normalization APIs intercept
// distinguishedNameMatch and uniqueMemberMatch before reaching this function.
func normalizeWithRule(rule string, value []byte) ([]byte, error) {
	switch canonicalMatchingRule(rule) {
	case "openldapacimatch":
		return aci.Normalize(value)
	case "caseignorematch",
		"caseignoreia5match",
		"caseignoreorderingmatch",
		"caseignoreia5orderingmatch":
		return normalizeCaseIgnore(value), nil
	case "caseexactmatch",
		"caseexactia5match",
		"caseexactorderingmatch",
		"caseexactia5orderingmatch":
		return normalizeSpace(value), nil
	case "caseignorelistmatch":
		return normalizeCaseIgnoreList(value), nil
	case "telephonenumbermatch":
		return normalizeTelephoneNumber(value), nil
	case "numericstringmatch", "numericstringorderingmatch":
		return normalizeNumericString(value), nil
	case "octetstringmatch", "octetstringorderingmatch",
		"objectidentifierfirstcomponentmatch", "integerfirstcomponentmatch":
		return bytes.Clone(value), nil
	case "authzmatch":
		if err := validateAuthzSyntax(value); err != nil {
			return nil, err
		}
		return bytes.Clone(value), nil
	case "objectidentifiermatch":
		return bytes.ToLower(value), nil
	case "integermatch", "integerorderingmatch":
		return bytes.Clone(value), nil
	case "booleanmatch":
		return bytes.ToUpper(value), nil
	case "distinguishednamematch":
		dn, err := directory.ParseDN(string(value))
		if err != nil {
			return nil, errors.New("distinguishedNameMatch received invalid DN")
		}
		return []byte(dn.Key()), nil
	case "uniquemembermatch":
		return normalizeUniqueMember(value)
	case "uuidmatch", "uuidorderingmatch":
		return bytes.ToLower(value), nil
	case "generalizedtimematch", "generalizedtimeorderingmatch":
		return normalizeGeneralizedTime(value)
	case "csnmatch", "csnorderingmatch":
		normalized, ok := normalizeCSN(value)
		if !ok {
			return nil, errors.New("CSN matching received an invalid value")
		}
		return []byte(normalized), nil
	default:
		return nil, fmt.Errorf("unsupported matching rule %q", rule)
	}
}

func supportedMatchingRule(rule string) bool {
	switch canonicalMatchingRule(rule) {
	case "openldapacimatch",
		"caseignorematch",
		"caseignoreia5match",
		"caseignoreorderingmatch",
		"caseignoreia5orderingmatch",
		"caseexactmatch",
		"caseexactia5match",
		"caseexactorderingmatch",
		"caseexactia5orderingmatch",
		"caseignorelistmatch",
		"telephonenumbermatch",
		"numericstringmatch",
		"numericstringorderingmatch",
		"octetstringmatch",
		"octetstringorderingmatch",
		"authzmatch",
		"objectidentifiermatch",
		"objectidentifierfirstcomponentmatch",
		"integermatch",
		"integerorderingmatch",
		"integerfirstcomponentmatch",
		"booleanmatch",
		"distinguishednamematch",
		"uniquemembermatch",
		"uuidmatch",
		"uuidorderingmatch",
		"generalizedtimematch",
		"generalizedtimeorderingmatch",
		"csnmatch",
		"csnorderingmatch":
		return true
	default:
		return false
	}
}

func canonicalMatchingRule(rule string) string {
	normalized := strings.ToLower(strings.TrimSpace(rule))
	switch normalized {
	case "1.3.6.1.4.1.4203.666.4.2":
		return "openldapacimatch"
	case "2.5.13.0":
		return "objectidentifiermatch"
	case "2.5.13.29":
		return "integerfirstcomponentmatch"
	case "2.5.13.30":
		return "objectidentifierfirstcomponentmatch"
	case "2.5.13.1":
		return "distinguishednamematch"
	case "2.5.13.23":
		return "uniquemembermatch"
	case "2.5.13.2":
		return "caseignorematch"
	case "2.5.13.3":
		return "caseignoreorderingmatch"
	case "2.5.13.5":
		return "caseexactmatch"
	case "2.5.13.6":
		return "caseexactorderingmatch"
	case "2.5.13.8":
		return "numericstringmatch"
	case "2.5.13.9":
		return "numericstringorderingmatch"
	case "2.5.13.10":
		return "numericstringsubstringsmatch"
	case "2.5.13.11":
		return "caseignorelistmatch"
	case "2.5.13.12":
		return "caseignorelistsubstringsmatch"
	case "2.5.13.13":
		return "booleanmatch"
	case "2.5.13.14":
		return "integermatch"
	case "2.5.13.15":
		return "integerorderingmatch"
	case "2.5.13.17":
		return "octetstringmatch"
	case "2.5.13.18":
		return "octetstringorderingmatch"
	case "2.5.13.20":
		return "telephonenumbermatch"
	case "2.5.13.21":
		return "telephonenumbersubstringsmatch"
	case "2.5.13.27":
		return "generalizedtimematch"
	case "2.5.13.28":
		return "generalizedtimeorderingmatch"
	case "1.3.6.1.4.1.1466.109.114.1":
		return "caseexactia5match"
	case "1.3.6.1.4.1.1466.109.114.2":
		return "caseignoreia5match"
	case "1.3.6.1.1.16.2":
		return "uuidmatch"
	case "1.3.6.1.1.16.3":
		return "uuidorderingmatch"
	case "1.3.6.1.4.1.4203.666.11.2.2":
		return "csnmatch"
	case "1.3.6.1.4.1.4203.666.11.2.3":
		return "csnorderingmatch"
	case "1.3.6.1.4.1.4203.666.4.12":
		return "authzmatch"
	default:
		return normalized
	}
}

func splitNameAndOptionalUID(value []byte) (dn, uid []byte, hasUID bool) {
	separator := bytes.LastIndexByte(value, '#')
	if separator < 0 || !validBitString(value[separator+1:]) {
		return value, nil, false
	}
	return value[:separator], value[separator+1:], true
}

func validBitString(value []byte) bool {
	if len(value) < 3 || value[0] != '\'' ||
		value[len(value)-2] != '\'' || value[len(value)-1] != 'B' {
		return false
	}
	for _, character := range value[1 : len(value)-2] {
		if character != '0' && character != '1' {
			return false
		}
	}
	return true
}

func compareUniqueMember(left, right []byte) (int, error) {
	leftDNValue, leftUID, leftHasUID := splitNameAndOptionalUID(left)
	rightDNValue, rightUID, rightHasUID := splitNameAndOptionalUID(right)
	switch {
	case leftHasUID && rightHasUID:
		if len(leftUID) != len(rightUID) {
			return len(leftUID) - len(rightUID), nil
		}
		if comparison := bytes.Compare(leftUID, rightUID); comparison != 0 {
			return comparison, nil
		}
	case leftHasUID:
		return -1, nil
	case rightHasUID:
		return 1, nil
	}
	leftDN, leftErr := directory.ParseDN(string(leftDNValue))
	rightDN, rightErr := directory.ParseDN(string(rightDNValue))
	if leftErr != nil || rightErr != nil {
		return 0, errors.New("uniqueMemberMatch received invalid name and optional UID")
	}
	return strings.Compare(leftDN.Key(), rightDN.Key()), nil
}

func normalizeUniqueMember(value []byte) ([]byte, error) {
	dnValue, uid, hasUID := splitNameAndOptionalUID(value)
	dn, err := directory.ParseDN(string(dnValue))
	if err != nil {
		return nil, errors.New("uniqueMemberMatch received invalid name and optional UID")
	}
	normalized := []byte(dn.Key())
	if hasUID {
		normalized = append(normalized, '#')
		normalized = append(normalized, uid...)
	}
	return normalized, nil
}

func schemaDescriptionFirstComponent(value []byte) (string, error) {
	parser, err := newDescriptionParser(string(value))
	if err != nil {
		return "", err
	}
	component := parser.take()
	if component == "" {
		return "", errors.New("schema description has no first component")
	}
	return component, nil
}

func matchSubstringWithRule(
	rule string,
	value []byte,
	substring directory.Substring,
) (bool, error) {
	var normalize func([]byte) []byte
	switch strings.ToLower(rule) {
	case "caseignoresubstringsmatch", "caseignoreia5substringsmatch":
		normalize = normalizeCaseIgnore
	case "caseignorelistsubstringsmatch":
		return matchCaseIgnoreListSubstring(value, substring)
	case "caseexactsubstringsmatch", "caseexactia5substringsmatch":
		normalize = normalizeSpace
	case "telephonenumbersubstringsmatch":
		normalize = normalizeTelephoneNumber
	case "numericstringsubstringsmatch":
		normalize = normalizeNumericString
	default:
		return false, fmt.Errorf("unsupported substring matching rule %q", rule)
	}

	candidate := normalize(value)
	position := 0
	if substring.Initial != nil {
		initial := normalize(substring.Initial)
		if !bytes.HasPrefix(candidate, initial) {
			return false, nil
		}
		position = len(initial)
	}
	for _, rawPart := range substring.Any {
		part := normalize(rawPart)
		index := bytes.Index(candidate[position:], part)
		if index < 0 {
			return false, nil
		}
		position += index + len(part)
	}
	if substring.Final != nil {
		return bytes.HasSuffix(candidate[position:], normalize(substring.Final)), nil
	}
	return true, nil
}

func normalizeCaseIgnore(value []byte) []byte {
	return bytes.ToLower(normalizeSpace(value))
}

func normalizeSpace(value []byte) []byte {
	return []byte(strings.Join(strings.Fields(string(value)), " "))
}

func normalizeCaseIgnoreList(value []byte) []byte {
	lines, ok := parsePostalAddress(value)
	if !ok {
		return bytes.Clone(value)
	}
	var normalized []byte
	for _, line := range lines {
		line = normalizeCaseIgnore(line)
		normalized = strconv.AppendInt(normalized, int64(len(line)), 10)
		normalized = append(normalized, ':')
		normalized = append(normalized, line...)
	}
	return normalized
}

func normalizeTelephoneNumber(value []byte) []byte {
	normalized := make([]byte, 0, len(value))
	for _, character := range bytes.ToLower(value) {
		if character != ' ' && character != '-' {
			normalized = append(normalized, character)
		}
	}
	return normalized
}

func normalizeNumericString(value []byte) []byte {
	normalized := make([]byte, 0, len(value))
	for _, character := range value {
		if character != ' ' {
			normalized = append(normalized, character)
		}
	}
	return normalized
}

func validPostalAddress(value []byte) bool {
	_, ok := parsePostalAddress(value)
	return ok
}

func parsePostalAddress(value []byte) ([][]byte, bool) {
	if len(value) == 0 {
		return nil, false
	}
	var (
		lines   [][]byte
		current []byte
	)
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '$':
			if len(current) == 0 || !utf8.Valid(current) {
				return nil, false
			}
			lines = append(lines, bytes.Clone(current))
			current = nil
		case '\\':
			if index+2 >= len(value) {
				return nil, false
			}
			escape := strings.ToLower(string(value[index+1 : index+3]))
			switch escape {
			case "24":
				current = append(current, '$')
			case "5c":
				current = append(current, '\\')
			default:
				return nil, false
			}
			index += 2
		default:
			current = append(current, value[index])
		}
	}
	if len(current) == 0 || !utf8.Valid(current) {
		return nil, false
	}
	lines = append(lines, bytes.Clone(current))
	return lines, true
}

type byteRange struct {
	start int
	end   int
}

func matchCaseIgnoreListSubstring(
	value []byte,
	substring directory.Substring,
) (bool, error) {
	lines, ok := parsePostalAddress(value)
	if !ok {
		return false, errors.New("value is not a postal address")
	}
	var (
		candidate []byte
		ranges    []byteRange
	)
	for _, line := range lines {
		start := len(candidate)
		candidate = append(candidate, normalizeCaseIgnore(line)...)
		ranges = append(ranges, byteRange{start: start, end: len(candidate)})
	}

	position := 0
	if substring.Initial != nil {
		initial := normalizeCaseIgnore(substring.Initial)
		if !bytes.HasPrefix(candidate, initial) ||
			!rangeContains(ranges[0], 0, len(initial)) {
			return false, nil
		}
		position = len(initial)
	}
	for _, rawPart := range substring.Any {
		part := normalizeCaseIgnore(rawPart)
		start, found := findContainedSubstring(
			candidate,
			ranges,
			part,
			position,
		)
		if !found {
			return false, nil
		}
		position = start + len(part)
	}
	if substring.Final == nil {
		return true, nil
	}
	final := normalizeCaseIgnore(substring.Final)
	start := len(candidate) - len(final)
	if start < position || start < 0 ||
		!bytes.Equal(candidate[start:], final) ||
		!rangeContains(ranges[len(ranges)-1], start, len(candidate)) {
		return false, nil
	}
	return true, nil
}

func findContainedSubstring(
	candidate []byte,
	ranges []byteRange,
	part []byte,
	position int,
) (int, bool) {
	for position <= len(candidate) {
		index := bytes.Index(candidate[position:], part)
		if index < 0 {
			return 0, false
		}
		start := position + index
		end := start + len(part)
		for _, candidateRange := range ranges {
			if rangeContains(candidateRange, start, end) {
				return start, true
			}
		}
		position = start + 1
	}
	return 0, false
}

func rangeContains(candidate byteRange, start, end int) bool {
	return start >= candidate.start && end <= candidate.end
}

func validPrintableStringList(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, item := range bytes.Split(value, []byte{'$'}) {
		if !validPrintableString(item) {
			return false
		}
	}
	return true
}

func validPrintableString(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9':
		case strings.ContainsRune(" '()+,-./:=?", rune(character)):
		default:
			return false
		}
	}
	return true
}

func schemaKeys(oid string, names []string) []string {
	if oid == "" {
		return nil
	}
	keys := []string{schemaKey(oid)}
	for _, name := range names {
		keys = append(keys, schemaKey(name))
	}
	return keys
}

func structureRuleKeys(ruleID int, names []string) []string {
	return schemaKeys(strconv.Itoa(ruleID), names)
}

func validateSchemaDefinitionKeys(kind, name string, keys []string) error {
	if len(keys) == 0 || keys[0] == "" {
		return fmt.Errorf("%s %q requires an identifier", kind, name)
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			return fmt.Errorf("%s %q has an empty name", kind, name)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%s %q repeats identifier %q", kind, name, key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func schemaKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func baseAttributeDescription(value string) string {
	if index := strings.IndexByte(value, ';'); index >= 0 {
		return value[:index]
	}
	return value
}

func uniqueAttributeTypes(attributes map[string]*AttributeType) []AttributeType {
	seen := make(map[string]struct{})
	result := make([]AttributeType, 0)
	for _, attribute := range attributes {
		key := schemaKey(attribute.OID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, *attribute)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].OID < result[j].OID
	})
	return result
}

func uniqueObjectClasses(objectClasses map[string]*ObjectClass) []ObjectClass {
	seen := make(map[string]struct{})
	result := make([]ObjectClass, 0)
	for _, objectClass := range objectClasses {
		key := schemaKey(objectClass.OID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, *objectClass)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].OID < result[j].OID
	})
	return result
}

func uniqueDITContentRules(
	contentRules map[string]*DITContentRule,
) []DITContentRule {
	seen := make(map[string]struct{})
	result := make([]DITContentRule, 0)
	for _, contentRule := range contentRules {
		key := schemaKey(contentRule.OID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, cloneDITContentRule(*contentRule))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].OID < result[j].OID
	})
	return result
}

func uniqueNameForms(nameForms map[string]*NameForm) []NameForm {
	seen := make(map[string]struct{})
	result := make([]NameForm, 0)
	for _, nameForm := range nameForms {
		key := schemaKey(nameForm.OID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, cloneNameForm(*nameForm))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].OID < result[j].OID
	})
	return result
}

func uniqueDITStructureRules(
	structureRules map[string]*DITStructureRule,
) []DITStructureRule {
	seen := make(map[int]struct{})
	result := make([]DITStructureRule, 0)
	for _, structureRule := range structureRules {
		if _, exists := seen[structureRule.RuleID]; exists {
			continue
		}
		seen[structureRule.RuleID] = struct{}{}
		result = append(result, cloneDITStructureRule(*structureRule))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].RuleID < result[j].RuleID
	})
	return result
}
