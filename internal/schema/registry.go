package schema

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/directory"
)

type Registry struct {
	mu             sync.RWMutex
	attributes     map[string]*AttributeType
	objectClasses  map[string]*ObjectClass
	contentRules   map[string]*DITContentRule
	nameForms      map[string]*NameForm
	structureRules map[string]*DITStructureRule
}

func NewRegistry() *Registry {
	return &Registry{
		attributes:     make(map[string]*AttributeType),
		objectClasses:  make(map[string]*ObjectClass),
		contentRules:   make(map[string]*DITContentRule),
		nameForms:      make(map[string]*NameForm),
		structureRules: make(map[string]*DITStructureRule),
	}
}

func (registry *Registry) Clone() *Registry {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	cloned := NewRegistry()
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

func (registry *Registry) ObjectClassDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	objectClasses := uniqueObjectClasses(registry.objectClasses)
	result := make([]string, len(objectClasses))
	for i := range objectClasses {
		result[i] = FormatObjectClass(objectClasses[i])
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
	return compareWithRule(rule, left, right)
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

func (registry *Registry) ValidateEntry(entry directory.Entry) error {
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
			required[key] = requiredAttribute{name: name}
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
		for _, value := range attribute.Values {
			if err := validateSyntax(effective.Syntax, effective.SyntaxLength, value); err != nil {
				return &Violation{
					Kind:      ViolationSyntax,
					Attribute: attribute.Description,
					Message:   err.Error(),
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
				Kind:      ViolationMissingRequiredAttribute,
				Attribute: requiredAttribute.name,
				Message:   "required attribute is missing",
			}
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
			sameAttributeOptions(candidateOptions, requestedOptions)
	}
	if !registry.attributeTypeSubtype(
		candidateType,
		requestedType,
		make(map[string]bool),
	) {
		return false
	}
	for option := range requestedOptions {
		if _, present := candidateOptions[option]; !present {
			return false
		}
	}
	return true
}

func sameAttributeOptions(
	left,
	right map[string]struct{},
) bool {
	if len(left) != len(right) {
		return false
	}
	for option := range left {
		if _, present := right[option]; !present {
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

func validateSyntax(syntax string, maxLength int, value []byte) error {
	if maxLength > 0 && len(value) > maxLength {
		return fmt.Errorf("value exceeds syntax length %d", maxLength)
	}
	switch syntax {
	case "", SyntaxOctetString, SyntaxAuthenticationPassword:
		return nil
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
	case SyntaxTelephoneNumber:
		if !validPrintableString(value) {
			return errors.New("value is not a telephone number")
		}
	case SyntaxTelexNumber, SyntaxFacsimileTelephone:
		if !validPrintableStringList(value) {
			return errors.New("value is not a printable string list")
		}
	case SyntaxInteger:
		if _, err := strconv.ParseInt(string(value), 10, 64); err != nil {
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
	case SyntaxOID:
		if !validObjectIdentifier(string(value)) {
			return errors.New("value is not an object identifier")
		}
	case SyntaxGeneralizedTime:
		if !validGeneralizedTime(value) {
			return errors.New("value is not generalized time")
		}
	case SyntaxCSN:
		if _, ok := normalizeCSN(value); !ok {
			return errors.New("value is not a CSN")
		}
	}
	return nil
}

func validGeneralizedTime(value []byte) bool {
	raw := string(value)
	for _, layout := range []string{
		"20060102150405Z",
		"20060102150405.000000Z",
		"200601021504Z",
	} {
		if _, err := time.Parse(layout, raw); err == nil {
			return true
		}
	}
	return false
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

func compareWithRule(rule string, left, right []byte) (int, error) {
	switch canonicalMatchingRule(rule) {
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
	case "octetstringmatch", "octetstringorderingmatch", "authzmatch":
		return bytes.Compare(left, right), nil
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
		leftInteger, leftErr := strconv.ParseInt(string(left), 10, 64)
		rightInteger, rightErr := strconv.ParseInt(string(right), 10, 64)
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("integer matching rule received invalid integer")
		}
		switch {
		case leftInteger < rightInteger:
			return -1, nil
		case leftInteger > rightInteger:
			return 1, nil
		default:
			return 0, nil
		}
	case "integerfirstcomponentmatch":
		firstComponent, err := schemaDescriptionFirstComponent(left)
		if err != nil {
			return 0, fmt.Errorf(
				"integerFirstComponentMatch received an invalid description: %w",
				err,
			)
		}
		leftInteger, leftErr := strconv.ParseInt(firstComponent, 10, 64)
		rightInteger, rightErr := strconv.ParseInt(
			strings.TrimSpace(string(right)),
			10,
			64,
		)
		if leftErr != nil || rightErr != nil {
			return 0, errors.New(
				"integerFirstComponentMatch received an invalid integer",
			)
		}
		switch {
		case leftInteger < rightInteger:
			return -1, nil
		case leftInteger > rightInteger:
			return 1, nil
		default:
			return 0, nil
		}
	case "booleanmatch":
		return strings.Compare(strings.ToUpper(string(left)), strings.ToUpper(string(right))), nil
	case "distinguishednamematch":
		leftDN, leftErr := directory.ParseDN(string(left))
		rightDN, rightErr := directory.ParseDN(string(right))
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("distinguishedNameMatch received invalid DN")
		}
		return strings.Compare(leftDN.Key(), rightDN.Key()), nil
	case "uuidmatch", "uuidorderingmatch", "generalizedtimematch", "generalizedtimeorderingmatch":
		return strings.Compare(strings.ToLower(string(left)), strings.ToLower(string(right))), nil
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

func supportedMatchingRule(rule string) bool {
	switch canonicalMatchingRule(rule) {
	case "caseignorematch",
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
	case "2.5.13.0":
		return "objectidentifiermatch"
	case "2.5.13.29":
		return "integerfirstcomponentmatch"
	case "2.5.13.30":
		return "objectidentifierfirstcomponentmatch"
	case "2.5.13.1":
		return "distinguishednamematch"
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
