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
	mu            sync.RWMutex
	attributes    map[string]*AttributeType
	objectClasses map[string]*ObjectClass
}

func NewRegistry() *Registry {
	return &Registry{
		attributes:    make(map[string]*AttributeType),
		objectClasses: make(map[string]*ObjectClass),
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
	return cloned
}

func (registry *Registry) RegisterAttributeType(attribute AttributeType) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	keys := schemaKeys(attribute.OID, attribute.Names)
	if len(keys) == 0 {
		return errors.New("attribute type requires an OID")
	}
	for _, key := range keys {
		if _, exists := registry.attributes[key]; exists {
			return fmt.Errorf("attribute type %q is already registered", key)
		}
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
	copy := objectClass
	for _, key := range keys {
		registry.objectClasses[key] = &copy
	}
	return nil
}

func (registry *Registry) UpsertAttributeType(attribute AttributeType) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()

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

func (registry *Registry) AttributeType(name string) (AttributeType, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	attribute, ok := registry.attributes[schemaKey(baseAttributeDescription(name))]
	if !ok {
		return AttributeType{}, false
	}
	return *attribute, true
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

func (registry *Registry) AttributeTypeDescriptions() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	attributes := uniqueAttributeTypes(registry.attributes)
	result := make([]string, len(attributes))
	for i := range attributes {
		result[i] = FormatAttributeType(attributes[i])
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

func (registry *Registry) StructuralObjectClass(entry directory.Entry) (string, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	classes := make(map[string]*ObjectClass)
	for _, value := range entry.Values("objectClass") {
		objectClass, ok := registry.objectClasses[schemaKey(string(value))]
		if !ok {
			return "", &Violation{
				Kind:      ViolationUnknownObjectClass,
				Attribute: "objectClass",
				Message:   fmt.Sprintf("unknown object class %q", value),
			}
		}
		if err := registry.collectObjectClass(objectClass, classes, make(map[string]bool)); err != nil {
			return "", err
		}
	}
	if err := registry.validateStructuralClasses(classes); err != nil {
		return "", err
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
			return candidate.Name(), nil
		}
	}
	return "", &Violation{
		Kind:    ViolationStructuralObjectClass,
		Message: "entry has no structural object class",
	}
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

	classValues := entry.Values("objectClass")
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
	required := make(map[string]struct{})
	allowed := map[string]struct{}{"objectclass": {}}
	extensible := false
	for _, objectClass := range classes {
		if strings.EqualFold(objectClass.Name(), "extensibleObject") {
			extensible = true
		}
		for _, name := range objectClass.Must {
			required[schemaKey(name)] = struct{}{}
			allowed[schemaKey(name)] = struct{}{}
		}
		for _, name := range objectClass.May {
			allowed[schemaKey(name)] = struct{}{}
		}
	}

	present := make(map[string]struct{}, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		baseName := baseAttributeDescription(attribute.Description)
		key := schemaKey(baseName)
		attributeType, ok := registry.attributes[key]
		if !ok {
			return &Violation{
				Kind:      ViolationUndefinedAttribute,
				Attribute: attribute.Description,
				Message:   "undefined attribute type",
			}
		}
		present[key] = struct{}{}
		if !extensible && attributeType.Usage == UsageUserApplications {
			if _, ok := allowed[key]; !ok {
				return &Violation{
					Kind:      ViolationDisallowedAttribute,
					Attribute: attribute.Description,
					Message:   "attribute is not allowed by the entry object classes",
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
	for name := range required {
		if _, ok := present[name]; !ok {
			return &Violation{
				Kind:      ViolationMissingRequiredAttribute,
				Attribute: name,
				Message:   "required attribute is missing",
			}
		}
	}
	return nil
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

func validateSyntax(syntax string, maxLength int, value []byte) error {
	if maxLength > 0 && len(value) > maxLength {
		return fmt.Errorf("value exceeds syntax length %d", maxLength)
	}
	switch syntax {
	case "", SyntaxOctetString:
		return nil
	case SyntaxDirectoryString:
		if len(value) == 0 || !utf8.Valid(value) {
			return errors.New("value is not a valid non-empty Directory String")
		}
	case SyntaxIA5String:
		for _, character := range value {
			if character > 0x7f {
				return errors.New("value is not IA5")
			}
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
	case SyntaxGeneralizedTime:
		if _, err := time.Parse("20060102150405Z", string(value)); err != nil {
			if _, fractionalErr := time.Parse("20060102150405.000000Z", string(value)); fractionalErr != nil {
				return errors.New("value is not generalized time")
			}
		}
	}
	return nil
}

func compareWithRule(rule string, left, right []byte) (int, error) {
	switch strings.ToLower(rule) {
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
	case "octetstringmatch", "octetstringorderingmatch":
		return bytes.Compare(left, right), nil
	case "objectidentifiermatch":
		return strings.Compare(strings.ToLower(string(left)), strings.ToLower(string(right))), nil
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
	case "booleanmatch":
		return strings.Compare(strings.ToUpper(string(left)), strings.ToUpper(string(right))), nil
	case "distinguishednamematch":
		leftDN, leftErr := directory.ParseDN(string(left))
		rightDN, rightErr := directory.ParseDN(string(right))
		if leftErr != nil || rightErr != nil {
			return 0, errors.New("distinguishedNameMatch received invalid DN")
		}
		return strings.Compare(leftDN.Key(), rightDN.Key()), nil
	case "uuidmatch", "uuidorderingmatch", "generalizedtimematch", "generalizedtimeorderingmatch",
		"csnmatch", "csnorderingmatch":
		return strings.Compare(strings.ToLower(string(left)), strings.ToLower(string(right))), nil
	default:
		return 0, fmt.Errorf("unsupported matching rule %q", rule)
	}
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
	case "caseexactsubstringsmatch", "caseexactia5substringsmatch":
		normalize = normalizeSpace
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
