package server

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type orderedSiblingChange struct {
	before directory.Entry
	after  directory.Entry
}

type orderedSibling struct {
	dn      directory.DN
	entry   directory.Entry
	order   int
	content string
}

func orderedSiblingModifyDNRequest(
	oldDN directory.DN,
	newRDN directory.DN,
	hasNewSuperior bool,
	registry *schema.Registry,
) (bool, int, *ldapwire.Result) {
	oldAttribute, oldValue, ordered := orderedSiblingRDN(oldDN, registry)
	if !ordered {
		return false, 0, nil
	}
	failure := func(code ldapwire.ResultCode, diagnostic string) (bool, int, *ldapwire.Result) {
		result := ldapwire.ResultError(code, diagnostic)
		return true, 0, &result
	}
	if hasNewSuperior {
		return failure(ldapwire.ResultUnwillingToPerform, "ordered siblings cannot change parent")
	}
	newAttribute, newValue, newOrdered := orderedSiblingRDN(newRDN, registry)
	if !newOrdered || !constraintAttributeDescriptionsEqual(
		registry, oldAttribute, newAttribute,
	) {
		return failure(ldapwire.ResultUnwillingToPerform, "ordered sibling type cannot change")
	}
	oldOrder, oldContent, oldIndexed, err := parseOrderedSiblingValue(oldValue)
	if err != nil || !oldIndexed {
		return failure(ldapwire.ResultNamingViolation, "existing ordered sibling has no valid index")
	}
	newOrder, newContent, newIndexed, err := parseOrderedSiblingValue(newValue)
	if err != nil || !newIndexed || newOrder < 0 {
		return failure(ldapwire.ResultUnwillingToPerform, "new ordered sibling index is invalid")
	}
	comparison, err := registry.Compare(
		oldAttribute, "", []byte(oldContent), []byte(newContent),
	)
	if err != nil || comparison != 0 {
		return failure(ldapwire.ResultUnwillingToPerform, "ordered sibling value cannot change")
	}
	if oldOrder < 0 || (oldOrder == 0 && strings.EqualFold(oldContent, "config")) {
		return failure(ldapwire.ResultConstraintViolation, "fixed ordered sibling cannot move")
	}
	return true, newOrder, nil
}

func reorderOrderedConfigSibling(
	tx storage.Writer,
	oldDN directory.DN,
	targetOrder int,
	registry *schema.Registry,
) ([]orderedSiblingChange, directory.Entry, error) {
	attribute, _, ordered := orderedSiblingRDN(oldDN, registry)
	if !ordered {
		return nil, directory.Entry{}, errors.New("entry is not an ordered sibling")
	}
	parent, ok := oldDN.Parent()
	if !ok {
		return nil, directory.Entry{}, errors.New("ordered sibling requires a parent")
	}
	parentDisplay := orderedSiblingParentDisplay(tx, parent)
	siblings, err := collectOrderedSiblings(tx, parent, attribute, registry)
	if err != nil {
		return nil, directory.Entry{}, err
	}
	source := -1
	for index := range siblings {
		if siblings[index].dn.Equal(oldDN) {
			source = index
			break
		}
	}
	if source < 0 {
		return nil, directory.Entry{}, storage.ErrEntryNotFound
	}
	moving := siblings[source]
	siblings = append(siblings[:source], siblings[source+1:]...)
	if targetOrder > len(siblings) {
		targetOrder = len(siblings)
	}
	siblings = append(siblings, orderedSibling{})
	copy(siblings[targetOrder+1:], siblings[targetOrder:])
	siblings[targetOrder] = moving

	mappings := make([]orderedSiblingMapping, 0, len(siblings))
	for order, sibling := range siblings {
		value := formatOrderedSiblingValue(order, sibling.content)
		newDN, err := composeOrderedSiblingDN(attribute, value, parent, registry)
		if err != nil {
			return nil, directory.Entry{}, err
		}
		if sibling.dn.Equal(newDN) {
			continue
		}
		mappings = append(mappings, orderedSiblingMapping{
			oldDN: sibling.dn, newDN: newDN,
			oldDisplay: sibling.entry.DN,
			newDisplay: orderedSiblingDisplayDN(attribute, value, parentDisplay),
			attribute:  attribute, value: value,
		})
	}
	if len(mappings) == 0 {
		return nil, moving.entry, nil
	}
	changes, err := applyOrderedSiblingMappings(tx, mappings, registry)
	if err != nil {
		return nil, directory.Entry{}, err
	}
	for _, change := range changes {
		beforeDN, parseErr := directory.ParseDN(change.before.DN)
		if parseErr == nil && beforeDN.Equal(oldDN) {
			return changes, change.after, nil
		}
	}
	return nil, directory.Entry{}, errors.New("ordered sibling move omitted source entry")
}

func parseOrderedSiblingValue(value string) (int, string, bool, error) {
	if value == "" || value[0] != '{' {
		return 0, value, false, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, "", false, errors.New("invalid ordered sibling prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil {
		return 0, "", false, errors.New("invalid ordered sibling prefix")
	}
	if value[end+1:] == "" {
		return 0, "", false, errors.New("ordered sibling value is empty")
	}
	return order, value[end+1:], true, nil
}

func formatOrderedSiblingValue(order int, content string) string {
	return "{" + strconv.Itoa(order) + "}" + content
}

func orderedSiblingRDN(
	dn directory.DN,
	registry *schema.Registry,
) (string, string, bool) {
	values := dn.RDNValues()
	if len(values) != 1 || !registry.HasOrderedSiblings(values[0].Type) {
		return "", "", false
	}
	attribute := values[0].Type
	if resolved, found := registry.AttributeType(attribute); found {
		attribute = resolved.Name()
	}
	return attribute, string(values[0].Value), true
}

func prepareOrderedConfigAdd(
	tx storage.Writer,
	entry directory.Entry,
	dn directory.DN,
	registry *schema.Registry,
) (directory.Entry, directory.DN, []orderedSiblingChange, error) {
	attribute, requestedValue, ordered := orderedSiblingRDN(dn, registry)
	if !ordered {
		return entry, dn, nil, nil
	}
	requestedOrder, content, indexed, err := parseOrderedSiblingValue(requestedValue)
	if err != nil {
		return directory.Entry{}, directory.DN{}, nil, err
	}
	if indexed && requestedOrder < 0 {
		return entry, dn, nil, nil
	}
	entryValues := registry.AttributeValues(entry, attribute)
	if len(entryValues) != 1 {
		return directory.Entry{}, directory.DN{}, nil,
			fmt.Errorf("ordered sibling attribute %q must contain one value", attribute)
	}
	_, entryContent, entryIndexed, err := parseOrderedSiblingValue(string(entryValues[0]))
	if err != nil {
		return directory.Entry{}, directory.DN{}, nil, err
	}
	comparison, err := registry.Compare(
		attribute, "", []byte(entryContent), []byte(content),
	)
	if err != nil || comparison != 0 {
		return directory.Entry{}, directory.DN{}, nil,
			fmt.Errorf("ordered sibling RDN value %q does not match attribute %q", content, entryContent)
	}
	if _, getErr := tx.Get(dn); getErr == nil {
		_, existingValue, existingOrdered := orderedSiblingRDN(dn, registry)
		if existingOrdered {
			_, existingContent, _, parseErr := parseOrderedSiblingValue(existingValue)
			if parseErr != nil {
				return directory.Entry{}, directory.DN{}, nil, parseErr
			}
			equal, compareErr := registry.Compare(
				attribute, "", []byte(existingContent), []byte(content),
			)
			if compareErr != nil {
				return directory.Entry{}, directory.DN{}, nil, compareErr
			}
			if equal == 0 {
				return directory.Entry{}, directory.DN{}, nil, storage.ErrEntryExists
			}
		}
	} else if !errors.Is(getErr, storage.ErrEntryNotFound) {
		return directory.Entry{}, directory.DN{}, nil, getErr
	}
	parent, ok := dn.Parent()
	if !ok {
		return directory.Entry{}, directory.DN{}, nil,
			errors.New("ordered sibling requires a parent")
	}
	parentDisplay := orderedSiblingParentDisplay(tx, parent)
	siblings, err := collectOrderedSiblings(tx, parent, attribute, registry)
	if err != nil {
		return directory.Entry{}, directory.DN{}, nil, err
	}
	position := len(siblings)
	if indexed && requestedOrder <= len(siblings) {
		position = requestedOrder
	}
	type orderedItem struct {
		sibling *orderedSibling
		content string
		new     bool
	}
	items := make([]orderedItem, 0, len(siblings)+1)
	for index := 0; index <= len(siblings); index++ {
		if index == position {
			items = append(items, orderedItem{content: content, new: true})
		}
		if index < len(siblings) {
			items = append(items, orderedItem{
				sibling: &siblings[index], content: siblings[index].content,
			})
		}
	}

	var mappings []orderedSiblingMapping
	var newDN directory.DN
	for order, item := range items {
		value := formatOrderedSiblingValue(order, item.content)
		target, err := composeOrderedSiblingDN(attribute, value, parent, registry)
		if err != nil {
			return directory.Entry{}, directory.DN{}, nil, err
		}
		if item.new {
			newDN = target
			continue
		}
		if !item.sibling.dn.Equal(target) {
			mappings = append(mappings, orderedSiblingMapping{
				oldDN: item.sibling.dn, newDN: target,
				oldDisplay: item.sibling.entry.DN,
				newDisplay: orderedSiblingDisplayDN(attribute, value, parentDisplay),
				attribute:  attribute, value: value,
			})
		}
	}
	changes, err := applyOrderedSiblingMappings(tx, mappings, registry)
	if err != nil {
		return directory.Entry{}, directory.DN{}, nil, err
	}
	entry.DN = orderedSiblingDisplayDN(
		attribute,
		formatOrderedSiblingValue(position, content),
		parentDisplay,
	)
	if !indexed || entryIndexed {
		replaceSchemaExactAttribute(
			&entry,
			attribute,
			[][]byte{[]byte(formatOrderedSiblingValue(position, content))},
			registry,
		)
	}
	return entry, newDN, changes, nil
}

func renumberOrderedConfigSiblingsAfterDelete(
	tx storage.Writer,
	dn directory.DN,
	registry *schema.Registry,
) ([]orderedSiblingChange, error) {
	attribute, value, ordered := orderedSiblingRDN(dn, registry)
	if !ordered {
		return nil, nil
	}
	order, _, indexed, err := parseOrderedSiblingValue(value)
	if err != nil || !indexed || order < 0 {
		return nil, err
	}
	parent, ok := dn.Parent()
	if !ok {
		return nil, errors.New("ordered sibling requires a parent")
	}
	parentDisplay := orderedSiblingParentDisplay(tx, parent)
	siblings, err := collectOrderedSiblings(tx, parent, attribute, registry)
	if err != nil {
		return nil, err
	}
	mappings := make([]orderedSiblingMapping, 0, len(siblings))
	for targetOrder, sibling := range siblings {
		value := formatOrderedSiblingValue(targetOrder, sibling.content)
		target, err := composeOrderedSiblingDN(attribute, value, parent, registry)
		if err != nil {
			return nil, err
		}
		if !sibling.dn.Equal(target) {
			mappings = append(mappings, orderedSiblingMapping{
				oldDN: sibling.dn, newDN: target,
				oldDisplay: sibling.entry.DN,
				newDisplay: orderedSiblingDisplayDN(attribute, value, parentDisplay),
				attribute:  attribute, value: value,
			})
		}
	}
	return applyOrderedSiblingMappings(tx, mappings, registry)
}

func collectOrderedSiblings(
	reader storage.Reader,
	parent directory.DN,
	attribute string,
	registry *schema.Registry,
) ([]orderedSibling, error) {
	var siblings []orderedSibling
	err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil || dn.Depth() != parent.Depth()+1 {
			return err
		}
		candidateParent, ok := dn.Parent()
		if !ok || !candidateParent.Equal(parent) {
			return nil
		}
		candidateAttribute, value, ordered := orderedSiblingRDN(dn, registry)
		if !ordered || !constraintAttributeDescriptionsEqual(
			registry, candidateAttribute, attribute,
		) {
			return nil
		}
		order, content, indexed, err := parseOrderedSiblingValue(value)
		if err != nil {
			return err
		}
		if !indexed || order < 0 {
			return nil
		}
		siblings = append(siblings, orderedSibling{
			dn: dn, entry: entry, order: order, content: content,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(siblings, func(left, right int) bool {
		if siblings[left].order != siblings[right].order {
			return siblings[left].order < siblings[right].order
		}
		return siblings[left].dn.String() < siblings[right].dn.String()
	})
	return siblings, nil
}

type orderedSiblingMapping struct {
	oldDN      directory.DN
	newDN      directory.DN
	oldDisplay string
	newDisplay string
	attribute  string
	value      string
}

func orderedSiblingDisplayDN(
	attribute, value string,
	parent string,
) string {
	local := attribute + "=" + ldap.EscapeDN(value)
	if parent == "" {
		return local
	}
	return local + "," + parent
}

func orderedSiblingParentDisplay(reader storage.Reader, parent directory.DN) string {
	if parent.Depth() == 0 {
		return ""
	}
	entry, err := reader.Get(parent)
	if err == nil && entry.DN != "" {
		return entry.DN
	}
	return parent.String()
}

func composeOrderedSiblingDN(
	attribute, value string,
	parent directory.DN,
	registry *schema.Registry,
) (directory.DN, error) {
	rdn, err := directory.ParseDNWithNormalizer(attribute+"="+value, registry)
	if err != nil {
		return directory.DN{}, err
	}
	return directory.ComposeLocalName(rdn, parent)
}

func applyOrderedSiblingMappings(
	tx storage.Writer,
	mappings []orderedSiblingMapping,
	registry *schema.Registry,
) ([]orderedSiblingChange, error) {
	if len(mappings) == 0 {
		return nil, nil
	}
	type move struct {
		oldDN   directory.DN
		newDN   directory.DN
		entry   directory.Entry
		mapping *orderedSiblingMapping
		root    bool
	}
	var moves []move
	oldKeys := make(map[string]struct{})
	for index := range mappings {
		mapping := &mappings[index]
		if err := tx.ForEach(func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !candidate.Equal(mapping.oldDN) && !mapping.oldDN.AncestorOf(candidate) {
				return nil
			}
			target, err := candidate.ReplaceAncestor(mapping.oldDN, mapping.newDN)
			if err != nil {
				return err
			}
			item := move{
				oldDN: candidate, newDN: target, entry: entry, mapping: mapping,
			}
			if candidate.Equal(mapping.oldDN) {
				item.root = true
			}
			moves = append(moves, item)
			oldKeys[candidate.Key()] = struct{}{}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	for _, item := range moves {
		if _, err := tx.Get(item.newDN); err == nil {
			if _, moving := oldKeys[item.newDN.Key()]; !moving {
				return nil, storage.ErrEntryExists
			}
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return nil, err
		}
	}
	changes := make([]orderedSiblingChange, 0, len(mappings))
	for index := range moves {
		item := &moves[index]
		before := item.entry.Clone()
		item.entry.DN = orderedSiblingMovedDisplayDN(item.entry.DN, item.mapping)
		if item.root {
			replaceSchemaExactAttribute(
				&item.entry,
				item.mapping.attribute,
				[][]byte{[]byte(item.mapping.value)},
				registry,
			)
			if item.entry.HasAttribute("entryDN") {
				item.entry.ReplaceValues("entryDN", [][]byte{[]byte(item.newDN.String())})
			}
			changes = append(changes, orderedSiblingChange{
				before: before, after: item.entry.Clone(),
			})
		}
	}
	sort.Slice(moves, func(left, right int) bool {
		return moves[left].oldDN.Depth() > moves[right].oldDN.Depth()
	})
	for _, item := range moves {
		if err := tx.Delete(item.oldDN); err != nil {
			return nil, err
		}
	}
	sort.Slice(moves, func(left, right int) bool {
		return moves[left].newDN.Depth() < moves[right].newDN.Depth()
	})
	for _, item := range moves {
		if err := tx.Put(item.entry, false); err != nil {
			return nil, fmt.Errorf("store renumbered sibling %q: %w", item.newDN.String(), err)
		}
	}
	return changes, nil
}

func orderedSiblingMovedDisplayDN(
	current string,
	mapping *orderedSiblingMapping,
) string {
	if mapping == nil {
		return current
	}
	if strings.EqualFold(current, mapping.oldDisplay) {
		return mapping.newDisplay
	}
	suffix := "," + mapping.oldDisplay
	if len(current) >= len(suffix) && strings.EqualFold(
		current[len(current)-len(suffix):],
		suffix,
	) {
		return current[:len(current)-len(suffix)] + "," + mapping.newDisplay
	}
	return current
}

func replaceSchemaExactAttribute(
	entry *directory.Entry,
	description string,
	values [][]byte,
	registry *schema.Registry,
) {
	indexes := schemaExactAttributeIndexes(*entry, description, registry)
	entry.Attributes = removeSchemaAttributes(entry.Attributes, indexes)
	if len(values) != 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: description,
			Values:      cloneByteValues(values),
		})
	}
}
