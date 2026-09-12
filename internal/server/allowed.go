package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var allowedAttributeNames = [...]string{
	"allowedChildClasses", "allowedChildClassesEffective",
	"allowedAttributes", "allowedAttributesEffective",
}

func allowedSchemaConfigured(reader storage.Reader) (bool, error) {
	enabled := false
	err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if !configurationSuffix.Equal(dn) && !configurationSuffix.AncestorOf(dn) {
			return nil
		}
		for _, value := range entry.Values("olcModuleLoad") {
			module, _, err := parseOpenLDAPModuleLoad(string(value))
			if err != nil {
				return err
			}
			if module == "allowed" || strings.HasPrefix(module, "allowed.") {
				enabled = true
			}
		}
		for _, value := range entry.Values("olcOverlay") {
			_, name, _, err := parseOrderedSiblingValue(string(value))
			if err != nil {
				return err
			}
			if strings.EqualFold(name, "allowed") {
				enabled = true
			}
		}
		return nil
	})
	return enabled, err
}

type allowedClassPlan struct {
	name       string
	required   []string
	attributes []string
}

type allowedSchemaPlan struct {
	global      bool
	classes     map[string]*allowedClassPlan
	auxiliaries []*allowedClassPlan
}

// Only immutable schema relationships are retained. ACL results always belong
// to the searching identity and the current entry/reader, never this cache.
func buildAllowedSchemaPlan(registry *schema.Registry, databases []runtimeDatabase) (*allowedSchemaPlan, error) {
	var enabled, global bool
	for _, database := range databases {
		if database.allowedOverlay {
			enabled = true
			global = global || databaseType(database.name) == "frontend"
		}
	}
	if !enabled {
		return nil, nil
	}
	for _, database := range databases {
		if (global || database.allowedOverlay) && (database.relay != nil ||
			databaseSearchCandidatesAreDelegated(nil, database)) {
			return nil, fmt.Errorf("allowed operational projection for delegated database %s is not implemented", database.name)
		}
	}
	classes := registry.ObjectClasses()
	if len(classes) > 8192 {
		return nil, fmt.Errorf("allowed schema exceeds 8192 object classes")
	}
	definitions := make(map[string]*schema.ObjectClass)
	for index := range classes {
		class := &classes[index]
		definitions[strings.ToLower(class.OID)] = class
		for _, name := range class.Names {
			definitions[strings.ToLower(name)] = class
		}
	}
	plan := &allowedSchemaPlan{global: global, classes: make(map[string]*allowedClassPlan)}
	visiting := make(map[string]bool)
	unavailable := make(map[string]bool)
	references := 0
	var compile func(*schema.ObjectClass, int) (*allowedClassPlan, error)
	compile = func(class *schema.ObjectClass, depth int) (*allowedClassPlan, error) {
		if unavailable[class.OID] {
			return nil, nil
		}
		if existing := plan.classes[strings.ToLower(class.OID)]; existing != nil {
			return existing, nil
		}
		if depth > 128 || visiting[class.OID] {
			return nil, fmt.Errorf("allowed schema has cyclic or excessive inheritance at %s", class.Name())
		}
		visiting[class.OID] = true
		defer delete(visiting, class.OID)
		required, all := make(map[string]bool), make(map[string]bool)
		for _, parentName := range class.Superiors {
			parent := definitions[strings.ToLower(parentName)]
			if parent == nil {
				// Some optional built-in config classes lack their unloaded base
				// definitions. Omit the whole class, never infer an empty MUST set.
				unavailable[class.OID] = true
				return nil, nil
			}
			compiled, err := compile(parent, depth+1)
			if err != nil {
				return nil, err
			}
			if compiled == nil {
				unavailable[class.OID] = true
				return nil, nil
			}
			for _, name := range compiled.required {
				required[name] = true
			}
			for _, name := range compiled.attributes {
				all[name] = true
			}
		}
		for index, names := range [][]string{class.Must, class.May} {
			for _, name := range names {
				attribute, known := registry.AttributeType(name)
				if !known {
					unavailable[class.OID] = true
					return nil, nil
				}
				canonical := attribute.Name()
				all[canonical] = true
				if index == 0 {
					required[canonical] = true
				}
			}
		}
		references += len(all) + len(required)
		if references > 1<<20 {
			return nil, fmt.Errorf("allowed schema exceeds attribute relationship limit")
		}
		compiled := &allowedClassPlan{name: class.Name()}
		for name := range required {
			compiled.required = append(compiled.required, name)
		}
		for name := range all {
			compiled.attributes = append(compiled.attributes, name)
		}
		sort.Strings(compiled.required)
		sort.Strings(compiled.attributes)
		plan.classes[strings.ToLower(class.OID)] = compiled
		for _, name := range class.Names {
			plan.classes[strings.ToLower(name)] = compiled
		}
		return compiled, nil
	}
	for index := range classes {
		compiled, err := compile(&classes[index], 0)
		if err != nil {
			return nil, err
		}
		if compiled != nil && classes[index].Kind == schema.ObjectClassAuxiliary {
			plan.auxiliaries = append(plan.auxiliaries, compiled)
		}
	}
	return plan, nil
}

// applyAllowedAttributes runs after filtering, before final selection. Read ACLs
// on generated values use the original entry, as native operational attributes
// live outside sr_entry and cannot change filters or ACL target predicates.
func (server *Server) applyAllowedAttributes(runtime *runtimeState, reader storage.Reader, subject string,
	original, readable directory.Entry, requested []string, typesOnly bool,
) directory.Entry {
	plan := runtime.allowed
	if plan == nil {
		return readable
	}
	var wanted [4]bool
	for _, selector := range requested {
		if selector == "+" {
			wanted = [4]bool{true, true, true, true}
			break
		}
		for index, name := range allowedAttributeNames {
			if runtime.schema.AttributeDescriptionSubtype(name, selector) {
				wanted[index] = true
			}
		}
	}
	if wanted == [4]bool{} {
		return readable
	}
	if !plan.global {
		dn, err := parseRuntimeConnectionDN(runtime, original.DN)
		if err != nil {
			return readable
		}
		database := databaseForDN(runtime, dn)
		if database == nil || !database.allowedOverlay {
			return readable
		}
	}
	objectClasses := runtime.schema.AttributeValues(original, "objectClass")
	if runtime.schema.HasAttributeDescription(original, "objectClass") &&
		!server.allowed(runtime, reader, subject, original, "objectClass", nil, acl.Read) {
		return readable
	}
	var generated [4][][]byte
	if wanted[2] || wanted[3] {
		seen := make(map[string]bool)
		for _, value := range objectClasses {
			class := plan.classes[strings.ToLower(strings.TrimSpace(string(value)))]
			if class == nil || !server.allowed(runtime, reader, subject, original, "objectClass", []byte(class.name), acl.Read) {
				continue
			}
			for _, name := range class.attributes {
				if seen[name] {
					continue
				}
				seen[name] = true
				if wanted[2] {
					generated[2] = append(generated[2], []byte(name))
				}
				if wanted[3] && server.allowed(runtime, reader, subject, original, name, nil, acl.Write) {
					generated[3] = append(generated[3], []byte(name))
				}
			}
		}
	}
	if wanted[0] || wanted[1] {
		for _, class := range plan.auxiliaries {
			if wanted[0] {
				generated[0] = append(generated[0], []byte(class.name))
			}
			if !wanted[1] || !server.allowed(runtime, reader, subject, original, "objectClass", []byte(class.name), acl.Write) {
				continue
			}
			writable := true
			for _, name := range class.required {
				if !server.allowed(runtime, reader, subject, original, name, nil, acl.Write) {
					writable = false
					break
				}
			}
			if writable {
				generated[1] = append(generated[1], []byte(class.name))
			}
		}
	}
	copied := false
	for index, values := range generated {
		if len(values) == 0 {
			continue
		}
		attribute := directory.Attribute{Description: allowedAttributeNames[index]}
		if typesOnly {
			if !server.allowed(runtime, reader, subject, original, attribute.Description, nil, acl.Read) {
				continue
			}
		} else {
			for _, value := range values {
				if server.allowed(runtime, reader, subject, original, attribute.Description, value, acl.Read) {
					attribute.Values = append(attribute.Values, value)
				}
			}
			if len(attribute.Values) == 0 {
				continue
			}
		}
		if !copied {
			readable.Attributes = append([]directory.Attribute(nil), readable.Attributes...)
			copied = true
		}
		readable.Attributes = append(readable.Attributes, attribute)
	}
	return readable
}
