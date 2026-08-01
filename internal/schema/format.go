package schema

import (
	"fmt"
	"sort"
	"strings"
)

func FormatAttributeType(attribute AttributeType) string {
	fields := []string{"(", attribute.OID}
	if len(attribute.Names) > 0 {
		fields = append(fields, "NAME", formatQuotedList(attribute.Names))
	}
	if attribute.Description != "" {
		fields = append(fields, "DESC", quoteSchemaValue(attribute.Description))
	}
	if attribute.Obsolete {
		fields = append(fields, "OBSOLETE")
	}
	if attribute.Superior != "" {
		fields = append(fields, "SUP", attribute.Superior)
	}
	if attribute.Equality != "" {
		fields = append(fields, "EQUALITY", attribute.Equality)
	}
	if attribute.Ordering != "" {
		fields = append(fields, "ORDERING", attribute.Ordering)
	}
	if attribute.Substring != "" {
		fields = append(fields, "SUBSTR", attribute.Substring)
	}
	if attribute.Syntax != "" {
		syntax := attribute.Syntax
		if attribute.SyntaxLength > 0 {
			syntax += fmt.Sprintf("{%d}", attribute.SyntaxLength)
		}
		fields = append(fields, "SYNTAX", syntax)
	}
	if attribute.SingleValue {
		fields = append(fields, "SINGLE-VALUE")
	}
	if attribute.Collective {
		fields = append(fields, "COLLECTIVE")
	}
	if attribute.NoUserModification {
		fields = append(fields, "NO-USER-MODIFICATION")
	}
	if attribute.Usage != "" && attribute.Usage != UsageUserApplications {
		fields = append(fields, "USAGE", string(attribute.Usage))
	}
	fields = appendExtensions(fields, attribute.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func FormatObjectClass(objectClass ObjectClass) string {
	fields := []string{"(", objectClass.OID}
	if len(objectClass.Names) > 0 {
		fields = append(fields, "NAME", formatQuotedList(objectClass.Names))
	}
	if objectClass.Description != "" {
		fields = append(fields, "DESC", quoteSchemaValue(objectClass.Description))
	}
	if objectClass.Obsolete {
		fields = append(fields, "OBSOLETE")
	}
	if len(objectClass.Superiors) > 0 {
		fields = append(fields, "SUP", formatOIDList(objectClass.Superiors))
	}
	if objectClass.Kind != "" {
		fields = append(fields, string(objectClass.Kind))
	}
	if len(objectClass.Must) > 0 {
		fields = append(fields, "MUST", formatOIDList(objectClass.Must))
	}
	if len(objectClass.May) > 0 {
		fields = append(fields, "MAY", formatOIDList(objectClass.May))
	}
	fields = appendExtensions(fields, objectClass.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func FormatDITContentRule(contentRule DITContentRule) string {
	fields := []string{"(", contentRule.OID}
	if len(contentRule.Names) > 0 {
		fields = append(fields, "NAME", formatQuotedList(contentRule.Names))
	}
	if contentRule.Description != "" {
		fields = append(
			fields,
			"DESC",
			quoteSchemaValue(contentRule.Description),
		)
	}
	if contentRule.Obsolete {
		fields = append(fields, "OBSOLETE")
	}
	if len(contentRule.Auxiliary) > 0 {
		fields = append(fields, "AUX", formatOIDList(contentRule.Auxiliary))
	}
	if len(contentRule.Must) > 0 {
		fields = append(fields, "MUST", formatOIDList(contentRule.Must))
	}
	if len(contentRule.May) > 0 {
		fields = append(fields, "MAY", formatOIDList(contentRule.May))
	}
	if len(contentRule.Not) > 0 {
		fields = append(fields, "NOT", formatOIDList(contentRule.Not))
	}
	fields = appendExtensions(fields, contentRule.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func FormatNameForm(nameForm NameForm) string {
	fields := []string{"(", nameForm.OID}
	if len(nameForm.Names) > 0 {
		fields = append(fields, "NAME", formatQuotedList(nameForm.Names))
	}
	if nameForm.Description != "" {
		fields = append(fields, "DESC", quoteSchemaValue(nameForm.Description))
	}
	if nameForm.Obsolete {
		fields = append(fields, "OBSOLETE")
	}
	fields = append(fields, "OC", nameForm.ObjectClass)
	fields = append(fields, "MUST", formatOIDList(nameForm.Must))
	if len(nameForm.May) > 0 {
		fields = append(fields, "MAY", formatOIDList(nameForm.May))
	}
	fields = appendExtensions(fields, nameForm.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func FormatDITStructureRule(structureRule DITStructureRule) string {
	fields := []string{"(", fmt.Sprintf("%d", structureRule.RuleID)}
	if len(structureRule.Names) > 0 {
		fields = append(fields, "NAME", formatQuotedList(structureRule.Names))
	}
	if structureRule.Description != "" {
		fields = append(
			fields,
			"DESC",
			quoteSchemaValue(structureRule.Description),
		)
	}
	if structureRule.Obsolete {
		fields = append(fields, "OBSOLETE")
	}
	fields = append(fields, "FORM", structureRule.Form)
	if len(structureRule.Superiors) > 0 {
		fields = append(
			fields,
			"SUP",
			formatRuleIDList(structureRule.Superiors),
		)
	}
	fields = appendExtensions(fields, structureRule.Extensions)
	return strings.Join(append(fields, ")"), " ")
}

func formatQuotedList(values []string) string {
	quoted := make([]string, len(values))
	for i := range values {
		quoted[i] = quoteSchemaValue(values[i])
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return "( " + strings.Join(quoted, " ") + " )"
}

func formatOIDList(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "( " + strings.Join(values, " $ ") + " )"
}

func formatRuleIDList(values []int) string {
	formatted := make([]string, len(values))
	for i, value := range values {
		formatted[i] = fmt.Sprintf("%d", value)
	}
	if len(formatted) == 1 {
		return formatted[0]
	}
	return "( " + strings.Join(formatted, " ") + " )"
}

func appendExtensions(fields []string, extensions map[string][]string) []string {
	names := make([]string, 0, len(extensions))
	for name := range extensions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fields = append(fields, strings.ToUpper(name), formatQuotedList(extensions[name]))
	}
	return fields
}

func quoteSchemaValue(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('\'')
	for _, character := range []byte(value) {
		switch {
		case character == '\'' || character == '\\' || character < 0x20 || character == 0x7f:
			quoted.WriteString(fmt.Sprintf("\\%02X", character))
		default:
			quoted.WriteByte(character)
		}
	}
	quoted.WriteByte('\'')
	return quoted.String()
}
