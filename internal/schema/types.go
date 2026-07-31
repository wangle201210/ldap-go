package schema

import "fmt"

type AttributeUsage string

const (
	UsageUserApplications     AttributeUsage = "userApplications"
	UsageDirectoryOperation   AttributeUsage = "directoryOperation"
	UsageDistributedOperation AttributeUsage = "distributedOperation"
	UsageDSAOperation         AttributeUsage = "dSAOperation"
)

type AttributeType struct {
	OID                string
	Names              []string
	Description        string
	Obsolete           bool
	Superior           string
	Equality           string
	Ordering           string
	Substring          string
	Syntax             string
	SyntaxLength       int
	SingleValue        bool
	Collective         bool
	NoUserModification bool
	Usage              AttributeUsage
	Extensions         map[string][]string
}

func (attribute AttributeType) Name() string {
	if len(attribute.Names) > 0 {
		return attribute.Names[0]
	}
	return attribute.OID
}

type ObjectClassKind string

const (
	ObjectClassAbstract   ObjectClassKind = "ABSTRACT"
	ObjectClassStructural ObjectClassKind = "STRUCTURAL"
	ObjectClassAuxiliary  ObjectClassKind = "AUXILIARY"
)

type ObjectClass struct {
	OID         string
	Names       []string
	Description string
	Obsolete    bool
	Superiors   []string
	Kind        ObjectClassKind
	Must        []string
	May         []string
	Extensions  map[string][]string
}

func (objectClass ObjectClass) Name() string {
	if len(objectClass.Names) > 0 {
		return objectClass.Names[0]
	}
	return objectClass.OID
}

type ViolationKind uint8

const (
	ViolationUndefinedAttribute ViolationKind = iota
	ViolationUnknownObjectClass
	ViolationMissingRequiredAttribute
	ViolationDisallowedAttribute
	ViolationSingleValue
	ViolationSyntax
	ViolationStructuralObjectClass
	ViolationNaming
)

type Violation struct {
	Kind      ViolationKind
	Attribute string
	Message   string
}

func (violation *Violation) Error() string {
	if violation.Attribute == "" {
		return violation.Message
	}
	return fmt.Sprintf("%s: %s", violation.Attribute, violation.Message)
}
