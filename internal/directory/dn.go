package directory

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type DN struct {
	parsed    *ldap.DN
	canonical string
}

type AttributeValue struct {
	Type  string
	Value []byte
}

func ParseDN(value string) (DN, error) {
	parsed, err := ldap.ParseDN(value)
	if err != nil {
		return DN{}, fmt.Errorf("parse DN %q: %w", value, err)
	}
	return DN{
		parsed:    parsed,
		canonical: strings.ToLower(parsed.String()),
	}, nil
}

func (dn DN) String() string {
	return dn.parsed.String()
}

func (dn DN) Key() string {
	return dn.canonical
}

func (dn DN) Depth() int {
	return len(dn.parsed.RDNs)
}

func (dn DN) Equal(other DN) bool {
	return dn.parsed.EqualFold(other.parsed)
}

func (dn DN) AncestorOf(other DN) bool {
	return dn.parsed.AncestorOfFold(other.parsed)
}

func (dn DN) Parent() (DN, bool) {
	if len(dn.parsed.RDNs) == 0 {
		return DN{}, false
	}
	parent := &ldap.DN{RDNs: dn.parsed.RDNs[1:]}
	return DN{
		parsed:    parent,
		canonical: strings.ToLower(parent.String()),
	}, true
}

func ComposeDN(rdn string, superior DN) (DN, error) {
	parsedRDN, err := ParseDN(rdn)
	if err != nil {
		return DN{}, err
	}
	if parsedRDN.Depth() != 1 {
		return DN{}, errors.New("new RDN must contain exactly one relative distinguished name")
	}
	if superior.Depth() == 0 {
		return parsedRDN, nil
	}
	return ParseDN(parsedRDN.String() + "," + superior.String())
}

func ComposeLocalName(localName, superior DN) (DN, error) {
	if localName.Depth() == 0 {
		return superior, nil
	}
	if superior.Depth() == 0 {
		return localName, nil
	}
	return ParseDN(localName.String() + "," + superior.String())
}

func (dn DN) ReplaceAncestor(oldBase, newBase DN) (DN, error) {
	if !oldBase.Equal(dn) && !oldBase.AncestorOf(dn) {
		return DN{}, errors.New("DN is outside the old naming subtree")
	}
	prefixLength := dn.Depth() - oldBase.Depth()
	rdns := make([]*ldap.RelativeDN, 0, prefixLength+newBase.Depth())
	rdns = append(rdns, dn.parsed.RDNs[:prefixLength]...)
	rdns = append(rdns, newBase.parsed.RDNs...)
	replaced := &ldap.DN{RDNs: rdns}
	return DN{
		parsed:    replaced,
		canonical: strings.ToLower(replaced.String()),
	}, nil
}

func (dn DN) RDNValues() []AttributeValue {
	if dn.Depth() == 0 {
		return nil
	}
	values := make([]AttributeValue, 0, len(dn.parsed.RDNs[0].Attributes))
	for _, attribute := range dn.parsed.RDNs[0].Attributes {
		values = append(values, AttributeValue{
			Type:  attribute.Type,
			Value: []byte(attribute.Value),
		})
	}
	return values
}

type Scope int

const (
	ScopeBase Scope = iota
	ScopeSingleLevel
	ScopeWholeSubtree
	ScopeChildren
)

func InScope(base, candidate DN, scope Scope) bool {
	switch scope {
	case ScopeBase:
		return base.Equal(candidate)
	case ScopeSingleLevel:
		return base.AncestorOf(candidate) && candidate.Depth() == base.Depth()+1
	case ScopeWholeSubtree:
		return base.Equal(candidate) || base.AncestorOf(candidate)
	case ScopeChildren:
		return base.AncestorOf(candidate)
	default:
		return false
	}
}
