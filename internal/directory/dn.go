package directory

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type DN struct {
	parsed    *ldap.DN
	canonical string
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

type Scope int

const (
	ScopeBase Scope = iota
	ScopeSingleLevel
	ScopeWholeSubtree
)

func InScope(base, candidate DN, scope Scope) bool {
	switch scope {
	case ScopeBase:
		return base.Equal(candidate)
	case ScopeSingleLevel:
		return base.AncestorOf(candidate) && candidate.Depth() == base.Depth()+1
	case ScopeWholeSubtree:
		return base.Equal(candidate) || base.AncestorOf(candidate)
	default:
		return false
	}
}
