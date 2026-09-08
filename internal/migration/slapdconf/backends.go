package slapdconf

import (
	"errors"
	"fmt"
	"strings"
)

var databaseObjectClasses = map[string]string{
	"config": "", "frontend": "olcFrontendConfig", "mdb": "olcMdbConfig",
	"monitor": "olcMonitorConfig", "ldap": "olcLDAPConfig", "ldif": "olcLdifConfig",
	"null": "olcNullConfig", "relay": "olcRelayConfig",
}

var backendDirectiveSpecs = map[string]map[string]directiveSpec{
	"mdb":  mdbDirectiveSpecs,
	"ldif": {"directory": single("olcDbDirectory")},
	"null": {
		"bind":      boolean("olcDbBindAllowed", false),
		"do-search": boolean("olcDbDoSearch", false),
	},
	"relay": {"relay": single("olcRelay")},
	"ldap": {
		"uri":                single("olcDbURI"),
		"tls":                joined("olcDbStartTLS", 1, -1),
		"acl-bind":           joined("olcDbACLBind", 1, -1),
		"idassert-bind":      joined("olcDbIDAssertBind", 1, -1),
		"idassert-authzfrom": ordered("olcDbIDAssertAuthzFrom", 1, 1),
		"rebind-as-user":     boolean("olcDbRebindAsUser", true),
		"chase-referrals":    boolean("olcDbChaseReferrals", false),
		"protocol-version":   single("olcDbProtocolVersion"),
		"network-timeout":    single("olcDbNetworkTimeout"),
		"timeout":            joined("olcDbTimeout", 1, -1),
		"idle-timeout":       single("olcDbIdleTimeout"),
		"conn-ttl":           single("olcDbConnTtl"),
		"quarantine":         joined("olcDbQuarantine", 1, 1),
		"single-conn":        boolean("olcDbSingleConn", false),
		"use-temporary-conn": boolean("olcDbUseTemporaryConn", false),
	},
}

func (converter *converter) startBackend(directive Directive) error {
	if len(directive.Arguments) != 1 {
		return sourceError(directive.Position, errors.New("backend requires exactly one backend name"))
	}
	name := strings.ToLower(directive.Arguments[0])
	if _, ok := databaseObjectClasses[name]; !ok || name == "frontend" {
		return sourceError(directive.Position, fmt.Errorf("unsupported backend %q", name))
	}
	dn := "olcBackend=" + name + ",cn=config"
	for _, existing := range converter.backends {
		if existing.dn == dn {
			return sourceError(directive.Position, fmt.Errorf("backend %q is declared more than once", name))
		}
	}
	entry := newMutableEntry(dn, "olcBackendConfig")
	entry.add("olcBackend", name, false)
	entry.position = directive.Position
	converter.backends = append(converter.backends, entry)
	converter.currentBackend = entry
	converter.currentDatabase = nil
	converter.currentOverlay = nil
	converter.currentOverlayName = ""
	return nil
}

// ACL's runtime lexer preserves backslashes for DN and regex processing.
// Escaping them a second time changes matching semantics. Embedded literal
// quotes cannot be represented by that lexer without changing the assertion.
func joinACLArguments(arguments []string) (string, error) {
	values := make([]string, len(arguments))
	for i, argument := range arguments {
		if strings.ContainsRune(argument, '"') || strings.HasSuffix(argument, "\\") {
			return "", errors.New("ACL argument contains quoting that ldap-go cannot preserve")
		}
		if strings.ContainsAny(argument, " \t'") {
			values[i] = `"` + argument + `"`
		} else {
			values[i] = argument
		}
	}
	return strings.Join(values, " "), nil
}
