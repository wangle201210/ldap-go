package acl

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func ParseRule(value string) (Rule, error) {
	order, description, err := orderedValue(value)
	if err != nil {
		return Rule{}, err
	}
	tokens, err := tokenize(description)
	if err != nil {
		return Rule{}, err
	}
	if len(tokens) == 0 || !strings.EqualFold(tokens[0], "to") {
		return Rule{}, errors.New("ACL must start with \"to\"")
	}

	firstBy := tokenIndex(tokens, "by", 1)
	if firstBy < 0 {
		return Rule{}, errors.New("ACL requires at least one by clause")
	}
	target, err := parseTarget(tokens[1:firstBy])
	if err != nil {
		return Rule{}, err
	}

	rule := Rule{Order: order, Target: target, Raw: value}
	for position := firstBy; position < len(tokens); {
		next := tokenIndex(tokens, "by", position+1)
		if next < 0 {
			next = len(tokens)
		}
		clause, err := parseByClause(tokens[position+1 : next])
		if err != nil {
			return Rule{}, fmt.Errorf("parse by clause: %w", err)
		}
		rule.By = append(rule.By, clause)
		position = next
	}
	return rule, nil
}

func SortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Order < rules[j].Order
	})
}

func parseTarget(tokens []string) (TargetSelector, error) {
	target := TargetSelector{DN: DNMatcher{Style: DNAny}}
	dnSpecified := false
	for _, token := range tokens {
		if token == "*" {
			if dnSpecified {
				return TargetSelector{}, errors.New("ACL target DN is already specified")
			}
			dnSpecified = true
			continue
		}
		key, value, ok := splitSelector(token)
		if !ok {
			return TargetSelector{}, fmt.Errorf("unsupported target selector %q", token)
		}
		switch {
		case key == "attrs" || key == "attr":
			for _, attribute := range strings.Split(value, ",") {
				attribute = strings.TrimSpace(attribute)
				if attribute == "" {
					return TargetSelector{}, errors.New("empty ACL target attribute")
				}
				if strings.ContainsRune("@!+-", rune(attribute[0])) && len(attribute) == 1 {
					if attribute == "+" {
						target.Attributes = append(target.Attributes, attribute)
						continue
					}
					return TargetSelector{}, fmt.Errorf("empty ACL target selector %q", attribute)
				}
				target.Attributes = append(target.Attributes, attribute)
			}
		case key == "dn" || strings.HasPrefix(key, "dn."):
			if dnSpecified {
				return TargetSelector{}, errors.New("ACL target DN is already specified")
			}
			matcher, err := parseDNMatcher(key, value, false)
			if err != nil {
				return TargetSelector{}, fmt.Errorf("target %s: %w", key, err)
			}
			target.DN = matcher
			dnSpecified = true
		case key == "filter":
			filter, err := ldapwire.CompileFilter(value)
			if err != nil {
				return TargetSelector{}, fmt.Errorf("compile ACL target filter: %w", err)
			}
			target.Filter = &filter
		case strings.HasPrefix(key, "val"):
			if target.Value != nil {
				return TargetSelector{}, errors.New("ACL target value is already specified")
			}
			if len(target.Attributes) != 1 || !plainValueAttribute(target.Attributes[0]) {
				return TargetSelector{}, errors.New("ACL target value requires one attribute")
			}
			selector, err := parseValueSelector(key, value)
			if err != nil {
				return TargetSelector{}, err
			}
			target.Value = &selector
		default:
			return TargetSelector{}, fmt.Errorf("unsupported target selector %q", token)
		}
	}
	return target, nil
}

func plainValueAttribute(attribute string) bool {
	return attribute != "" && !strings.ContainsRune("@!+-*", rune(attribute[0]))
}

func parseValueSelector(key, value string) (ValueSelector, error) {
	style := "exact"
	if dot := strings.IndexByte(key, '.'); dot >= 0 {
		style = key[dot+1:]
		key = key[:dot]
	}
	parts := strings.SplitN(key, "/", 2)
	if parts[0] != "val" || len(parts) > 2 {
		return ValueSelector{}, fmt.Errorf("invalid ACL target value selector %q", key)
	}
	selector := ValueSelector{
		Style:     DNExact,
		Assertion: []byte(value),
	}
	if len(parts) == 2 {
		if parts[1] == "" {
			return ValueSelector{}, errors.New("empty ACL target value matching rule")
		}
		selector.MatchingRule = parts[1]
	}
	switch style {
	case "exact", "base", "baseobject":
		return selector, nil
	case "regex":
		pattern, err := regexp.Compile("(?i)" + value)
		if err != nil {
			return ValueSelector{}, fmt.Errorf("compile ACL target value regular expression: %w", err)
		}
		selector.Style = DNRegex
		selector.Pattern = pattern
		return selector, nil
	case "one", "onelevel":
		selector.Style = DNOne
	case "sub", "subtree":
		selector.Style = DNSubtree
	case "children":
		selector.Style = DNChildren
	default:
		return ValueSelector{}, fmt.Errorf("unsupported ACL target value style %q", style)
	}
	return selector, nil
}

func parseByClause(tokens []string) (ByClause, error) {
	if len(tokens) == 0 {
		return ByClause{}, errors.New("empty by clause")
	}
	clause := ByClause{
		Control: ControlStop,
		Grant:   Grant{Mode: grantIdentity},
	}

	if control, ok := parseControl(tokens[len(tokens)-1]); ok {
		clause.Control = control
		tokens = tokens[:len(tokens)-1]
	}
	if len(tokens) == 0 {
		return ByClause{}, errors.New("by clause requires a subject")
	}

	accessIndex := -1
	for i := 1; i < len(tokens); i++ {
		if isAccessToken(tokens[i]) {
			accessIndex = i
			break
		}
	}
	whoTokens := tokens
	if accessIndex >= 0 {
		var err error
		clause.Grant, err = parseGrant(tokens[accessIndex])
		if err != nil {
			return ByClause{}, err
		}
		whoTokens = tokens[:accessIndex]
		if accessIndex != len(tokens)-1 {
			return ByClause{}, fmt.Errorf("unexpected token %q after access grant", tokens[accessIndex+1])
		}
	}

	for _, token := range whoTokens {
		matcher, err := parseWhoMatcher(token)
		if err != nil {
			return ByClause{}, err
		}
		clause.Who = append(clause.Who, matcher)
	}
	return clause, nil
}

func parseWhoMatcher(token string) (WhoMatcher, error) {
	lower := strings.ToLower(token)
	switch lower {
	case "*":
		return WhoMatcher{Kind: WhoAny}, nil
	case "anonymous":
		return WhoMatcher{Kind: WhoAnonymous}, nil
	case "users":
		return WhoMatcher{Kind: WhoUsers}, nil
	case "self":
		return WhoMatcher{Kind: WhoSelf}, nil
	case "realanonymous":
		return WhoMatcher{Kind: WhoAnonymous, Real: true}, nil
	case "realusers":
		return WhoMatcher{Kind: WhoUsers, Real: true}, nil
	case "realself":
		return WhoMatcher{Kind: WhoSelf, Real: true}, nil
	case "aci", "dynacl/aci":
		return WhoMatcher{Kind: WhoACI, ACIAttribute: "OpenLDAPaci"}, nil
	}
	if isACISelector(lower) {
		return parseACIMatcher(lower, "")
	}
	selfPrefix := "self."
	real := false
	if strings.HasPrefix(lower, "realself.") {
		selfPrefix = "realself."
		real = true
	}
	if strings.HasPrefix(lower, selfPrefix+"level{") {
		level, ok, err := parseLevelStyle(strings.TrimPrefix(lower, selfPrefix))
		if err != nil {
			return WhoMatcher{}, fmt.Errorf("subject %s: %w", strings.TrimSuffix(selfPrefix, "."), err)
		}
		if ok {
			return WhoMatcher{Kind: WhoSelf, Real: real, SelfLevel: level}, nil
		}
	}

	key, value, ok := splitSelector(token)
	if !ok {
		return WhoMatcher{}, fmt.Errorf("unsupported subject selector %q", token)
	}
	switch {
	case isACISelector(key):
		return parseACIMatcher(key, value)
	case strings.HasPrefix(key, "dn.") || key == "dn":
		matcher, err := parseDNMatcher(key, value, true)
		if err != nil {
			return WhoMatcher{}, fmt.Errorf("subject %s: %w", key, err)
		}
		return WhoMatcher{Kind: WhoDN, DN: matcher}, nil
	case strings.HasPrefix(key, "realdn.") || key == "realdn":
		matcherKey := strings.TrimPrefix(key, "real")
		matcher, err := parseDNMatcher(matcherKey, value, true)
		if err != nil {
			return WhoMatcher{}, fmt.Errorf("subject %s: %w", key, err)
		}
		return WhoMatcher{Kind: WhoDN, Real: true, DN: matcher}, nil
	case key == "dnattr":
		if value == "" {
			return WhoMatcher{}, errors.New("dnattr requires an attribute")
		}
		return WhoMatcher{Kind: WhoDNAttribute, Attribute: value}, nil
	case key == "realdnattr":
		if value == "" {
			return WhoMatcher{}, errors.New("realdnattr requires an attribute")
		}
		return WhoMatcher{Kind: WhoDNAttribute, Real: true, Attribute: value}, nil
	case strings.HasPrefix(key, "group"):
		return parseGroupMatcher(key, value)
	case key == "peername" || strings.HasPrefix(key, "peername."):
		matcher, err := parseStringMatcher(key, "peername", value, stringStyles{
			regex: true, ip: true, ipv6: true, path: true,
		})
		return WhoMatcher{Kind: WhoPeerName, Connection: matcher}, err
	case key == "sockname" || strings.HasPrefix(key, "sockname."):
		matcher, err := parseStringMatcher(key, "sockname", value, stringStyles{regex: true})
		return WhoMatcher{Kind: WhoSockName, Connection: matcher}, err
	case key == "domain" || strings.HasPrefix(key, "domain."):
		matcher, err := parseStringMatcher(key, "domain", value, stringStyles{
			regex: true, subtree: true, modifier: true,
		})
		return WhoMatcher{Kind: WhoDomain, Connection: matcher}, err
	case key == "sockurl" || strings.HasPrefix(key, "sockurl."):
		matcher, err := parseStringMatcher(key, "sockurl", value, stringStyles{regex: true})
		return WhoMatcher{Kind: WhoSockURL, Connection: matcher}, err
	case key == "set" || strings.HasPrefix(key, "set."):
		style := "exact"
		if key != "set" {
			style = strings.TrimPrefix(key, "set.")
		}
		expand := false
		switch style {
		case "exact", "base", "baseobject":
		case "expand", "regex":
			expand = true
		default:
			return WhoMatcher{}, fmt.Errorf("unsupported set style %q", style)
		}
		if value == "" {
			return WhoMatcher{}, errors.New("set requires an expression")
		}
		return WhoMatcher{Kind: WhoSet, SetPattern: value, SetExpand: expand}, nil
	case key == "ssf" || key == "transport_ssf" || key == "tls_ssf" || key == "sasl_ssf":
		minimum, err := strconv.Atoi(value)
		if err != nil || minimum < 0 {
			return WhoMatcher{}, fmt.Errorf("invalid SSF %q", value)
		}
		kind := SSFOverall
		switch key {
		case "transport_ssf":
			kind = SSFTransport
		case "tls_ssf":
			kind = SSFTLS
		case "sasl_ssf":
			kind = SSFSASL
		}
		return WhoMatcher{Kind: WhoSSF, SSFKind: kind, MinimumSSF: minimum}, nil
	default:
		return WhoMatcher{}, fmt.Errorf("unsupported subject selector %q", token)
	}
}

func isACISelector(key string) bool {
	base := key
	if dot := strings.LastIndexByte(base, '.'); dot > strings.LastIndexByte(base, '/') {
		base = base[:dot]
	}
	return base == "aci" || base == "dynacl/aci" ||
		strings.HasPrefix(base, "dynacl/aci/")
}

func parseACIMatcher(key, attribute string) (WhoMatcher, error) {
	style := "exact"
	if dot := strings.LastIndexByte(key, '.'); dot > strings.LastIndexByte(key, '/') {
		style = key[dot+1:]
	}
	switch style {
	case "exact", "base", "baseobject", "regex":
	default:
		return WhoMatcher{}, fmt.Errorf("unsupported ACI style %q", style)
	}
	if attribute == "" {
		attribute = "OpenLDAPaci"
	}
	return WhoMatcher{Kind: WhoACI, ACIAttribute: attribute}, nil
}

func parseGroupMatcher(key, value string) (WhoMatcher, error) {
	style := "exact"
	if dot := strings.LastIndexByte(key, '.'); dot >= 0 {
		style = key[dot+1:]
		key = key[:dot]
	}
	expand := false
	switch style {
	case "exact", "base", "baseobject":
	case "expand", "regex":
		expand = true
	default:
		return WhoMatcher{}, fmt.Errorf("unsupported group style %q", style)
	}
	parts := strings.Split(key, "/")
	if parts[0] != "group" || len(parts) > 3 {
		return WhoMatcher{}, fmt.Errorf("invalid group selector %q", key)
	}
	objectClass := "groupOfNames"
	attribute := "member"
	if len(parts) >= 2 && parts[1] != "" {
		objectClass = parts[1]
	}
	if len(parts) == 3 && parts[2] != "" {
		attribute = parts[2]
	}
	matcher := WhoMatcher{
		Kind:             WhoGroup,
		GroupObjectClass: objectClass,
		GroupAttribute:   attribute,
		GroupPattern:     value,
		GroupExpand:      expand,
	}
	if expand {
		return matcher, nil
	}
	groupDN, err := directory.ParseDN(value)
	matcher.DN = DNMatcher{Style: DNExact, DN: groupDN}
	return matcher, err
}

func parseDNMatcher(key, value string, allowExpansion bool) (DNMatcher, error) {
	style := "exact"
	expand := false
	if dot := strings.IndexByte(key, '.'); dot >= 0 {
		style = key[dot+1:]
		if comma := strings.IndexByte(style, ','); comma >= 0 {
			if style[comma+1:] != "expand" {
				return DNMatcher{}, fmt.Errorf("unsupported DN modifier %q", style[comma+1:])
			}
			if !allowExpansion {
				return DNMatcher{}, errors.New("DN expansion is not valid in an ACL target")
			}
			expand = true
			style = style[:comma]
		}
	}
	if expand && style == "regex" {
		return DNMatcher{}, errors.New("DN regex style already implies expansion")
	}
	if expand && !hasACLExpansion(value) {
		return DNMatcher{}, errors.New("DN expansion pattern contains no substitutions")
	}
	if expand {
		matcher := DNMatcher{Raw: value, Expand: true}
		if level, ok, err := parseLevelStyle(style); ok || err != nil {
			if err != nil {
				return DNMatcher{}, err
			}
			if level < 0 {
				return DNMatcher{}, fmt.Errorf("negative DN level %d", level)
			}
			matcher.Style = DNLevel
			matcher.Level = level
			return matcher, nil
		}
		switch style {
		case "exact", "base", "baseobject":
			matcher.Style = DNExact
		case "one", "onelevel":
			matcher.Style = DNOne
		case "subtree", "sub":
			matcher.Style = DNSubtree
		case "children":
			matcher.Style = DNChildren
		default:
			return DNMatcher{}, fmt.Errorf("unsupported DN style %q", style)
		}
		return matcher, nil
	}
	switch style {
	case "regex":
		if value == "" {
			dn, err := directory.ParseDN("")
			return DNMatcher{Style: DNExact, DN: dn}, err
		}
		switch value {
		case "*", ".*", ".*$", "^.*", "^.*$", ".*$$", "^.*$$":
			return DNMatcher{Style: DNAny}, nil
		}
		if allowExpansion {
			return DNMatcher{
				Style:  DNRegex,
				Raw:    value,
				Expand: hasACLExpansion(value),
			}, nil
		}
		pattern, err := regexp.Compile("(?i)" + value)
		if err != nil {
			return DNMatcher{}, fmt.Errorf("compile DN regular expression: %w", err)
		}
		return DNMatcher{Style: DNRegex, Pattern: pattern}, nil
	case "exact", "base", "baseobject":
		dn, err := directory.ParseDN(value)
		return DNMatcher{Style: DNExact, DN: dn}, err
	case "one", "onelevel":
		dn, err := directory.ParseDN(value)
		return DNMatcher{Style: DNOne, DN: dn}, err
	case "subtree", "sub":
		dn, err := directory.ParseDN(value)
		return DNMatcher{Style: DNSubtree, DN: dn}, err
	case "children":
		dn, err := directory.ParseDN(value)
		return DNMatcher{Style: DNChildren, DN: dn}, err
	default:
		if level, ok, err := parseLevelStyle(style); ok || err != nil {
			if err != nil {
				return DNMatcher{}, err
			}
			if level < 0 {
				return DNMatcher{}, fmt.Errorf("negative DN level %d", level)
			}
			if !allowExpansion {
				return DNMatcher{}, fmt.Errorf("unsupported DN style %q", style)
			}
			dn, err := directory.ParseDN(value)
			return DNMatcher{Style: DNLevel, DN: dn, Level: level}, err
		}
		return DNMatcher{}, fmt.Errorf("unsupported DN style %q", style)
	}
}

func parseLevelStyle(style string) (int, bool, error) {
	if !strings.HasPrefix(style, "level") {
		return 0, false, nil
	}
	if len(style) < len("level{}") || style[len("level")] != '{' || style[len(style)-1] != '}' {
		return 0, true, fmt.Errorf("invalid DN level style %q", style)
	}
	raw := style[len("level{") : len(style)-1]
	if raw == "" {
		return 0, true, errors.New("empty DN level")
	}
	level, err := strconv.Atoi(raw)
	if err != nil {
		return 0, true, fmt.Errorf("invalid DN level %q", raw)
	}
	return level, true, nil
}

func parseGrant(token string) (Grant, error) {
	grant := Grant{Mode: grantSet}
	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, "realself") {
		grant.RealSelfValue = true
		lower = strings.TrimPrefix(lower, "realself")
		if lower == "" {
			return Grant{}, errors.New("realself access modifier requires a level or privileges")
		}
	} else if strings.HasPrefix(lower, "self") {
		grant.SelfValue = true
		lower = strings.TrimPrefix(lower, "self")
		if lower == "" {
			return Grant{}, errors.New("self access modifier requires a level or privileges")
		}
	}

	switch lower {
	case "none":
		grant.Privileges = NoneLevel
		return grant, nil
	case "disclose":
		grant.Privileges = DiscloseLevel
		return grant, nil
	case "auth":
		grant.Privileges = AuthLevel
		return grant, nil
	case "compare":
		grant.Privileges = CompareLevel
		return grant, nil
	case "search":
		grant.Privileges = SearchLevel
		return grant, nil
	case "read":
		grant.Privileges = ReadLevel
		return grant, nil
	case "write":
		grant.Privileges = WriteLevel
		return grant, nil
	case "manage":
		grant.Privileges = ManageLevel
		return grant, nil
	}

	if len(lower) < 2 {
		return Grant{}, fmt.Errorf("invalid access grant %q", token)
	}
	switch lower[0] {
	case '=':
		grant.Mode = grantSet
	case '+':
		grant.Mode = grantAdd
	case '-':
		grant.Mode = grantRemove
	default:
		return Grant{}, fmt.Errorf("invalid access grant %q", token)
	}
	privileges, err := parsePrivilegeLetters(lower[1:])
	if err != nil {
		return Grant{}, err
	}
	grant.Privileges = privileges
	return grant, nil
}

func parsePrivilegeLetters(value string) (Privilege, error) {
	var privileges Privilege
	for _, letter := range value {
		switch letter {
		case '0':
			if len(value) != 1 {
				return 0, errors.New("zero privilege cannot be combined")
			}
		case 'd':
			privileges |= Disclose
		case 'x':
			privileges |= Auth
		case 'c':
			privileges |= Compare
		case 's':
			privileges |= Search
		case 'r':
			privileges |= Read
		case 'w':
			privileges |= WriteAdd | WriteDelete
		case 'a':
			privileges |= WriteAdd
		case 'z':
			privileges |= WriteDelete
		case 'm':
			privileges |= Manage
		default:
			return 0, fmt.Errorf("unknown access privilege %q", string(letter))
		}
	}
	return privileges, nil
}

func isAccessToken(token string) bool {
	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, "realself") {
		lower = strings.TrimPrefix(lower, "realself")
	} else if strings.HasPrefix(lower, "self") {
		lower = strings.TrimPrefix(lower, "self")
	}
	switch lower {
	case "none", "disclose", "auth", "compare", "search", "read", "write", "manage":
		return true
	}
	return len(lower) >= 2 && strings.ContainsRune("=+-", rune(lower[0]))
}

func parseControl(token string) (Control, bool) {
	switch strings.ToLower(token) {
	case "stop":
		return ControlStop, true
	case "continue":
		return ControlContinue, true
	case "break":
		return ControlBreak, true
	default:
		return 0, false
	}
}

func splitSelector(token string) (string, string, bool) {
	index := strings.IndexByte(token, '=')
	if index < 1 {
		return "", "", false
	}
	return strings.ToLower(token[:index]), token[index+1:], true
}

func orderedValue(value string) (int, string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return int(^uint(0) >> 1), value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, "", errors.New("invalid ordered ACL prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return 0, "", fmt.Errorf("invalid ordered ACL prefix %q", value[:end+1])
	}
	return order, strings.TrimSpace(value[end+1:]), nil
}

func tokenIndex(tokens []string, token string, start int) int {
	for i := start; i < len(tokens); i++ {
		if strings.EqualFold(tokens[i], token) {
			return i
		}
	}
	return -1
}

func tokenize(value string) ([]string, error) {
	var tokens []string
	for position := 0; position < len(value); {
		for position < len(value) && unicode.IsSpace(rune(value[position])) {
			position++
		}
		if position == len(value) {
			break
		}

		var token strings.Builder
		var quote byte
		for position < len(value) {
			character := value[position]
			if quote == 0 && unicode.IsSpace(rune(character)) {
				break
			}
			if character == '\'' || character == '"' {
				if quote == 0 {
					quote = character
					position++
					continue
				}
				if quote == character {
					quote = 0
					position++
					continue
				}
			}
			if character == '\\' && position+1 < len(value) {
				token.WriteByte(character)
				position++
				token.WriteByte(value[position])
				position++
				continue
			}
			token.WriteByte(character)
			position++
		}
		if quote != 0 {
			return nil, errors.New("unterminated quoted ACL value")
		}
		if token.Len() > 0 {
			tokens = append(tokens, token.String())
		}
	}
	return tokens, nil
}
