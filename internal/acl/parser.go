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
	for _, token := range tokens {
		if token == "*" {
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
				if strings.HasPrefix(attribute, "@") || strings.HasPrefix(attribute, "!") {
					return TargetSelector{}, fmt.Errorf(
						"object-class attribute selector %q is not implemented",
						attribute,
					)
				}
				target.Attributes = append(target.Attributes, attribute)
			}
		case strings.HasPrefix(key, "dn"):
			matcher, err := parseDNMatcher(key, value)
			if err != nil {
				return TargetSelector{}, fmt.Errorf("target %s: %w", key, err)
			}
			target.DN = matcher
		case key == "filter":
			return TargetSelector{}, errors.New("ACL filter selectors are not implemented")
		case strings.HasPrefix(key, "val"):
			return TargetSelector{}, errors.New("ACL value selectors are not implemented")
		default:
			return TargetSelector{}, fmt.Errorf("unsupported target selector %q", token)
		}
	}
	return target, nil
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
	switch strings.ToLower(token) {
	case "*":
		return WhoMatcher{Kind: WhoAny}, nil
	case "anonymous":
		return WhoMatcher{Kind: WhoAnonymous}, nil
	case "users":
		return WhoMatcher{Kind: WhoUsers}, nil
	case "self":
		return WhoMatcher{Kind: WhoSelf}, nil
	}

	key, value, ok := splitSelector(token)
	if !ok {
		return WhoMatcher{}, fmt.Errorf("unsupported subject selector %q", token)
	}
	switch {
	case strings.HasPrefix(key, "dn.") || key == "dn":
		matcher, err := parseDNMatcher(key, value)
		if err != nil {
			return WhoMatcher{}, fmt.Errorf("subject %s: %w", key, err)
		}
		return WhoMatcher{Kind: WhoDN, DN: matcher}, nil
	case key == "dnattr":
		if value == "" {
			return WhoMatcher{}, errors.New("dnattr requires an attribute")
		}
		return WhoMatcher{Kind: WhoDNAttribute, Attribute: value}, nil
	case strings.HasPrefix(key, "group"):
		return parseGroupMatcher(key, value)
	case key == "ssf":
		minimum, err := strconv.Atoi(value)
		if err != nil || minimum < 0 {
			return WhoMatcher{}, fmt.Errorf("invalid SSF %q", value)
		}
		return WhoMatcher{Kind: WhoSSF, MinimumSSF: minimum}, nil
	default:
		return WhoMatcher{}, fmt.Errorf("unsupported subject selector %q", token)
	}
}

func parseGroupMatcher(key, value string) (WhoMatcher, error) {
	style := "exact"
	if dot := strings.LastIndexByte(key, '.'); dot >= 0 {
		style = key[dot+1:]
		key = key[:dot]
	}
	if style != "exact" {
		return WhoMatcher{}, fmt.Errorf("group style %q is not implemented", style)
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
	groupDN, err := directory.ParseDN(value)
	if err != nil {
		return WhoMatcher{}, err
	}
	return WhoMatcher{
		Kind:             WhoGroup,
		DN:               DNMatcher{Style: DNExact, DN: groupDN},
		GroupObjectClass: objectClass,
		GroupAttribute:   attribute,
	}, nil
}

func parseDNMatcher(key, value string) (DNMatcher, error) {
	style := "regex"
	if dot := strings.IndexByte(key, '.'); dot >= 0 {
		style = key[dot+1:]
		if comma := strings.IndexByte(style, ','); comma >= 0 {
			if style[comma+1:] != "expand" {
				return DNMatcher{}, fmt.Errorf("unsupported DN modifier %q", style[comma+1:])
			}
			return DNMatcher{}, errors.New("DN expansion is not implemented")
		}
	}
	switch style {
	case "regex":
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
		return DNMatcher{}, fmt.Errorf("unsupported DN style %q", style)
	}
}

func parseGrant(token string) (Grant, error) {
	grant := Grant{Mode: grantSet}
	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, "self") {
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
	if strings.HasPrefix(lower, "self") {
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
