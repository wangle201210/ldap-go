package acl

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func hasACLExpansion(pattern string) bool {
	for position := 0; position < len(pattern); position++ {
		if pattern[position] != '$' || position+1 >= len(pattern) {
			continue
		}
		next := pattern[position+1]
		if next >= '0' && next <= '9' {
			return true
		}
		if next != '{' {
			continue
		}
		end := strings.IndexByte(pattern[position+2:], '}')
		if end < 0 {
			continue
		}
		token := pattern[position+2 : position+2+end]
		if _, _, ok := aclExpansionReference(token); ok {
			return true
		}
	}
	return false
}

func expandACLPattern(pattern string, context matchContext) (string, bool) {
	var expanded strings.Builder
	for position := 0; position < len(pattern); {
		if pattern[position] != '$' || position+1 >= len(pattern) {
			expanded.WriteByte(pattern[position])
			position++
			continue
		}
		next := pattern[position+1]
		if next == '$' {
			expanded.WriteByte('$')
			position += 2
			continue
		}
		if next >= '0' && next <= '9' {
			appendACLExpansion(&expanded, context.dn, int(next-'0'))
			position += 2
			continue
		}
		if next != '{' {
			expanded.WriteByte('$')
			position++
			continue
		}
		end := strings.IndexByte(pattern[position+2:], '}')
		if end < 0 {
			return "", false
		}
		token := pattern[position+2 : position+2+end]
		valueMatches, index, ok := aclExpansionReference(token)
		if !ok {
			return "", false
		}
		matches := context.dn
		if valueMatches {
			matches = context.value
		}
		appendACLExpansion(&expanded, matches, index)
		position += end + 3
	}
	return expanded.String(), true
}

func aclExpansionReference(token string) (bool, int, bool) {
	valueMatches := false
	if strings.HasPrefix(token, "v") {
		valueMatches = true
		token = token[1:]
	} else if strings.HasPrefix(token, "d") {
		token = token[1:]
	}
	if token == "" {
		return false, 0, false
	}
	index, err := strconv.Atoi(token)
	if err != nil || index < 0 {
		return false, 0, false
	}
	return valueMatches, index, true
}

func appendACLExpansion(builder *strings.Builder, matches []string, index int) {
	if index >= 0 && index < len(matches) {
		builder.WriteString(matches[index])
	}
}

func matchesExpandedDN(
	matcher DNMatcher,
	candidate directory.DN,
	context matchContext,
) bool {
	if matcher.Style == DNRegex {
		pattern := matcher.Raw
		if pattern == "" && matcher.Pattern != nil {
			return matcher.Pattern.MatchString(candidate.Key())
		}
		expanded, ok := expandACLPattern(pattern, context)
		if !ok {
			return false
		}
		compiled, err := regexp.Compile("(?i)" + expanded)
		return err == nil && compiled.MatchString(candidate.Key())
	}
	if !matcher.Expand {
		return matchesDN(matcher, candidate)
	}
	expanded, ok := expandACLPattern(matcher.Raw, context)
	if !ok {
		return false
	}
	dn, err := directory.ParseDN(expanded)
	if err != nil {
		return false
	}
	matcher.DN = dn
	return matchesDN(matcher, candidate)
}
