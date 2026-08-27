package server

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type referralURLScope string

const (
	referralScopeDefault  referralURLScope = ""
	referralScopeBase     referralURLScope = "base"
	referralScopeOne      referralURLScope = "one"
	referralScopeSubtree  referralURLScope = "sub"
	referralScopeChildren referralURLScope = "subordinate"
)

func referralScopeForSearch(scope directory.Scope) referralURLScope {
	switch scope {
	case directory.ScopeBase:
		return referralScopeBase
	case directory.ScopeSingleLevel:
		return referralScopeOne
	case directory.ScopeWholeSubtree:
		return referralScopeSubtree
	case directory.ScopeChildren:
		return referralScopeChildren
	default:
		return referralScopeDefault
	}
}

func referralScopeForReference(scope directory.Scope) referralURLScope {
	if scope == directory.ScopeSingleLevel {
		return referralScopeBase
	}
	return referralScopeSubtree
}

func globalReferralResult(
	runtime *runtimeState,
	target *directory.DN,
	scope referralURLScope,
) (ldapwire.Result, bool) {
	if runtime == nil || len(runtime.defaultReferrals) == 0 {
		return ldapwire.Result{}, false
	}
	referrals := make([]string, 0, len(runtime.defaultReferrals))
	for _, raw := range runtime.defaultReferrals {
		candidate, scheme, recognized, _ := openLDAPReferralURL(raw)
		if !recognized {
			referrals = append(referrals, raw)
			continue
		}
		rewritten, ok := rewriteReferralURLWithNormalizer(
			raw,
			nil,
			target,
			scope,
			runtime.schema,
		)
		if ok {
			referrals = append(referrals, rewritten)
		} else if scheme == "ldapi" {
			referrals = append(referrals, rewriteGlobalLDAPIReferral(
				candidate,
				runtime,
				target,
				scope,
			))
		} else {
			referrals = append(referrals, raw)
		}
	}
	if len(referrals) == 0 {
		// OpenLDAP falls back to the configured values if rewriting fails.
		referrals = append(referrals, runtime.defaultReferrals...)
	}
	return ldapwire.Result{
		Code:      ldapwire.ResultReferral,
		Referrals: referrals,
	}, true
}

func rewriteGlobalLDAPIReferral(
	candidate string,
	runtime *runtimeState,
	target *directory.DN,
	scope referralURLScope,
) string {
	const (
		prefix      = "ldapi://"
		placeholder = "ldapi://ldap-go.invalid"
	)
	authority := candidate[len(prefix):]
	if slash := strings.IndexByte(authority, '/'); slash >= 0 {
		authority = authority[:slash]
	}
	if _, err := url.PathUnescape(authority); err != nil {
		authority = ""
	}
	rewritten, ok := rewriteReferralURLWithNormalizer(
		placeholder,
		nil,
		target,
		scope,
		runtime.schema,
	)
	if !ok {
		return candidate
	}
	return prefix + authority + strings.TrimPrefix(rewritten, placeholder)
}

func globalReferralOrResult(
	runtime *runtimeState,
	target *directory.DN,
	scope referralURLScope,
	fallback ldapwire.Result,
) ldapwire.Result {
	if result, ok := globalReferralResult(runtime, target, scope); ok {
		return result
	}
	return fallback
}

func globalReferralForMissingTarget(
	runtime *runtimeState,
	reader storage.Reader,
	target directory.DN,
	scope referralURLScope,
) (*ldapwire.Result, error) {
	_, found, err := closestExistingAncestor(reader, target)
	if err != nil {
		return nil, err
	}
	if found {
		return nil, nil
	}
	result, ok := globalReferralResult(runtime, &target, scope)
	if !ok {
		return nil, nil
	}
	return &result, nil
}

func (server *Server) entryOrReferral(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	target directory.DN,
	manageDsaIT bool,
) (directory.Entry, error) {
	target, err := storage.NormalizeReaderDN(reader, target)
	if err != nil {
		return directory.Entry{}, fmt.Errorf(
			"normalize referral request DN %q: %w",
			target.String(),
			err,
		)
	}
	entry, err := reader.Get(target)
	if err == nil {
		if manageDsaIT || !runtime.schema.EntryHasObjectClass(entry, "referral") {
			return entry, nil
		}
		logicalEntry, err := withCollectiveAttributes(runtime.schema, reader, entry)
		if err != nil {
			return directory.Entry{}, err
		}
		if !server.allowed(
			runtime,
			reader,
			boundDN,
			logicalEntry,
			"entry",
			nil,
			acl.Disclose,
		) {
			return directory.Entry{}, storage.ErrEntryNotFound
		}
		result, err := referralResultWithReader(
			entry,
			&target,
			referralScopeDefault,
			reader,
		)
		if err != nil {
			return directory.Entry{}, err
		}
		return directory.Entry{}, &operationFailure{result: result}
	}
	if !errors.Is(err, storage.ErrEntryNotFound) {
		return directory.Entry{}, err
	}

	ancestor, found, err := closestExistingAncestor(reader, target)
	if err != nil {
		return directory.Entry{}, err
	}
	if !found ||
		!runtime.schema.EntryHasObjectClass(ancestor, "referral") {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	logicalAncestor, err := withCollectiveAttributes(runtime.schema, reader, ancestor)
	if err != nil {
		return directory.Entry{}, err
	}
	if !server.allowed(
		runtime,
		reader,
		boundDN,
		logicalAncestor,
		"entry",
		nil,
		acl.Disclose,
	) {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	result, err := referralResultWithReader(
		ancestor,
		&target,
		referralScopeDefault,
		reader,
	)
	if err != nil {
		return directory.Entry{}, err
	}
	return directory.Entry{}, &operationFailure{result: result}
}

func closestExistingAncestor(
	reader storage.Reader,
	target directory.DN,
) (directory.Entry, bool, error) {
	target, err := storage.NormalizeReaderDN(reader, target)
	if err != nil {
		return directory.Entry{}, false, fmt.Errorf(
			"normalize referral target DN %q: %w",
			target.String(),
			err,
		)
	}
	current, ok := target.Parent()
	for ok {
		entry, err := reader.Get(current)
		switch {
		case err == nil:
			return entry, true, nil
		case !errors.Is(err, storage.ErrEntryNotFound):
			return directory.Entry{}, false, err
		}
		current, ok = current.Parent()
	}
	return directory.Entry{}, false, nil
}

func referralResult(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
) (ldapwire.Result, error) {
	return referralResultWithParser(
		entry,
		target,
		scope,
		nil,
	)
}

func referralResultWithNormalizer(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
	normalizer directory.DNAttributeNormalizer,
) (ldapwire.Result, error) {
	return referralResultWithParser(
		entry,
		target,
		scope,
		referralParserWithNormalizer(normalizer),
	)
}

func referralResultWithReader(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
	reader storage.Reader,
) (ldapwire.Result, error) {
	return referralResultWithParser(
		entry,
		target,
		scope,
		referralParserWithReader(reader),
	)
}

func referralResultWithParser(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
	parser referralDNParser,
) (ldapwire.Result, error) {
	matchedDN := entry.DN
	if parser != nil {
		normalized, err := parseReferralDNWithParser(entry.DN, parser)
		if err != nil {
			return ldapwire.Result{}, fmt.Errorf(
				"parse referral matched DN %q: %w",
				entry.DN,
				err,
			)
		}
		matchedDN = normalized.String()
	}
	referrals, err := rewrittenReferralURLsWithParser(
		entry,
		target,
		scope,
		parser,
	)
	if err != nil {
		return ldapwire.Result{}, err
	}
	if len(referrals) == 0 {
		return ldapwire.ResultError(
			ldapwire.ResultOther,
			"bad referral object",
		), nil
	}
	return ldapwire.Result{
		Code:      ldapwire.ResultReferral,
		MatchedDN: matchedDN,
		Referrals: referrals,
	}, nil
}

func rewrittenReferralURLs(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
) ([]string, error) {
	return rewrittenReferralURLsWithParser(
		entry,
		target,
		scope,
		nil,
	)
}

func rewrittenReferralURLsWithNormalizer(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
	normalizer directory.DNAttributeNormalizer,
) ([]string, error) {
	return rewrittenReferralURLsWithParser(
		entry,
		target,
		scope,
		referralParserWithNormalizer(normalizer),
	)
}

func rewrittenReferralURLsWithParser(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
	parser referralDNParser,
) ([]string, error) {
	base, err := parseReferralDNWithParser(entry.DN, parser)
	if err != nil {
		return nil, fmt.Errorf("parse referral DN %q: %w", entry.DN, err)
	}
	var values [][]byte
	for _, attribute := range entry.Attributes {
		description := attribute.Description
		if index := strings.IndexByte(description, ';'); index >= 0 {
			description = description[:index]
		}
		if strings.EqualFold(strings.TrimSpace(description), "ref") {
			values = append(values, attribute.Values...)
		}
	}
	referrals := make([]string, 0, len(values))
	for _, value := range values {
		raw := referralURI(string(value))
		if raw == "" {
			continue
		}
		rewritten, ok := rewriteReferralURLWithParser(
			raw,
			&base,
			target,
			scope,
			parser,
		)
		if ok {
			referrals = append(referrals, rewritten)
		}
	}
	return referrals, nil
}

func referralURI(value string) string {
	if index := strings.IndexFunc(value, unicode.IsSpace); index >= 0 {
		value = value[:index]
	}
	return value
}

func rewriteReferralURL(
	raw string,
	base *directory.DN,
	target *directory.DN,
	scope referralURLScope,
) (string, bool) {
	return rewriteReferralURLWithParser(
		raw,
		base,
		target,
		scope,
		nil,
	)
}

func rewriteReferralURLWithNormalizer(
	raw string,
	base *directory.DN,
	target *directory.DN,
	scope referralURLScope,
	normalizer directory.DNAttributeNormalizer,
) (string, bool) {
	return rewriteReferralURLWithParser(
		raw,
		base,
		target,
		scope,
		referralParserWithNormalizer(normalizer),
	)
}

func rewriteReferralURLWithParser(
	raw string,
	base *directory.DN,
	target *directory.DN,
	scope referralURLScope,
	parser referralDNParser,
) (string, bool) {
	candidate := raw
	enclosed := strings.HasPrefix(candidate, "<")
	closed := !enclosed || strings.HasSuffix(candidate, ">")
	if enclosed {
		candidate = strings.TrimPrefix(candidate, "<")
		if closed {
			candidate = strings.TrimSuffix(candidate, ">")
		}
	}
	if len(candidate) >= len("URL:") &&
		strings.EqualFold(candidate[:len("URL:")], "URL:") {
		candidate = candidate[len("URL:"):]
	}

	schemeEnd := strings.IndexByte(candidate, ':')
	if schemeEnd < 0 {
		return raw, true
	}
	scheme := strings.ToLower(candidate[:schemeEnd])
	if scheme != "ldap" &&
		scheme != "ldaps" &&
		scheme != "ldapi" &&
		scheme != "ldap+tlcp" &&
		scheme != "pldap" &&
		scheme != "pldaps" {
		return raw, true
	}
	if !closed || !strings.HasPrefix(candidate[schemeEnd+1:], "//") {
		return "", false
	}

	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Opaque != "" || parsed.Fragment != "" ||
		parsed.User != nil {
		return "", false
	}
	parsed.Scheme = scheme
	parsed.OmitHost = false

	var referralDN *directory.DN
	var referralDNDisplay string
	switch {
	case parsed.Path == "":
	case !strings.HasPrefix(parsed.Path, "/"):
		return "", false
	default:
		rawDN := strings.TrimPrefix(parsed.Path, "/")
		if rawDN != "" {
			dn, err := parseReferralDNWithParser(rawDN, parser)
			if err != nil {
				return "", false
			}
			referralDN = &dn
			referralDNDisplay = rawDN
		}
	}

	rewrittenDN, err := rewriteReferralDNWithParser(
		referralDN,
		base,
		target,
		parser,
	)
	if err != nil {
		return "", false
	}
	if parser == nil && referralDN != nil {
		rewrittenDN = preserveReferralDNDisplay(
			rewrittenDN,
			referralDNDisplay,
			referralDN,
			base,
			target,
		)
	}
	preserveAbsentPath := parsed.Path == "" && referralDN == nil &&
		base == nil && target == nil && rewrittenDN == ""
	if preserveAbsentPath {
		parsed.Path = ""
	} else {
		parsed.Path = "/" + rewrittenDN
	}
	parsed.RawPath = ""

	components, ok := referralURLQuery(parsed)
	if !ok {
		return "", false
	}
	if scope != referralScopeDefault {
		for len(components) < 2 {
			components = append(components, "")
		}
		if components[1] == "" {
			components[1] = string(scope)
		}
	}
	parsed.RawQuery = strings.Join(components, "?")
	parsed.ForceQuery = len(components) > 0
	return parsed.String(), true
}

func preserveReferralDNDisplay(
	rewritten string,
	display string,
	referralDN *directory.DN,
	base *directory.DN,
	target *directory.DN,
) string {
	if display == "" || referralDN == nil {
		return rewritten
	}
	if target == nil {
		return display
	}
	if base == nil || base.Equal(*referralDN) ||
		(!base.Equal(*target) && !base.AncestorOf(*target)) {
		return rewritten
	}
	normalizedSuffix := referralDN.String()
	if rewritten == normalizedSuffix {
		return display
	}
	suffix := "," + normalizedSuffix
	if strings.HasSuffix(rewritten, suffix) {
		return strings.TrimSuffix(rewritten, suffix) + "," + display
	}
	return rewritten
}

func referralURLQuery(parsed *url.URL) ([]string, bool) {
	if parsed.RawQuery == "" && !parsed.ForceQuery {
		return nil, true
	}
	components := strings.Split(parsed.RawQuery, "?")
	if len(components) > 4 {
		return nil, false
	}
	for _, component := range components {
		if _, err := url.PathUnescape(component); err != nil {
			return nil, false
		}
	}
	if len(components) > 1 && components[1] != "" {
		scope, err := url.PathUnescape(components[1])
		if err != nil {
			return nil, false
		}
		switch strings.ToLower(scope) {
		case "base":
			components[1] = "base"
		case "one", "onelevel":
			components[1] = "one"
		case "sub", "subtree":
			components[1] = "sub"
		case "subord", "subordinate", "children":
			components[1] = "subordinate"
		default:
			return nil, false
		}
	}
	return components, true
}

func rewriteReferralDN(
	referralDN *directory.DN,
	base *directory.DN,
	target *directory.DN,
) (string, error) {
	return rewriteReferralDNWithParser(
		referralDN,
		base,
		target,
		nil,
	)
}

func rewriteReferralDNWithNormalizer(
	referralDN *directory.DN,
	base *directory.DN,
	target *directory.DN,
	normalizer directory.DNAttributeNormalizer,
) (string, error) {
	return rewriteReferralDNWithParser(
		referralDN,
		base,
		target,
		referralParserWithNormalizer(normalizer),
	)
}

func rewriteReferralDNWithParser(
	referralDN *directory.DN,
	base *directory.DN,
	target *directory.DN,
	parser referralDNParser,
) (string, error) {
	var err error
	referralDN, err = normalizeReferralDN(referralDN, parser)
	if err != nil {
		return "", err
	}
	base, err = normalizeReferralDN(base, parser)
	if err != nil {
		return "", err
	}
	target, err = normalizeReferralDN(target, parser)
	if err != nil {
		return "", err
	}
	if base == nil {
		if target == nil {
			return "", nil
		}
		return target.String(), nil
	}
	if target == nil {
		if referralDN != nil {
			return referralDN.String(), nil
		}
		return base.String(), nil
	}
	if referralDN == nil {
		return target.String(), nil
	}
	if base.Equal(*referralDN) {
		return target.String(), nil
	}
	if base.Equal(*target) || base.AncestorOf(*target) {
		rewritten, err := target.ReplaceAncestor(*base, *referralDN)
		if err != nil {
			return "", err
		}
		return rewritten.String(), nil
	}
	return target.String(), nil
}

type referralDNParser func(string) (directory.DN, error)

func parseReferralDNWithParser(
	value string,
	parser referralDNParser,
) (directory.DN, error) {
	if parser == nil {
		return directory.ParseDN(value)
	}
	return parser(value)
}

func referralParserWithNormalizer(
	normalizer directory.DNAttributeNormalizer,
) referralDNParser {
	if normalizer == nil {
		return nil
	}
	return func(value string) (directory.DN, error) {
		return directory.ParseDNWithNormalizer(value, normalizer)
	}
}

func referralParserWithReader(reader storage.Reader) referralDNParser {
	return func(value string) (directory.DN, error) {
		dn, err := directory.ParseDN(value)
		if err != nil {
			return directory.DN{}, err
		}
		return storage.NormalizeReaderDN(reader, dn)
	}
}

func normalizeReferralDN(
	dn *directory.DN,
	parser referralDNParser,
) (*directory.DN, error) {
	if dn == nil || parser == nil {
		return dn, nil
	}
	normalized, err := parseReferralDNWithParser(dn.String(), parser)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}
