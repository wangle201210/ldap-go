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
	referralScopeDefault referralURLScope = ""
	referralScopeBase    referralURLScope = "base"
	referralScopeOne     referralURLScope = "one"
	referralScopeSubtree referralURLScope = "sub"
)

func referralScopeForSearch(scope directory.Scope) referralURLScope {
	switch scope {
	case directory.ScopeBase:
		return referralScopeBase
	case directory.ScopeSingleLevel:
		return referralScopeOne
	case directory.ScopeWholeSubtree:
		return referralScopeSubtree
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

func (server *Server) entryOrReferral(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	target directory.DN,
	manageDsaIT bool,
) (directory.Entry, error) {
	entry, err := reader.Get(target)
	if err == nil {
		if manageDsaIT || !runtime.schema.EntryHasObjectClass(entry, "referral") {
			return entry, nil
		}
		if !server.allowed(
			runtime,
			reader,
			boundDN,
			entry,
			"entry",
			nil,
			acl.Disclose,
		) {
			return directory.Entry{}, storage.ErrEntryNotFound
		}
		result, err := referralResult(entry, &target, referralScopeDefault)
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
	if !server.allowed(
		runtime,
		reader,
		boundDN,
		ancestor,
		"entry",
		nil,
		acl.Disclose,
	) {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	result, err := referralResult(ancestor, &target, referralScopeDefault)
	if err != nil {
		return directory.Entry{}, err
	}
	return directory.Entry{}, &operationFailure{result: result}
}

func closestExistingAncestor(
	reader storage.Reader,
	target directory.DN,
) (directory.Entry, bool, error) {
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
	referrals, err := rewrittenReferralURLs(entry, target, scope)
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
		MatchedDN: entry.DN,
		Referrals: referrals,
	}, nil
}

func rewrittenReferralURLs(
	entry directory.Entry,
	target *directory.DN,
	scope referralURLScope,
) ([]string, error) {
	base, err := directory.ParseDN(entry.DN)
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
		rewritten, ok := rewriteReferralURL(raw, base, target, scope)
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
	base directory.DN,
	target *directory.DN,
	scope referralURLScope,
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
	switch {
	case parsed.Path == "":
	case !strings.HasPrefix(parsed.Path, "/"):
		return "", false
	default:
		rawDN := strings.TrimPrefix(parsed.Path, "/")
		if rawDN != "" {
			dn, err := directory.ParseDN(rawDN)
			if err != nil {
				return "", false
			}
			referralDN = &dn
		}
	}

	rewrittenDN, err := rewriteReferralDN(referralDN, base, target)
	if err != nil {
		return "", false
	}
	parsed.Path = "/" + rewrittenDN
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
	base directory.DN,
	target *directory.DN,
) (string, error) {
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
		rewritten, err := target.ReplaceAncestor(base, *referralDN)
		if err != nil {
			return "", err
		}
		return rewritten.String(), nil
	}
	return target.String(), nil
}
