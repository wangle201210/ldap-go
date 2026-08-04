package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

const ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"

func ldapReferralClientResult(err error) (uint16, string, bool) {
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		return 0, "", false
	}
	switch ldapError.ResultCode {
	case ldap.LDAPResultClientLoop:
		return ldapError.ResultCode, "Client Loop", true
	case ldap.LDAPResultReferralLimitExceeded:
		return ldapError.ResultCode, "Referral Limit Exceeded", true
	default:
		return 0, "", false
	}
}

type ldapReferralTarget struct {
	raw              string
	endpoint         string
	dn               string
	hasDN            bool
	scope            int
	hasScope         bool
	startTLS         bool
	startTLSRequired bool
}

func parseLDAPReferralTarget(raw string) (ldapReferralTarget, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ldapReferralTarget{}, fmt.Errorf("parse referral URL %q: %w", raw, err)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
		return ldapReferralTarget{}, fmt.Errorf(
			"referral URL %q must use ldap:// or ldaps://",
			raw,
		)
	}
	if parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.Opaque != "" {
		return ldapReferralTarget{}, fmt.Errorf("referral URL %q is invalid", raw)
	}

	target := ldapReferralTarget{
		raw:      raw,
		endpoint: (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String(),
		hasDN:    parsed.EscapedPath() != "",
	}
	if target.hasDN {
		escapedDN := strings.TrimPrefix(parsed.EscapedPath(), "/")
		target.dn, err = url.PathUnescape(escapedDN)
		if err != nil {
			return ldapReferralTarget{}, fmt.Errorf("decode referral DN in %q: %w", raw, err)
		}
		if target.dn != "" {
			if _, err := ldap.ParseDN(target.dn); err != nil {
				return ldapReferralTarget{}, fmt.Errorf(
					"parse referral DN %q: %w",
					target.dn,
					err,
				)
			}
		}
	}

	components := strings.Split(parsed.RawQuery, "?")
	if len(components) > 4 {
		return ldapReferralTarget{}, fmt.Errorf("referral URL %q has too many query components", raw)
	}
	if len(components) > 1 && components[1] != "" {
		scopeName, err := url.PathUnescape(components[1])
		if err != nil {
			return ldapReferralTarget{}, fmt.Errorf("decode referral scope in %q: %w", raw, err)
		}
		switch strings.ToLower(scopeName) {
		case "base":
			target.scope = ldap.ScopeBaseObject
		case "one":
			target.scope = ldap.ScopeSingleLevel
		case "sub":
			target.scope = ldap.ScopeWholeSubtree
		default:
			return ldapReferralTarget{}, fmt.Errorf(
				"referral URL %q has invalid search scope %q",
				raw,
				scopeName,
			)
		}
		target.hasScope = true
	}
	if len(components) == 4 && components[3] != "" {
		for _, rawExtension := range strings.Split(components[3], ",") {
			extension, err := url.PathUnescape(rawExtension)
			if err != nil {
				return ldapReferralTarget{}, fmt.Errorf(
					"decode referral extension in %q: %w",
					raw,
					err,
				)
			}
			critical := strings.HasPrefix(extension, "!")
			extension = strings.TrimPrefix(extension, "!")
			name, _, _ := strings.Cut(extension, "=")
			if strings.EqualFold(name, "StartTLS") || name == ldapStartTLSOID {
				target.startTLS = true
				target.startTLSRequired = target.startTLSRequired || critical
				continue
			}
			if critical {
				return ldapReferralTarget{}, fmt.Errorf(
					"referral URL %q has unsupported critical extension %q",
					raw,
					name,
				)
			}
		}
	}
	if target.startTLS && parsed.Scheme == "ldaps" {
		return ldapReferralTarget{}, fmt.Errorf(
			"referral URL %q cannot combine ldaps:// and StartTLS",
			raw,
		)
	}
	return target, nil
}

func (options *ldapClientOptions) connectLDAPReferral(
	target ldapReferralTarget,
) (*ldap.Conn, error) {
	parsed, err := url.Parse(target.endpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := options.clientTLSConfig(parsed.Hostname())
	if err != nil {
		return nil, err
	}
	dialOptions := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: options.timeout}),
	}
	if parsed.Scheme == "ldaps" {
		dialOptions = append(dialOptions, ldap.DialWithTLSConfig(tlsConfig.Clone()))
	}
	connection, err := ldap.DialURL(target.endpoint, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("connect to referral %s: %w", target.endpoint, err)
	}
	connection.SetTimeout(options.timeout)
	closeOnError := func(err error) (*ldap.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	if target.startTLS {
		if err := connection.StartTLS(tlsConfig.Clone()); err != nil {
			if target.startTLSRequired {
				return closeOnError(fmt.Errorf("StartTLS with referral %s: %w", target.endpoint, err))
			}
			_ = connection.Close()
			connection, err = ldap.DialURL(
				target.endpoint,
				ldap.DialWithDialer(&net.Dialer{Timeout: options.timeout}),
			)
			if err != nil {
				return nil, fmt.Errorf(
					"reconnect to referral %s after StartTLS failure: %w",
					target.endpoint,
					err,
				)
			}
			connection.SetTimeout(options.timeout)
		}
	}
	// OpenLDAP libldap performs an anonymous bind on a referral connection
	// unless an application installs an explicit rebind callback. The tools do not.
	if err := connection.UnauthenticatedBind(""); err != nil {
		return closeOnError(fmt.Errorf("anonymous bind to referral %s: %w", target.endpoint, err))
	}
	return connection, nil
}

func (options *ldapClientOptions) searchWithReferrals(
	connection *ldap.Conn,
	request *ldap.SearchRequest,
	pageSize uint32,
) (*ldap.SearchResult, error) {
	seen := map[string]struct{}{
		options.referralKey(options.uri, "search", request.BaseDN): {},
	}
	return options.searchWithReferralsAt(connection, request, pageSize, 0, seen)
}

func (options *ldapClientOptions) searchWithReferralsAt(
	connection *ldap.Conn,
	request *ldap.SearchRequest,
	pageSize uint32,
	depth int,
	seen map[string]struct{},
) (*ldap.SearchResult, error) {
	sent := cloneLDAPSearchRequest(request)
	defer clearLDAPControls(sent.Controls)
	var result *ldap.SearchResult
	var searchErr error
	if pageSize > 0 {
		result, searchErr = connection.SearchWithPaging(&sent, pageSize)
	} else {
		result, searchErr = connection.Search(&sent)
	}
	if !options.chaseReferrals {
		return result, searchErr
	}
	if result == nil {
		result = &ldap.SearchResult{}
	}
	references := append([]string(nil), result.Referrals...)
	result.Referrals = nil
	for _, reference := range references {
		followed, err := options.followLDAPSearchReferrals(
			[]string{reference},
			request,
			pageSize,
			true,
			depth,
			seen,
		)
		appendLDAPSearchResult(result, followed)
		if err != nil {
			return result, err
		}
	}

	referrals := ldapReferralURLs(searchErr)
	if len(referrals) == 0 {
		return result, searchErr
	}
	followed, err := options.followLDAPSearchReferrals(
		referrals,
		request,
		pageSize,
		false,
		depth,
		seen,
	)
	appendLDAPSearchResult(result, followed)
	return result, err
}

func (options *ldapClientOptions) followLDAPSearchReferrals(
	referrals []string,
	request *ldap.SearchRequest,
	pageSize uint32,
	searchReference bool,
	depth int,
	seen map[string]struct{},
) (*ldap.SearchResult, error) {
	if depth >= options.referralHopLimit {
		return nil, ldap.NewError(
			ldap.LDAPResultReferralLimitExceeded,
			fmt.Errorf("referral hop limit %d exceeded", options.referralHopLimit),
		)
	}
	var lastErr error
	for _, raw := range referrals {
		target, err := parseLDAPReferralTarget(raw)
		if err != nil {
			lastErr = err
			continue
		}
		followedRequest := cloneLDAPSearchRequest(request)
		applyLDAPSearchReferral(&followedRequest, target, searchReference)
		key := options.referralKey(target.endpoint, "search", followedRequest.BaseDN)
		if _, duplicate := seen[key]; duplicate {
			clearLDAPControls(followedRequest.Controls)
			lastErr = ldap.NewError(
				ldap.LDAPResultClientLoop,
				fmt.Errorf("LDAP referral loop at %s", target.raw),
			)
			continue
		}
		connection, err := options.connectLDAPReferral(target)
		if err != nil {
			clearLDAPControls(followedRequest.Controls)
			lastErr = err
			continue
		}
		branchSeen := cloneLDAPReferralSet(seen)
		branchSeen[key] = struct{}{}
		result, err := options.searchWithReferralsAt(
			connection,
			&followedRequest,
			pageSize,
			depth+1,
			branchSeen,
		)
		_ = connection.Close()
		clearLDAPControls(followedRequest.Controls)
		return result, err
	}
	if lastErr == nil {
		lastErr = errors.New("server returned an empty LDAP referral")
	}
	return nil, fmt.Errorf("chase LDAP referral: %w", lastErr)
}

func applyLDAPSearchReferral(
	request *ldap.SearchRequest,
	target ldapReferralTarget,
	searchReference bool,
) {
	if target.hasDN {
		request.BaseDN = target.dn
	} else if searchReference {
		request.BaseDN = ""
	}
	if target.hasScope {
		request.Scope = target.scope
	} else if searchReference {
		switch request.Scope {
		case ldap.ScopeBaseObject, ldap.ScopeSingleLevel:
			request.Scope = ldap.ScopeBaseObject
		default:
			request.Scope = ldap.ScopeWholeSubtree
		}
	}
}

func cloneLDAPSearchRequest(request *ldap.SearchRequest) ldap.SearchRequest {
	cloned := *request
	cloned.Attributes = append([]string(nil), request.Attributes...)
	cloned.Controls = cloneLDAPControls(request.Controls)
	return cloned
}

func appendLDAPSearchResult(destination, source *ldap.SearchResult) {
	if destination == nil || source == nil {
		return
	}
	destination.Entries = append(destination.Entries, source.Entries...)
	destination.Referrals = append(destination.Referrals, source.Referrals...)
	destination.Controls = append(destination.Controls, source.Controls...)
}

func (options *ldapClientOptions) executeWriteWithReferrals(
	connection *ldap.Conn,
	operation *ldapWriteOperation,
) error {
	seen := map[string]struct{}{
		options.referralKey(options.uri, operation.name(), operation.dn()): {},
	}
	return options.executeWriteWithReferralsAt(connection, operation, 0, seen)
}

func (options *ldapClientOptions) executeWriteWithReferralsAt(
	connection *ldap.Conn,
	operation *ldapWriteOperation,
	depth int,
	seen map[string]struct{},
) error {
	err := operation.execute(connection)
	if !options.chaseReferrals {
		return err
	}
	referrals := ldapReferralURLs(err)
	if len(referrals) == 0 {
		return err
	}
	if depth >= options.referralHopLimit {
		return ldap.NewError(
			ldap.LDAPResultReferralLimitExceeded,
			fmt.Errorf("referral hop limit %d exceeded", options.referralHopLimit),
		)
	}
	var lastErr error
	for _, raw := range referrals {
		target, parseErr := parseLDAPReferralTarget(raw)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		followed := cloneLDAPWriteOperation(operation)
		if target.hasDN {
			followed.setDN(target.dn)
		}
		key := options.referralKey(target.endpoint, operation.name(), followed.dn())
		if _, duplicate := seen[key]; duplicate {
			lastErr = ldap.NewError(
				ldap.LDAPResultClientLoop,
				fmt.Errorf("LDAP referral loop at %s", target.raw),
			)
			continue
		}
		referralConnection, connectErr := options.connectLDAPReferral(target)
		if connectErr != nil {
			lastErr = connectErr
			continue
		}
		branchSeen := cloneLDAPReferralSet(seen)
		branchSeen[key] = struct{}{}
		executeErr := options.executeWriteWithReferralsAt(
			referralConnection,
			followed,
			depth+1,
			branchSeen,
		)
		_ = referralConnection.Close()
		return executeErr
	}
	if lastErr == nil {
		lastErr = err
	}
	return fmt.Errorf("chase LDAP referral: %w", lastErr)
}

func cloneLDAPWriteOperation(operation *ldapWriteOperation) *ldapWriteOperation {
	cloned := *operation
	switch operation.kind {
	case ldapWriteAdd:
		request := *operation.add
		cloned.add = &request
	case ldapWriteModify:
		request := *operation.modify
		cloned.modify = &request
	case ldapWriteDelete:
		request := *operation.delete
		cloned.delete = &request
	case ldapWriteModifyDN:
		request := *operation.modifyDN
		cloned.modifyDN = &request
	}
	return &cloned
}

func (operation *ldapWriteOperation) setDN(dn string) {
	switch operation.kind {
	case ldapWriteAdd:
		operation.add.DN = dn
	case ldapWriteModify:
		operation.modify.DN = dn
	case ldapWriteDelete:
		operation.delete.DN = dn
	case ldapWriteModifyDN:
		operation.modifyDN.DN = dn
	}
}

func (options *ldapClientOptions) extendedWithReferrals(
	connection *ldap.Conn,
	request *ldap.ExtendedRequest,
) (*ldap.ExtendedResponse, error) {
	seen := map[string]struct{}{
		options.referralKey(options.uri, "extended", request.Name): {},
	}
	return options.extendedWithReferralsAt(connection, request, 0, seen)
}

func (options *ldapClientOptions) extendedWithReferralsAt(
	connection *ldap.Conn,
	request *ldap.ExtendedRequest,
	depth int,
	seen map[string]struct{},
) (*ldap.ExtendedResponse, error) {
	response, err := connection.Extended(request)
	if !options.chaseReferrals {
		return response, err
	}
	referrals := ldapReferralURLs(err)
	if len(referrals) == 0 {
		return response, err
	}
	if depth >= options.referralHopLimit {
		return nil, ldap.NewError(
			ldap.LDAPResultReferralLimitExceeded,
			fmt.Errorf("referral hop limit %d exceeded", options.referralHopLimit),
		)
	}
	var lastErr error
	for _, raw := range referrals {
		target, parseErr := parseLDAPReferralTarget(raw)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		key := options.referralKey(target.endpoint, "extended", request.Name)
		if _, duplicate := seen[key]; duplicate {
			lastErr = ldap.NewError(
				ldap.LDAPResultClientLoop,
				fmt.Errorf("LDAP referral loop at %s", target.raw),
			)
			continue
		}
		referralConnection, connectErr := options.connectLDAPReferral(target)
		if connectErr != nil {
			lastErr = connectErr
			continue
		}
		branchSeen := cloneLDAPReferralSet(seen)
		branchSeen[key] = struct{}{}
		response, executeErr := options.extendedWithReferralsAt(
			referralConnection,
			request,
			depth+1,
			branchSeen,
		)
		_ = referralConnection.Close()
		return response, executeErr
	}
	if lastErr == nil {
		lastErr = err
	}
	return nil, fmt.Errorf("chase LDAP referral: %w", lastErr)
}

func (options *ldapClientOptions) compareWithReferrals(
	connection *ldap.Conn,
	dn, attribute, value string,
) (bool, error) {
	seen := map[string]struct{}{
		options.referralKey(options.uri, "compare", dn): {},
	}
	return options.compareWithReferralsAt(connection, dn, attribute, value, 0, seen)
}

func (options *ldapClientOptions) compareWithReferralsAt(
	connection *ldap.Conn,
	dn, attribute, value string,
	depth int,
	seen map[string]struct{},
) (bool, error) {
	matched, err := connection.Compare(dn, attribute, value)
	if !options.chaseReferrals {
		return matched, err
	}
	referrals := ldapReferralURLs(err)
	if len(referrals) == 0 {
		return matched, err
	}
	if depth >= options.referralHopLimit {
		return false, ldap.NewError(
			ldap.LDAPResultReferralLimitExceeded,
			fmt.Errorf("referral hop limit %d exceeded", options.referralHopLimit),
		)
	}
	var lastErr error
	for _, raw := range referrals {
		target, parseErr := parseLDAPReferralTarget(raw)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		followedDN := dn
		if target.hasDN {
			followedDN = target.dn
		}
		key := options.referralKey(target.endpoint, "compare", followedDN)
		if _, duplicate := seen[key]; duplicate {
			lastErr = ldap.NewError(
				ldap.LDAPResultClientLoop,
				fmt.Errorf("LDAP referral loop at %s", target.raw),
			)
			continue
		}
		referralConnection, connectErr := options.connectLDAPReferral(target)
		if connectErr != nil {
			lastErr = connectErr
			continue
		}
		branchSeen := cloneLDAPReferralSet(seen)
		branchSeen[key] = struct{}{}
		matched, compareErr := options.compareWithReferralsAt(
			referralConnection,
			followedDN,
			attribute,
			value,
			depth+1,
			branchSeen,
		)
		_ = referralConnection.Close()
		return matched, compareErr
	}
	if lastErr == nil {
		lastErr = err
	}
	return false, fmt.Errorf("chase LDAP referral: %w", lastErr)
}

func ldapReferralURLs(err error) []string {
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultReferral ||
		ldapError.Packet == nil || len(ldapError.Packet.Children) < 2 {
		return nil
	}
	operation := ldapError.Packet.Children[1]
	if operation == nil {
		return nil
	}
	var referrals []string
	for _, child := range operation.Children {
		if child == nil || child.ClassType != ber.ClassContext ||
			child.TagType != ber.TypeConstructed || child.Tag != 3 {
			continue
		}
		for _, value := range child.Children {
			if value == nil || value.Data == nil {
				continue
			}
			referral := value.Data.String()
			if referral == "" {
				if text, ok := value.Value.(string); ok {
					referral = text
				}
			}
			if referral != "" {
				referrals = append(referrals, referral)
			}
		}
	}
	return referrals
}

func (options *ldapClientOptions) referralKey(endpoint, operation, dn string) string {
	parsed, err := url.Parse(endpoint)
	if err == nil && parsed.Host != "" {
		endpoint = (&url.URL{
			Scheme: strings.ToLower(parsed.Scheme),
			Host:   strings.ToLower(parsed.Host),
		}).String()
	}
	if parsedDN, err := ldap.ParseDN(dn); err == nil {
		dn = strings.ToLower(parsedDN.String())
	} else {
		dn = strings.ToLower(dn)
	}
	return endpoint + "|" + operation + "|" + dn
}

func cloneLDAPReferralSet(source map[string]struct{}) map[string]struct{} {
	cloned := make(map[string]struct{}, len(source)+1)
	for key := range source {
		cloned[key] = struct{}{}
	}
	return cloned
}
