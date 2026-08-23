package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
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
	case ldap.LDAPResultParamError:
		return ldapError.ResultCode, "Bad parameter to an ldap routine", true
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
	attributes       []string
	hasAttributes    bool
	scope            int
	hasScope         bool
	filter           string
	hasFilter        bool
	startTLS         bool
	startTLSRequired bool
}

func parseLDAPReferralTarget(raw string) (ldapReferralTarget, error) {
	target, err := parseLDAPReferralTargetURL(raw)
	if err == nil {
		return target, nil
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		return ldapReferralTarget{}, err
	}
	return ldapReferralTarget{}, ldap.NewError(ldap.LDAPResultParamError, err)
}

func parseLDAPReferralTargetURL(raw string) (ldapReferralTarget, error) {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd <= 0 {
		return ldapReferralTarget{}, fmt.Errorf("referral URL %q is invalid", raw)
	}
	scheme := strings.ToLower(raw[:schemeEnd])
	if scheme != "ldap" && scheme != "ldaps" {
		return ldapReferralTarget{}, fmt.Errorf(
			"referral URL %q must use ldap:// or ldaps://",
			raw,
		)
	}
	remainder := raw[schemeEnd+3:]
	if strings.ContainsRune(remainder, '#') {
		return ldapReferralTarget{}, fmt.Errorf("referral URL %q is invalid", raw)
	}
	authorityEnd := strings.IndexAny(remainder, "/?")
	if authorityEnd < 0 {
		authorityEnd = len(remainder)
	}
	if authorityEnd < len(remainder) && remainder[authorityEnd] != '/' {
		return ldapReferralTarget{}, fmt.Errorf("referral URL %q is invalid", raw)
	}
	endpoint, err := parseLDAPReferralEndpoint(raw, scheme, remainder[:authorityEnd])
	if err != nil {
		return ldapReferralTarget{}, err
	}

	target := ldapReferralTarget{
		raw:      raw,
		endpoint: endpoint,
	}
	if authorityEnd == len(remainder) {
		return target, nil
	}

	components := strings.Split(remainder[authorityEnd+1:], "?")
	if len(components) > 5 {
		return ldapReferralTarget{}, fmt.Errorf("referral URL %q has too many fields", raw)
	}
	if components[0] != "" {
		target.dn, err = url.PathUnescape(components[0])
		if err != nil {
			return ldapReferralTarget{}, fmt.Errorf("decode referral DN in %q: %w", raw, err)
		}
		target.hasDN = target.dn != ""
	}
	if len(components) > 1 && components[1] != "" {
		decoded, decodeErr := url.PathUnescape(components[1])
		if decodeErr != nil {
			return ldapReferralTarget{}, fmt.Errorf(
				"decode referral attributes in %q: %w",
				raw,
				decodeErr,
			)
		}
		target.attributes = splitLDAPReferralList(decoded)
		target.hasAttributes = true
	}
	if len(components) > 2 && components[2] != "" {
		scopeName, err := url.PathUnescape(components[2])
		if err != nil {
			return ldapReferralTarget{}, fmt.Errorf("decode referral scope in %q: %w", raw, err)
		}
		switch strings.ToLower(scopeName) {
		case "base":
			target.scope = ldap.ScopeBaseObject
		case "one", "onelevel":
			target.scope = ldap.ScopeSingleLevel
		case "sub", "subtree":
			target.scope = ldap.ScopeWholeSubtree
		case "subord", "subordinate", "children":
			target.scope = ldap.ScopeChildren
		default:
			return ldapReferralTarget{}, fmt.Errorf(
				"referral URL %q has invalid search scope %q",
				raw,
				scopeName,
			)
		}
		target.hasScope = true
	}
	if len(components) > 3 && components[3] != "" {
		target.filter, err = url.PathUnescape(components[3])
		if err != nil {
			return ldapReferralTarget{}, fmt.Errorf("decode referral filter in %q: %w", raw, err)
		}
		target.hasFilter = true
	}
	if len(components) == 5 {
		rawExtensions := splitLDAPReferralList(components[4])
		if len(rawExtensions) == 0 {
			return ldapReferralTarget{}, fmt.Errorf("referral URL %q has empty extensions", raw)
		}
		criticalExtensions := 0
		for _, rawExtension := range rawExtensions {
			extension, err := url.PathUnescape(rawExtension)
			if err != nil {
				return ldapReferralTarget{}, fmt.Errorf(
					"decode referral extension in %q: %w",
					raw,
					err,
				)
			}
			critical := strings.HasPrefix(extension, "!")
			if critical {
				criticalExtensions++
				extension = strings.TrimPrefix(extension, "!")
			}
			if strings.EqualFold(extension, "StartTLS") ||
				strings.EqualFold(extension, "X-StartTLS") ||
				extension == ldapStartTLSOID {
				target.startTLS = true
				target.startTLSRequired = target.startTLSRequired || critical
				continue
			}
			if critical {
				return ldapReferralTarget{}, ldap.NewError(
					ldap.LDAPResultNotSupported,
					fmt.Errorf(
						"referral URL %q has unsupported critical extension %q",
						raw,
						extension,
					),
				)
			}
		}
		if criticalExtensions > 1 {
			return ldapReferralTarget{}, ldap.NewError(
				ldap.LDAPResultNotSupported,
				fmt.Errorf("referral URL %q has multiple critical extensions", raw),
			)
		}
	}
	return target, nil
}

func parseLDAPReferralEndpoint(rawURL, scheme, authority string) (string, error) {
	if strings.ContainsRune(authority, '@') {
		return "", fmt.Errorf("referral URL %q must not contain userinfo", rawURL)
	}

	hostPart := authority
	portPart := ""
	hasPort := false
	ipv6 := false
	if strings.HasPrefix(hostPart, "[") {
		closing := strings.IndexByte(hostPart, ']')
		if closing < 0 {
			return "", fmt.Errorf("referral URL %q has an invalid IPv6 host", rawURL)
		}
		ipv6 = true
		remainder := hostPart[closing+1:]
		hostPart = hostPart[1:closing]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") || strings.Contains(remainder[1:], ":") {
				return "", fmt.Errorf("referral URL %q has an invalid host or port", rawURL)
			}
			hasPort = true
			portPart = remainder[1:]
		}
	} else {
		if strings.ContainsRune(hostPart, ']') {
			return "", fmt.Errorf("referral URL %q has an invalid host", rawURL)
		}
		if colon := strings.IndexByte(hostPart, ':'); colon >= 0 {
			hasPort = true
			portPart = hostPart[colon+1:]
			hostPart = hostPart[:colon]
			if strings.ContainsRune(portPart, ':') {
				return "", fmt.Errorf("referral URL %q has an invalid port", rawURL)
			}
		}
	}

	host, err := url.PathUnescape(hostPart)
	if err != nil {
		return "", fmt.Errorf("decode referral host in %q: %w", rawURL, err)
	}
	if host == "" {
		host = "localhost"
	}
	if strings.ContainsAny(host, "\x00\r\n/?#@") || (!ipv6 && strings.ContainsRune(host, ':')) {
		return "", fmt.Errorf("referral URL %q has an invalid host", rawURL)
	}

	port := ""
	if hasPort {
		port, err = url.PathUnescape(portPart)
		if err != nil {
			return "", fmt.Errorf("decode referral port in %q: %w", rawURL, err)
		}
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 0 || value > 65535 || port == "" {
			return "", fmt.Errorf("referral URL %q has an invalid port", rawURL)
		}
		if value == 0 {
			port = ""
		}
	}

	endpointHost := host
	if ipv6 {
		endpointHost = "[" + host + "]"
	}
	if port != "" {
		endpointHost = net.JoinHostPort(host, port)
	}
	return (&url.URL{Scheme: scheme, Host: endpointHost}).String(), nil
}

func splitLDAPReferralList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
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
	if options.observeSearch {
		return options.connectObservedLDAPReferral(target, parsed, tlsConfig)
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

func (options *ldapClientOptions) connectObservedLDAPReferral(
	target ldapReferralTarget,
	parsed *url.URL,
	tlsConfig *tls.Config,
) (*ldap.Conn, error) {
	dial := func(startTLS bool) (*ldap.Conn, *ldapSearchResponseObserver, error) {
		return dialObservedLDAPConnection(
			target.endpoint,
			parsed.Scheme == "ldaps",
			startTLS,
			tlsConfig,
			options.timeout,
		)
	}
	connection, observer, err := dial(target.startTLS)
	if err != nil && target.startTLS && !target.startTLSRequired {
		connection, observer, err = dial(false)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to referral %s: %w", target.endpoint, err)
	}
	closeOnError := func(err error) (*ldap.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.UnauthenticatedBind(""); err != nil {
		return closeOnError(fmt.Errorf("anonymous bind to referral %s: %w", target.endpoint, err))
	}
	options.addReferralSearchObserver(observer)
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
