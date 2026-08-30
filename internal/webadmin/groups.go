package webadmin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	groupObjectFilter      = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
	maximumGroupValueBytes = 4096
)

var groupSearchAttributes = []string{"objectClass", "member", "uniqueMember", "memberUid"}

type groupResponse struct {
	DN           string   `json:"dn"`
	Type         string   `json:"type"`
	Types        []string `json:"types,omitempty"`
	Member       []string `json:"member"`
	UniqueMember []string `json:"uniqueMember"`
	MemberUID    []string `json:"memberUid"`
}

type groupsResponse struct {
	Groups []groupResponse      `json:"groups"`
	Nested *nestedGroupResponse `json:"nested,omitempty"`
}

type nestedGroupResponse struct {
	RootDN       string   `json:"root_dn"`
	Groups       []string `json:"groups"`
	Member       []string `json:"member"`
	UniqueMember []string `json:"uniqueMember"`
	MemberUID    []string `json:"memberUid"`
	Cycles       []string `json:"cycles,omitempty"`
}

type groupPatchRequest struct {
	DN      string             `json:"dn"`
	Changes []groupPatchChange `json:"changes"`
}

type groupPatchChange struct {
	Operation string   `json:"operation"`
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
}

type groupPatchResult struct {
	Operation string   `json:"operation"`
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
	Status    string   `json:"status"`
}

type groupPatchResponse struct {
	DN      string             `json:"dn"`
	Atomic  bool               `json:"atomic"`
	Results []groupPatchResult `json:"results"`
}

type nestedGroupLimitError struct {
	message string
}

func (failure *nestedGroupLimitError) Error() string {
	return failure.message
}

// handleGroups lists supported LDAP group entries and applies atomic membership
// changes through the current bound session.
func (application *Application) handleGroups(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet, http.MethodPatch) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)

	switch request.Method {
	case http.MethodGet:
		application.getGroups(response, request, current)
	case http.MethodPatch:
		application.patchGroup(response, request, current)
	}
}

func (application *Application) getGroups(
	response http.ResponseWriter,
	request *http.Request,
	current *session,
) {
	query, err := parseGroupQuery(request.URL.RawQuery)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_groups_query", Message: err.Error()})
		return
	}
	baseDN, err := parseBoundedGroupDN(query.baseDN, "base_dn")
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_base_dn", Message: err.Error()})
		return
	}
	var selectedDN *ldap.DN
	if query.dn != "" {
		selectedDN, err = parseBoundedGroupDN(query.dn, "dn")
		if err != nil {
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
			return
		}
		if !baseDN.EqualFold(selectedDN) && !baseDN.AncestorOfFold(selectedDN) {
			writeAPIError(response, http.StatusBadRequest, apiError{
				Code: "dn_outside_base", Message: "dn must be equal to or below base_dn",
			})
			return
		}
	}

	ldapRequest := ldap.NewSearchRequest(
		query.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		application.config.MaxSearchSize, application.config.MaxSearchSeconds,
		false, groupObjectFilter, groupSearchAttributes, nil,
	)
	ldapRequest.EnforceSizeLimit = true
	result, release, err := application.search(current.client, ldapRequest)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
	if result == nil {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: "LDAP group search returned no result",
		})
		return
	}
	if rejectIncompleteReferrals(response, result) {
		return
	}
	if len(result.Entries) > application.config.MaxSearchSize {
		writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
			Code: "group_limit_exceeded", Message: "LDAP group result exceeds the configured search limit",
		})
		return
	}

	groups, index, err := convertGroups(result.Entries)
	if err != nil {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: err.Error(),
		})
		return
	}
	output := groupsResponse{Groups: groups}
	if selectedDN != nil {
		key := groupDNKey(selectedDN)
		selected, exists := index[key]
		if !exists {
			writeAPIError(response, http.StatusNotFound, apiError{
				Code: "group_not_found", Message: "group was not found below base_dn",
			})
			return
		}
		output.Groups = []groupResponse{groups[selected]}
		if query.nested {
			nested, err := expandNestedGroup(groups, index, selected, application.config.MaxSearchSize)
			if err != nil {
				var limitError *nestedGroupLimitError
				if errors.As(err, &limitError) {
					writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
						Code: "nested_group_limit_exceeded", Message: err.Error(),
					})
				} else {
					writeAPIError(response, http.StatusBadGateway, apiError{
						Code: "invalid_ldap_response", Message: err.Error(),
					})
				}
				return
			}
			output.Nested = &nested
		}
	}
	writeJSON(response, http.StatusOK, output)
}

func (application *Application) patchGroup(
	response http.ResponseWriter,
	request *http.Request,
	current *session,
) {
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	if request.URL.RawQuery != "" {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_groups_query", Message: "PATCH does not accept query parameters",
		})
		return
	}
	var input groupPatchRequest
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	if _, err := parseBoundedGroupDN(input.DN, "dn"); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	changes, err := validateGroupChanges(input.Changes, application.config.MaxAttributes)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_group_changes", Message: err.Error()})
		return
	}

	lookup := ldap.NewSearchRequest(
		input.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		application.config.MaxSearchSeconds, false, groupObjectFilter,
		[]string{"objectClass"}, nil,
	)
	lookup.EnforceSizeLimit = true
	result, release, err := application.search(current.client, lookup)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	if result == nil || len(result.Entries) > 1 ||
		(len(result.Entries) == 1 && result.Entries[0] == nil) {
		release()
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: "LDAP group lookup returned an invalid result",
		})
		return
	}
	if rejectIncompleteReferrals(response, result) {
		release()
		return
	}
	if len(result.Entries) == 0 {
		release()
		writeAPIError(response, http.StatusNotFound, apiError{
			Code: "group_not_found", Message: "group was not found",
		})
		return
	}
	if _, err := groupTypes(result.Entries[0]); err != nil {
		release()
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: err.Error(),
		})
		return
	}
	release()

	modify := ldap.NewModifyRequest(input.DN, nil)
	results := make([]groupPatchResult, 0, len(changes))
	for _, change := range changes {
		switch change.Operation {
		case "add":
			modify.Add(change.Attribute, change.Values)
		case "remove":
			modify.Delete(change.Attribute, change.Values)
		}
		results = append(results, groupPatchResult{
			Operation: change.Operation, Attribute: change.Attribute,
			Values: append([]string(nil), change.Values...), Status: "applied",
		})
	}
	if err := current.client.Modify(modify); err != nil {
		writeLDAPError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, groupPatchResponse{
		DN: input.DN, Atomic: true, Results: results,
	})
}

type groupQuery struct {
	baseDN string
	dn     string
	nested bool
}

func parseGroupQuery(raw string) (groupQuery, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return groupQuery{}, errors.New("invalid query encoding")
	}
	for name, entries := range values {
		switch name {
		case "base_dn", "dn", "nested":
		default:
			return groupQuery{}, fmt.Errorf("unknown query parameter %q", name)
		}
		if len(entries) != 1 {
			return groupQuery{}, fmt.Errorf("query parameter %q must occur exactly once", name)
		}
	}
	query := groupQuery{baseDN: values.Get("base_dn"), dn: values.Get("dn")}
	if query.baseDN == "" {
		return groupQuery{}, errors.New("base_dn is required")
	}
	switch values.Get("nested") {
	case "", "false":
	case "true":
		query.nested = true
	default:
		return groupQuery{}, errors.New("nested must be true or false")
	}
	if query.nested && query.dn == "" {
		return groupQuery{}, errors.New("dn is required when nested is true")
	}
	return query, nil
}

func parseBoundedGroupDN(value, name string) (*ldap.DN, error) {
	if len(value) > maximumGroupValueBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, maximumGroupValueBytes)
	}
	if err := validateDN(value, false); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	parsed, _ := ldap.ParseDN(value)
	return parsed, nil
}

func convertGroups(entries []*ldap.Entry) ([]groupResponse, map[string]int, error) {
	groups := make([]groupResponse, 0, len(entries))
	index := make(map[string]int, len(entries))
	for _, entry := range entries {
		if entry == nil {
			return nil, nil, errors.New("LDAP group search returned a nil entry")
		}
		parsed, err := parseBoundedGroupDN(entry.DN, "group DN")
		if err != nil {
			return nil, nil, err
		}
		types, err := groupTypes(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("group %q: %w", entry.DN, err)
		}
		key := groupDNKey(parsed)
		if _, duplicate := index[key]; duplicate {
			return nil, nil, fmt.Errorf("LDAP group search returned duplicate DN %q", entry.DN)
		}
		group := groupResponse{
			DN: entry.DN, Type: types[0],
			Member:       cloneAttributeValues(entry, "member"),
			UniqueMember: cloneAttributeValues(entry, "uniqueMember"),
			MemberUID:    cloneAttributeValues(entry, "memberUid"),
		}
		if len(types) > 1 {
			group.Types = types
		}
		index[key] = len(groups)
		groups = append(groups, group)
	}
	return groups, index, nil
}

func groupTypes(entry *ldap.Entry) ([]string, error) {
	classes := entry.GetEqualFoldAttributeValues("objectClass")
	types := make([]string, 0, 3)
	for _, candidate := range []string{"groupOfNames", "groupOfUniqueNames", "posixGroup"} {
		for _, class := range classes {
			if strings.EqualFold(class, candidate) {
				types = append(types, candidate)
				break
			}
		}
	}
	if len(types) == 0 {
		return nil, errors.New("entry does not have a supported group objectClass")
	}
	return types, nil
}

func cloneAttributeValues(entry *ldap.Entry, name string) []string {
	values := entry.GetEqualFoldAttributeValues(name)
	return append(make([]string, 0, len(values)), values...)
}

func groupDNKey(value *ldap.DN) string {
	return strings.ToLower(value.String())
}

func expandNestedGroup(
	groups []groupResponse,
	index map[string]int,
	root int,
	maximum int,
) (nestedGroupResponse, error) {
	if maximum < 1 {
		return nestedGroupResponse{}, &nestedGroupLimitError{message: "nested group limit is invalid"}
	}
	output := nestedGroupResponse{
		RootDN: groups[root].DN,
		Groups: make([]string, 0), Member: make([]string, 0),
		UniqueMember: make([]string, 0), MemberUID: make([]string, 0),
	}
	state := make([]uint8, len(groups))
	seenDN := make(map[string]struct{})
	seenUID := make(map[string]struct{})
	seenCycle := make(map[string]struct{})
	memberCount := 0

	var visit func(int) error
	visit = func(groupIndex int) error {
		if state[groupIndex] == 2 {
			return nil
		}
		if len(output.Groups) >= maximum {
			return &nestedGroupLimitError{message: fmt.Sprintf("nested group traversal exceeds %d groups", maximum)}
		}
		state[groupIndex] = 1
		group := groups[groupIndex]
		output.Groups = append(output.Groups, group.DN)

		visitDN := func(raw string, unique bool) error {
			parsed, identity, err := parseGroupMember(raw, unique)
			if err != nil {
				return fmt.Errorf("group %q contains invalid membership value %q: %w", group.DN, raw, err)
			}
			key := groupDNKey(parsed)
			if child, exists := index[key]; exists {
				if state[child] == 1 {
					if _, duplicate := seenCycle[key]; !duplicate {
						seenCycle[key] = struct{}{}
						output.Cycles = append(output.Cycles, raw)
					}
					return nil
				}
				return visit(child)
			}
			leafKey := key
			if unique {
				leafKey += "\x00" + identity
			}
			if _, duplicate := seenDN[leafKey]; duplicate {
				return nil
			}
			if memberCount >= maximumGroupMembershipLimit(maximum) {
				return &nestedGroupLimitError{message: fmt.Sprintf(
					"nested membership exceeds %d values", maximumGroupMembershipLimit(maximum),
				)}
			}
			seenDN[leafKey] = struct{}{}
			memberCount++
			if unique {
				output.UniqueMember = append(output.UniqueMember, raw)
			} else {
				output.Member = append(output.Member, raw)
			}
			return nil
		}
		for _, value := range group.Member {
			if err := visitDN(value, false); err != nil {
				return err
			}
		}
		for _, value := range group.UniqueMember {
			if err := visitDN(value, true); err != nil {
				return err
			}
		}
		for _, value := range group.MemberUID {
			if err := validateMemberUID(value); err != nil {
				return fmt.Errorf("group %q contains invalid memberUid %q: %w", group.DN, value, err)
			}
			key := value
			if _, duplicate := seenUID[key]; duplicate {
				continue
			}
			if memberCount >= maximumGroupMembershipLimit(maximum) {
				return &nestedGroupLimitError{message: fmt.Sprintf(
					"nested membership exceeds %d values", maximumGroupMembershipLimit(maximum),
				)}
			}
			seenUID[key] = struct{}{}
			memberCount++
			output.MemberUID = append(output.MemberUID, value)
		}
		state[groupIndex] = 2
		return nil
	}
	if err := visit(root); err != nil {
		return nestedGroupResponse{}, err
	}
	return output, nil
}

func maximumGroupMembershipLimit(searchLimit int) int {
	if searchLimit < maximumValuesPerAttribute {
		return searchLimit
	}
	return maximumValuesPerAttribute
}

func parseGroupMemberDN(value string, unique bool) (*ldap.DN, error) {
	parsed, _, err := parseGroupMember(value, unique)
	return parsed, err
}

func parseGroupMember(value string, unique bool) (*ldap.DN, string, error) {
	if unique && len(value) <= maximumGroupValueBytes && strings.HasSuffix(value, "'B") {
		separator := strings.LastIndex(value, "#'")
		if separator > 0 {
			for _, bit := range value[separator+2 : len(value)-2] {
				if bit != '0' && bit != '1' {
					return nil, "", errors.New("invalid uniqueMember bit string")
				}
			}
			parsed, err := parseBoundedGroupDN(value[:separator], "uniqueMember DN")
			if err != nil {
				return nil, "", err
			}
			return parsed, value[separator:], nil
		}
	}
	parsed, err := parseBoundedGroupDN(value, "member DN")
	return parsed, "", err
}

func validateGroupChanges(input []groupPatchChange, maximum int) ([]groupPatchChange, error) {
	if len(input) == 0 || len(input) > maximum {
		return nil, fmt.Errorf("changes must contain between 1 and %d items", maximum)
	}
	totalValues := 0
	seen := make(map[string]struct{})
	validated := make([]groupPatchChange, 0, len(input))
	for _, original := range input {
		change := groupPatchChange{
			Operation: strings.ToLower(original.Operation),
			Attribute: canonicalGroupAttribute(original.Attribute),
			Values:    append([]string(nil), original.Values...),
		}
		if change.Operation != "add" && change.Operation != "remove" {
			return nil, errors.New("operation must be add or remove")
		}
		if change.Attribute == "" {
			return nil, errors.New("attribute must be member, uniqueMember, or memberUid")
		}
		if len(change.Values) == 0 {
			return nil, errors.New("each group change requires at least one value")
		}
		totalValues += len(change.Values)
		if totalValues > maximumValuesPerAttribute {
			return nil, fmt.Errorf("group changes exceed %d total values", maximumValuesPerAttribute)
		}
		for _, value := range change.Values {
			var key string
			switch change.Attribute {
			case "member":
				parsed, err := parseGroupMemberDN(value, false)
				if err != nil {
					return nil, err
				}
				key = groupDNKey(parsed)
			case "uniqueMember":
				parsed, uid, err := parseGroupMember(value, true)
				if err != nil {
					return nil, err
				}
				key = groupDNKey(parsed) + "\x00" + uid
			case "memberUid":
				if err := validateMemberUID(value); err != nil {
					return nil, err
				}
				key = value
			}
			identity := change.Operation + "\x00" + change.Attribute + "\x00" + key
			if _, duplicate := seen[identity]; duplicate {
				return nil, fmt.Errorf("duplicate %s %s value %q", change.Operation, change.Attribute, value)
			}
			seen[identity] = struct{}{}
		}
		validated = append(validated, change)
	}
	return validated, nil
}

func canonicalGroupAttribute(value string) string {
	switch {
	case strings.EqualFold(value, "member"):
		return "member"
	case strings.EqualFold(value, "uniqueMember"):
		return "uniqueMember"
	case strings.EqualFold(value, "memberUid"):
		return "memberUid"
	default:
		return ""
	}
}

func validateMemberUID(value string) error {
	if value == "" || strings.TrimSpace(value) == "" {
		return errors.New("memberUid must not be empty")
	}
	if len(value) > maximumGroupValueBytes {
		return fmt.Errorf("memberUid exceeds %d bytes", maximumGroupValueBytes)
	}
	if !utf8.ValidString(value) {
		return errors.New("memberUid must be valid UTF-8")
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return errors.New("memberUid must not contain control characters")
		}
	}
	return nil
}
