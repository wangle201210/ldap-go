package webadmin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
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
	Groups      []groupResponse           `json:"groups"`
	Nested      *nestedGroupResponse      `json:"nested,omitempty"`
	Memberships *groupMembershipsResponse `json:"memberships,omitempty"`
}

type nestedGroupResponse struct {
	RootDN       string   `json:"root_dn"`
	Groups       []string `json:"groups"`
	Member       []string `json:"member"`
	UniqueMember []string `json:"uniqueMember"`
	MemberUID    []string `json:"memberUid"`
	Cycles       []string `json:"cycles,omitempty"`
}

type groupMembershipsResponse struct {
	MemberDN  string                    `json:"member_dn"`
	MemberUID string                    `json:"member_uid"`
	Groups    []groupMembershipResponse `json:"groups"`
	Cycles    []string                  `json:"cycles"`
}

type groupMembershipResponse struct {
	DN         string                     `json:"dn"`
	Type       string                     `json:"type"`
	Direct     bool                       `json:"direct"`
	Depth      int                        `json:"depth"`
	ViaDN      string                     `json:"via_dn,omitempty"`
	References []groupMembershipReference `json:"references"`
}

type groupMembershipReference struct {
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
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
	var memberDN *ldap.DN
	if query.memberDN != "" {
		memberDN, err = parseBoundedGroupDN(query.memberDN, "member_dn")
		if err != nil {
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_member_dn", Message: err.Error()})
			return
		}
	}
	if query.memberUID != "" {
		if err := validateMemberUID(query.memberUID); err != nil {
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_member_uid", Message: err.Error()})
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
	} else if memberDN != nil || query.memberUID != "" {
		memberships, matched, err := findGroupMemberships(
			groups, index, memberDN, query.memberDN, query.memberUID,
			query.nested, application.config.MaxSearchSize,
		)
		if err != nil {
			var limitError *nestedGroupLimitError
			if errors.As(err, &limitError) {
				writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
					Code: "group_membership_limit_exceeded", Message: err.Error(),
				})
			} else {
				writeAPIError(response, http.StatusBadGateway, apiError{
					Code: "invalid_ldap_response", Message: err.Error(),
				})
			}
			return
		}
		output.Groups = make([]groupResponse, 0, len(matched))
		for _, groupIndex := range matched {
			output.Groups = append(output.Groups, groups[groupIndex])
		}
		output.Memberships = &memberships
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
	if failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		return client.Modify(modify)
	}); failure != nil {
		writeAPIError(response, status, *failure)
		return
	}
	writeJSON(response, http.StatusOK, groupPatchResponse{
		DN: input.DN, Atomic: true, Results: results,
	})
}

type groupQuery struct {
	baseDN    string
	dn        string
	memberDN  string
	memberUID string
	nested    bool
}

func parseGroupQuery(raw string) (groupQuery, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return groupQuery{}, errors.New("invalid query encoding")
	}
	for name, entries := range values {
		switch name {
		case "base_dn", "dn", "member_dn", "member_uid", "nested":
		default:
			return groupQuery{}, fmt.Errorf("unknown query parameter %q", name)
		}
		if len(entries) != 1 {
			return groupQuery{}, fmt.Errorf("query parameter %q must occur exactly once", name)
		}
	}
	query := groupQuery{
		baseDN: values.Get("base_dn"), dn: values.Get("dn"),
		memberDN: values.Get("member_dn"), memberUID: values.Get("member_uid"),
	}
	if query.baseDN == "" {
		return groupQuery{}, errors.New("base_dn is required")
	}
	for _, name := range []string{"dn", "member_dn", "member_uid"} {
		if entries, present := values[name]; present && entries[0] == "" {
			return groupQuery{}, fmt.Errorf("query parameter %q must not be empty", name)
		}
	}
	if query.dn != "" && (query.memberDN != "" || query.memberUID != "") {
		return groupQuery{}, errors.New("dn is mutually exclusive with member_dn and member_uid")
	}
	nestedValue, nestedPresent := values["nested"]
	if !nestedPresent {
		nestedValue = []string{"false"}
	}
	switch nestedValue[0] {
	case "false":
	case "true":
		query.nested = true
	default:
		return groupQuery{}, errors.New("nested must be true or false")
	}
	if query.nested && query.dn == "" && query.memberDN == "" && query.memberUID == "" {
		return groupQuery{}, errors.New("dn, member_dn, or member_uid is required when nested is true")
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
	return value.String()
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

type groupMembershipPath struct {
	depth      int
	via        int
	references []groupMembershipReference
}

func findGroupMemberships(
	groups []groupResponse,
	index map[string]int,
	memberDN *ldap.DN,
	memberDNValue string,
	memberUID string,
	nested bool,
	maximum int,
) (groupMembershipsResponse, []int, error) {
	output := groupMembershipsResponse{
		MemberDN: memberDNValue, MemberUID: memberUID,
		Groups: make([]groupMembershipResponse, 0), Cycles: make([]string, 0),
	}
	if maximum < 1 {
		return groupMembershipsResponse{}, nil, &nestedGroupLimitError{message: "group membership limit is invalid"}
	}

	keys := make([]string, len(groups))
	for key, groupIndex := range index {
		if groupIndex < 0 || groupIndex >= len(groups) || keys[groupIndex] != "" {
			return groupMembershipsResponse{}, nil, errors.New("LDAP group index is inconsistent")
		}
		keys[groupIndex] = key
	}
	for _, key := range keys {
		if key == "" {
			return groupMembershipsResponse{}, nil, errors.New("LDAP group index is incomplete")
		}
	}

	parents := make([]map[int][]groupMembershipReference, len(groups))
	directReferences := make(map[int][]groupMembershipReference)
	memberDNKey := ""
	if memberDN != nil {
		memberDNKey = groupDNKey(memberDN)
	}
	membershipLimit := maximumGroupMembershipLimit(maximum)
	membershipValues := 0

	addDNReference := func(groupIndex int, attribute, raw string, unique bool) error {
		membershipValues++
		if membershipValues > membershipLimit {
			return &nestedGroupLimitError{message: fmt.Sprintf(
				"group membership graph exceeds %d values", membershipLimit,
			)}
		}
		parsed, _, err := parseGroupMember(raw, unique)
		if err != nil {
			return fmt.Errorf("group %q contains invalid %s value %q: %w", groups[groupIndex].DN, attribute, raw, err)
		}
		key := groupDNKey(parsed)
		reference := groupMembershipReference{Attribute: attribute, Value: raw}
		if memberDN != nil && key == memberDNKey {
			directReferences[groupIndex] = append(directReferences[groupIndex], reference)
		}
		if child, exists := index[key]; exists {
			if parents[child] == nil {
				parents[child] = make(map[int][]groupMembershipReference)
			}
			parents[child][groupIndex] = append(parents[child][groupIndex], reference)
		}
		return nil
	}

	for groupIndex, group := range groups {
		for _, value := range group.Member {
			if err := addDNReference(groupIndex, "member", value, false); err != nil {
				return groupMembershipsResponse{}, nil, err
			}
		}
		for _, value := range group.UniqueMember {
			if err := addDNReference(groupIndex, "uniqueMember", value, true); err != nil {
				return groupMembershipsResponse{}, nil, err
			}
		}
		for _, value := range group.MemberUID {
			membershipValues++
			if membershipValues > membershipLimit {
				return groupMembershipsResponse{}, nil, &nestedGroupLimitError{message: fmt.Sprintf(
					"group membership graph exceeds %d values", membershipLimit,
				)}
			}
			if err := validateMemberUID(value); err != nil {
				return groupMembershipsResponse{}, nil, fmt.Errorf(
					"group %q contains invalid memberUid value %q: %w", group.DN, value, err,
				)
			}
			if memberUID != "" && value == memberUID {
				directReferences[groupIndex] = append(directReferences[groupIndex], groupMembershipReference{
					Attribute: "memberUid", Value: value,
				})
			}
		}
	}

	lessDN := func(left, right int) bool {
		if keys[left] == keys[right] {
			return groups[left].DN < groups[right].DN
		}
		return keys[left] < keys[right]
	}
	direct := make([]int, 0, len(directReferences))
	paths := make(map[int]groupMembershipPath, len(directReferences))
	for groupIndex, references := range directReferences {
		direct = append(direct, groupIndex)
		paths[groupIndex] = groupMembershipPath{
			depth: 0, via: -1, references: sortedGroupMembershipReferences(references),
		}
	}
	sort.Slice(direct, func(left, right int) bool { return lessDN(direct[left], direct[right]) })

	if nested {
		frontier := direct
		for len(frontier) > 0 {
			candidates := make(map[int]int)
			for _, child := range frontier {
				parentIndexes := make([]int, 0, len(parents[child]))
				for parent := range parents[child] {
					parentIndexes = append(parentIndexes, parent)
				}
				sort.Slice(parentIndexes, func(left, right int) bool {
					return lessDN(parentIndexes[left], parentIndexes[right])
				})
				for _, parent := range parentIndexes {
					if _, seen := paths[parent]; seen {
						continue
					}
					if previous, exists := candidates[parent]; !exists || lessDN(child, previous) {
						candidates[parent] = child
					}
				}
			}
			next := make([]int, 0, len(candidates))
			for parent := range candidates {
				next = append(next, parent)
			}
			sort.Slice(next, func(left, right int) bool { return lessDN(next[left], next[right]) })
			for _, parent := range next {
				via := candidates[parent]
				paths[parent] = groupMembershipPath{
					depth: paths[via].depth + 1, via: via,
					references: sortedGroupMembershipReferences(parents[via][parent]),
				}
			}
			frontier = next
		}
		output.Cycles = findReverseGroupCycles(groups, keys, parents, paths, lessDN)
	}

	matched := make([]int, 0, len(paths))
	for groupIndex := range paths {
		matched = append(matched, groupIndex)
	}
	sort.Slice(matched, func(left, right int) bool {
		leftPath, rightPath := paths[matched[left]], paths[matched[right]]
		if leftPath.depth != rightPath.depth {
			return leftPath.depth < rightPath.depth
		}
		return lessDN(matched[left], matched[right])
	})
	for _, groupIndex := range matched {
		path := paths[groupIndex]
		membership := groupMembershipResponse{
			DN: groups[groupIndex].DN, Type: groups[groupIndex].Type,
			Direct: path.depth == 0, Depth: path.depth,
			References: append(make([]groupMembershipReference, 0, len(path.references)), path.references...),
		}
		if path.via >= 0 {
			membership.ViaDN = groups[path.via].DN
		}
		output.Groups = append(output.Groups, membership)
	}
	return output, matched, nil
}

func sortedGroupMembershipReferences(input []groupMembershipReference) []groupMembershipReference {
	output := append(make([]groupMembershipReference, 0, len(input)), input...)
	sort.SliceStable(output, func(left, right int) bool {
		if output[left].Attribute != output[right].Attribute {
			return output[left].Attribute < output[right].Attribute
		}
		return output[left].Value < output[right].Value
	})
	return output
}

func findReverseGroupCycles(
	groups []groupResponse,
	keys []string,
	parents []map[int][]groupMembershipReference,
	paths map[int]groupMembershipPath,
	lessDN func(int, int) bool,
) []string {
	state := make([]uint8, len(groups))
	cycleIndexes := make(map[int]struct{})
	starts := make([]int, 0, len(paths))
	for groupIndex := range paths {
		starts = append(starts, groupIndex)
	}
	sort.Slice(starts, func(left, right int) bool { return lessDN(starts[left], starts[right]) })

	var visit func(int)
	visit = func(child int) {
		state[child] = 1
		parentIndexes := make([]int, 0, len(parents[child]))
		for parent := range parents[child] {
			if _, reachable := paths[parent]; reachable {
				parentIndexes = append(parentIndexes, parent)
			}
		}
		sort.Slice(parentIndexes, func(left, right int) bool {
			return lessDN(parentIndexes[left], parentIndexes[right])
		})
		for _, parent := range parentIndexes {
			switch state[parent] {
			case 0:
				visit(parent)
			case 1:
				cycleIndexes[parent] = struct{}{}
			}
		}
		state[child] = 2
	}
	for _, start := range starts {
		if state[start] == 0 {
			visit(start)
		}
	}
	cycles := make([]int, 0, len(cycleIndexes))
	for groupIndex := range cycleIndexes {
		cycles = append(cycles, groupIndex)
	}
	sort.Slice(cycles, func(left, right int) bool { return lessDN(cycles[left], cycles[right]) })
	output := make([]string, 0, len(cycles))
	for _, groupIndex := range cycles {
		if keys[groupIndex] != "" {
			output = append(output, groups[groupIndex].DN)
		}
	}
	return output
}

func parseGroupMemberDN(value string, unique bool) (*ldap.DN, error) {
	parsed, _, err := parseGroupMember(value, unique)
	return parsed, err
}

func parseGroupMember(value string, unique bool) (*ldap.DN, string, error) {
	if unique && len(value) <= maximumGroupValueBytes {
		separator := strings.LastIndexByte(value, '#')
		if separator >= 0 && validGroupBitString(value[separator+1:]) {
			if separator == 0 {
				return &ldap.DN{}, value[separator:], nil
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

func validGroupBitString(value string) bool {
	if len(value) < 3 || value[0] != '\'' || value[len(value)-2] != '\'' || value[len(value)-1] != 'B' {
		return false
	}
	for _, bit := range value[1 : len(value)-2] {
		if bit != '0' && bit != '1' {
			return false
		}
	}
	return true
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
