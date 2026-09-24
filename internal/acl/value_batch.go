package acl

// CanBatchValues reports whether Allowed is independent of Target.Value and
// cannot call the EntryReader, for otherwise fixed inputs. It does not authorize
// access: callers must still evaluate Allowed and separately establish stable
// policy, subject, entry, schema and DN normalization semantics, along with any
// root checks, context accessors and remapping outside Allowed.
//
// The proof scans all rules on each call because NewPolicy only shallow-copies
// rules. A true result must not be retained across policy mutations.
func (policy *Policy) CanBatchValues() bool {
	if policy == nil || !rulesCanBatchValues(policy.global) {
		return false
	}
	for _, database := range policy.databases {
		if !rulesCanBatchValues(database.Rules) {
			return false
		}
	}
	return true
}

func rulesCanBatchValues(rules []Rule) bool {
	for _, rule := range rules {
		if rule.Target.Value != nil || rule.Target.Filter != nil {
			return false
		}
		for _, clause := range rule.By {
			if clause.Grant.SelfValue || clause.Grant.RealSelfValue {
				return false
			}
			for _, matcher := range clause.Who {
				switch matcher.Kind {
				case WhoAny, WhoAnonymous, WhoUsers, WhoSelf, WhoDN,
					WhoPeerName, WhoSockName, WhoDomain, WhoSockURL, WhoSSF:
					// Without a value selector, expansions can only capture the DN.
				default:
					return false
				}
			}
		}
	}
	return true
}
