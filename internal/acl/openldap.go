package acl

import (
	"context"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func LoadOpenLDAPConfig(ctx context.Context, store storage.Store) (*Policy, LoadResult, error) {
	type ruleSet struct {
		suffixes      []string
		global        bool
		rules         []Rule
		addContentACL bool
	}
	var sets []ruleSet
	if err := store.View(ctx, func(tx storage.Reader) error {
		return tx.ForEach(func(entry directory.Entry) error {
			entryDN, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("parse configuration entry DN %q: %w", entry.DN, err)
			}
			if !configSuffix.Equal(entryDN) && !configSuffix.AncestorOf(entryDN) {
				return nil
			}
			values := entry.Values("olcAccess")
			set := ruleSet{}
			for _, value := range values {
				rule, err := ParseRule(string(value))
				if err != nil {
					return fmt.Errorf("%s olcAccess: %w", entry.DN, err)
				}
				set.rules = append(set.rules, rule)
			}
			SortRules(set.rules)
			for _, suffix := range entry.Values("olcSuffix") {
				set.suffixes = append(set.suffixes, string(suffix))
			}
			addContentValues := entry.Values("olcAddContentAcl")
			if len(addContentValues) > 1 {
				return fmt.Errorf("%s olcAddContentAcl has multiple values", entry.DN)
			}
			if len(addContentValues) == 1 {
				switch {
				case strings.EqualFold(string(addContentValues[0]), "TRUE"):
					set.addContentACL = true
				case strings.EqualFold(string(addContentValues[0]), "FALSE"):
				default:
					return fmt.Errorf(
						"%s olcAddContentAcl has invalid value %q",
						entry.DN,
						addContentValues[0],
					)
				}
			}
			database := strings.ToLower(firstString(entry.Values("olcDatabase")))
			if len(values) == 0 && len(set.suffixes) == 0 && database == "" {
				return nil
			}
			if len(set.suffixes) == 0 {
				switch {
				case strings.Contains(database, "config"):
					set.suffixes = []string{"cn=config"}
				case strings.Contains(database, "monitor"):
					set.suffixes = []string{"cn=Monitor"}
				default:
					set.global = true
				}
			}
			sets = append(sets, set)
			return nil
		})
	}); err != nil {
		return nil, LoadResult{}, fmt.Errorf("load OpenLDAP ACL configuration: %w", err)
	}

	var global []Rule
	databases := make(map[string][]Rule)
	addContentACL := make(map[string]bool)
	result := LoadResult{}
	for _, set := range sets {
		if len(set.rules) > 0 {
			result.RuleSets++
		}
		result.Rules += len(set.rules)
		if set.global {
			global = append(global, set.rules...)
			continue
		}
		for _, suffix := range set.suffixes {
			databases[suffix] = append(databases[suffix], set.rules...)
			addContentACL[suffix] = set.addContentACL
		}
	}
	policy, err := newPolicy(global, databases, addContentACL)
	if err != nil {
		return nil, LoadResult{}, fmt.Errorf("build OpenLDAP ACL policy: %w", err)
	}
	return policy, result, nil
}

func firstString(values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}
