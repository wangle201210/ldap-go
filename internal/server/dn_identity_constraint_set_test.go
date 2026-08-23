package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestDNIdentityConstraintSetValuesAndParents(t *testing.T) {
	registry := dnIdentityOverlayScopeRegistry(t)
	runtime := &runtimeState{schema: registry}

	tests := []struct {
		name       string
		targetDN   string
		userDN     string
		expression string
		want       string
	}{
		{
			name:       "OID target intersects canonical caseExact literal",
			targetDN:   "1.3.6.1.4.1.99999.917.1=Alice,dc=example,dc=com",
			expression: "this & [scopeExactName=Alice,dc=example,dc=com]",
			want:       "scopeExactName=Alice,dc=example,dc=com",
		},
		{
			name:       "caseIgnore target intersects normalized literal",
			targetDN:   `scopeFoldName=\20REMOTE\20\20TENANT\20,DC=EXAMPLE,DC=COM`,
			expression: "this & [scopeFoldName=remote tenant,dc=example,dc=com]",
			want:       "scopeFoldName=remote tenant,dc=example,dc=com",
		},
		{
			name:       "caseExact user remains distinct",
			targetDN:   "scopeExactName=target,dc=example,dc=com",
			userDN:     "scopeExactName=alice,dc=example,dc=com",
			expression: "user & [scopeExactName=Alice,dc=example,dc=com]",
		},
		{
			name:       "schema-aware parent remains parseable",
			targetDN:   "uid=Alice,scopeExactName=Tenant,dc=example,dc=com",
			expression: "this/-1 & [scopeExactName=Tenant,dc=example,dc=com]",
			want:       "scopeExactName=Tenant,dc=example,dc=com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node, err := parseConstraintSetExpression(test.expression)
			if err != nil {
				t.Fatalf("parseConstraintSetExpression(): %v", err)
			}
			values, err := (constraintSetEvaluation{
				runtime: runtime,
				target:  directory.Entry{DN: test.targetDN},
				userDN:  test.userDN,
			}).evaluate(node)
			if err != nil {
				t.Fatalf("evaluate(): %v", err)
			}
			if test.want == "" {
				if len(values) != 0 {
					t.Fatalf("values = %#v, want empty", values)
				}
				return
			}
			if _, found := values[test.want]; !found || len(values) != 1 {
				t.Fatalf("values = %#v, want only %q", values, test.want)
			}
		})
	}
}
