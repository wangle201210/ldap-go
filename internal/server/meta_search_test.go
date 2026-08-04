package server

import (
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestMetaSearchPlansScopeMatrix(t *testing.T) {
	configuration := &metaBackendRuntimeConfiguration{
		targets: []metaBackendTargetRuntimeConfiguration{
			{
				configDNKey: "broad",
				suffix:      mustMetaBackendDN(t, "dc=meta,dc=test"),
				scope:       directory.ScopeWholeSubtree,
			},
			{
				configDNKey: "specific",
				suffix:      mustMetaBackendDN(t, "ou=team,dc=meta,dc=test"),
				scope:       directory.ScopeWholeSubtree,
			},
		},
	}
	tests := []struct {
		name       string
		base       string
		scope      directory.Scope
		wantKeys   []string
		wantBases  []string
		wantScopes []directory.Scope
	}{
		{
			name:       "subtree broadcasts to descendant target",
			base:       "dc=meta,dc=test",
			scope:      directory.ScopeWholeSubtree,
			wantKeys:   []string{"broad", "specific"},
			wantBases:  []string{"dc=meta,dc=test", "ou=team,dc=meta,dc=test"},
			wantScopes: []directory.Scope{directory.ScopeWholeSubtree, directory.ScopeWholeSubtree},
		},
		{
			name:       "one level includes direct target base",
			base:       "dc=meta,dc=test",
			scope:      directory.ScopeSingleLevel,
			wantKeys:   []string{"broad", "specific"},
			wantBases:  []string{"dc=meta,dc=test", "ou=team,dc=meta,dc=test"},
			wantScopes: []directory.Scope{directory.ScopeSingleLevel, directory.ScopeBase},
		},
		{
			name:       "base does not include descendant target",
			base:       "dc=meta,dc=test",
			scope:      directory.ScopeBase,
			wantKeys:   []string{"broad"},
			wantBases:  []string{"dc=meta,dc=test"},
			wantScopes: []directory.Scope{directory.ScopeBase},
		},
		{
			name:       "specific base remains multi target",
			base:       "ou=team,dc=meta,dc=test",
			scope:      directory.ScopeBase,
			wantKeys:   []string{"broad", "specific"},
			wantBases:  []string{"ou=team,dc=meta,dc=test", "ou=team,dc=meta,dc=test"},
			wantScopes: []directory.Scope{directory.ScopeBase, directory.ScopeBase},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plans, err := configuration.searchPlans(ldapwire.SearchRequest{
				BaseDN: test.base,
				Scope:  test.scope,
			})
			if err != nil {
				t.Fatalf("searchPlans(): %v", err)
			}
			if len(plans) != len(test.wantKeys) {
				t.Fatalf("search plan count = %d, want %d", len(plans), len(test.wantKeys))
			}
			for index := range plans {
				if plans[index].target.configDNKey != test.wantKeys[index] ||
					plans[index].request.BaseDN != test.wantBases[index] ||
					plans[index].request.Scope != test.wantScopes[index] {
					t.Fatalf("search plan %d = %#v", index, plans[index])
				}
			}
		})
	}
}

func TestFinalizeMetaSearchResult(t *testing.T) {
	failure := ldapwire.ResultError(ldapwire.ResultUnavailable, "target unavailable")
	tests := []struct {
		name       string
		result     ldapwire.Result
		valid      bool
		onError    string
		failure    *ldapwire.Result
		wantCode   ldapwire.ResultCode
		wantDetail string
	}{
		{
			name:     "valid result demotes no such object",
			result:   ldapwire.Result{Code: ldapwire.ResultNoSuchObject},
			valid:    true,
			onError:  "continue",
			wantCode: ldapwire.ResultSuccess,
		},
		{
			name:       "report restores target failure",
			result:     ldapwire.Result{Code: ldapwire.ResultSuccess},
			valid:      true,
			onError:    "report",
			failure:    &failure,
			wantCode:   ldapwire.ResultUnavailable,
			wantDetail: "target unavailable",
		},
		{
			name:     "continue ignores saved failure after success",
			result:   ldapwire.ResultError(ldapwire.ResultUnavailable, "late failure"),
			valid:    true,
			onError:  "continue",
			failure:  &failure,
			wantCode: ldapwire.ResultSuccess,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.result
			finalizeMetaSearchResult(&result, test.valid, test.onError, test.failure, false)
			if result.Code != test.wantCode || result.DiagnosticMessage != test.wantDetail {
				t.Fatalf("result = %#v, want code=%d detail=%q", result, test.wantCode, test.wantDetail)
			}
		})
	}

	result := ldapwire.Result{Code: ldapwire.ResultSizeLimitExceeded}
	finalizeMetaSearchResult(&result, true, "continue", &failure, true)
	if result.Code != ldapwire.ResultSizeLimitExceeded {
		t.Fatalf("terminal size limit result = %#v", result)
	}
}
