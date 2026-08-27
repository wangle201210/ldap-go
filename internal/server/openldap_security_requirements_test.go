package server

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPSecurityRequirementsVersion = "2.6.13"

type securityRequirementsResult struct {
	code       uint16
	diagnostic string
}

type securityRequirementsObservation struct {
	anonymousSearch securityRequirementsResult
	anonymousBind   securityRequirementsResult
	bind            securityRequirementsResult
	boundSearch     securityRequirementsResult
	modify          securityRequirementsResult
}

func TestOpenLDAPReferenceGlobalSecurityAndRequirements(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	requireOpenLDAPSecurityRequirementsVersion(t, tools)

	success := securityRequirementsResult{}
	confidentiality := securityRequirementsResult{
		code:       ldap.LDAPResultConfidentialityRequired,
		diagnostic: "confidentiality required",
	}
	anonymousUpdate := securityRequirementsResult{
		code:       ldap.LDAPResultStrongAuthRequired,
		diagnostic: "modifications require authentication",
	}

	tests := []struct {
		name           string
		openLDAPConfig string
		localAttribute string
		localValue     string
		want           securityRequirementsObservation
	}{
		{
			name:           "security ssf",
			openLDAPConfig: "security ssf=1",
			localAttribute: "olcSecurity",
			localValue:     "ssf=1",
			want: securityRequirementsObservation{
				anonymousSearch: confidentiality,
				bind:            confidentiality,
				boundSearch:     confidentiality,
				modify:          confidentiality,
			},
		},
		{
			name:           "security simple_bind",
			openLDAPConfig: "security simple_bind=1",
			localAttribute: "olcSecurity",
			localValue:     "simple_bind=1",
			want: securityRequirementsObservation{
				anonymousSearch: success,
				bind:            confidentiality,
				boundSearch:     success,
				modify:          anonymousUpdate,
			},
		},
		{
			name:           "security update_ssf",
			openLDAPConfig: "security update_ssf=1",
			localAttribute: "olcSecurity",
			localValue:     "update_ssf=1",
			want: securityRequirementsObservation{
				anonymousSearch: success,
				bind:            success,
				boundSearch:     success,
				modify: securityRequirementsResult{
					code:       ldap.LDAPResultConfidentialityRequired,
					diagnostic: "confidentiality required for update",
				},
			},
		},
		{
			name:           "requires bind",
			openLDAPConfig: "require bind",
			localAttribute: "olcRequires",
			localValue:     "bind",
			want: securityRequirementsObservation{
				anonymousSearch: securityRequirementsResult{
					code:       ldap.LDAPResultOperationsError,
					diagnostic: "BIND required",
				},
				bind:        success,
				boundSearch: success,
				modify:      success,
			},
		},
		{
			name:           "requires authc",
			openLDAPConfig: "require authc",
			localAttribute: "olcRequires",
			localValue:     "authc",
			want: securityRequirementsObservation{
				anonymousSearch: securityRequirementsResult{
					code:       ldap.LDAPResultUnwillingToPerform,
					diagnostic: "authentication required",
				},
				bind:        success,
				boundSearch: success,
				modify:      success,
			},
		},
		{
			name:           "requires sasl",
			openLDAPConfig: "require sasl",
			localAttribute: "olcRequires",
			localValue:     "sasl",
			want: securityRequirementsObservation{
				anonymousSearch: securityRequirementsResult{
					code:       ldap.LDAPResultStrongAuthRequired,
					diagnostic: "SASL authentication required",
				},
				bind: success,
				boundSearch: securityRequirementsResult{
					code:       ldap.LDAPResultStrongAuthRequired,
					diagnostic: "SASL authentication required",
				},
				modify: securityRequirementsResult{
					code:       ldap.LDAPResultStrongAuthRequired,
					diagnostic: "SASL authentication required",
				},
			},
		},
		{
			name:           "requires strong",
			openLDAPConfig: "require strong",
			localAttribute: "olcRequires",
			localValue:     "strong",
			want: securityRequirementsObservation{
				anonymousSearch: securityRequirementsResult{
					code:       ldap.LDAPResultStrongAuthRequired,
					diagnostic: "strong(er) authentication required",
				},
				bind:        success,
				boundSearch: success,
				modify:      success,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				test.openLDAPConfig,
				"",
				"",
			)
			defer stopReference()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			putGlobalSecurityRequirementsConfiguration(
				t,
				store,
				test.localAttribute,
				test.localValue,
			)
			localAddress, stopLocal := startServer(t, store, Config{
				RootDN:       "cn=admin,dc=example,dc=com",
				RootPassword: []byte("secret"),
			})
			defer stopLocal()

			reference := observeSecurityRequirements(
				t,
				referenceURI,
			)
			if !reflect.DeepEqual(reference, test.want) {
				t.Fatalf(
					"OpenLDAP %s observation drifted:\n got: %#v\nwant: %#v",
					openLDAPSecurityRequirementsVersion,
					reference,
					test.want,
				)
			}

			local := observeSecurityRequirements(
				t,
				"ldap://"+localAddress,
			)
			if !reflect.DeepEqual(local, reference) {
				t.Fatalf(
					"global security policy differs:\nOpenLDAP: %#v\nldap-go:  %#v",
					reference,
					local,
				)
			}
		})
	}
}

func requireOpenLDAPSecurityRequirementsVersion(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	output, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil {
		t.Fatalf(
			"read OpenLDAP reference version: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}
	want := "OpenLDAP: slapd " + openLDAPSecurityRequirementsVersion + " "
	if !strings.Contains(string(output), want) {
		t.Fatalf(
			"security requirements differential requires OpenLDAP slapd %s, got: %s",
			openLDAPSecurityRequirementsVersion,
			strings.TrimSpace(string(output)),
		)
	}
}

func putGlobalSecurityRequirementsConfiguration(
	t *testing.T,
	store storage.Store,
	attribute,
	value string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: configurationSuffix.String(),
		Attributes: []directory.Attribute{
			{Description: attribute, Values: stringValues(value)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("put global %s configuration: %v", attribute, err)
	}
}

func observeSecurityRequirements(
	t *testing.T,
	uri string,
) securityRequirementsObservation {
	t.Helper()
	anonymousBindClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s) for anonymous Bind: %v", uri, err)
	}
	anonymousBindErr := anonymousBindClient.UnauthenticatedBind("")
	anonymousBindClient.Close()

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()

	search := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	)
	_, anonymousSearchErr := client.Search(search)
	bindErr := client.Bind("cn=admin,dc=example,dc=com", "secret")
	_, boundSearchErr := client.Search(search)
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("description", []string{"security requirements differential"})
	modifyErr := client.Modify(modify)

	return securityRequirementsObservation{
		anonymousSearch: securityRequirementsResultFromError(anonymousSearchErr),
		anonymousBind:   securityRequirementsResultFromError(anonymousBindErr),
		bind:            securityRequirementsResultFromError(bindErr),
		boundSearch:     securityRequirementsResultFromError(boundSearchErr),
		modify:          securityRequirementsResultFromError(modifyErr),
	}
}

func securityRequirementsResultFromError(err error) securityRequirementsResult {
	if err == nil {
		return securityRequirementsResult{}
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		return securityRequirementsResult{
			code:       ldap.ErrorNetwork,
			diagnostic: err.Error(),
		}
	}
	diagnostic := ""
	if ldapError.Err != nil {
		diagnostic = ldapError.Err.Error()
	}
	return securityRequirementsResult{
		code:       ldapError.ResultCode,
		diagnostic: diagnostic,
	}
}
