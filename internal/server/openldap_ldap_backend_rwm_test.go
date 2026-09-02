package server

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func assertOpenLDAPLDAPBackendRWMSource(t *testing.T) {
	t.Helper()
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	contents, err := exec.Command(
		"git",
		"-C",
		source,
		"show",
		openLDAPLDAPBackendACLCommit+":servers/slapd/overlays/rwm.c",
	).Output()
	if err != nil {
		t.Fatalf("read pinned OpenLDAP rwm.c: %v", err)
	}
	text := string(contents)
	for _, anchor := range []string{
		"rwm_op_bind",
		"rwm_op_search",
		"rwm_op_compare",
		"rwm_op_add",
		"rwm_op_modify",
		"rwm_op_delete",
		"rwm_op_modrdn",
		"rwm_exop_passwd",
		"rwm_response",
	} {
		if !strings.Contains(text, anchor) {
			t.Fatalf("pinned OpenLDAP rwm.c lacks %q", anchor)
		}
	}
}

func startOpenLDAPBackendRWMProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
) (string, func()) {
	t.Helper()
	configuration := fmt.Sprintf(
		`access to * by * read

database ldap
suffix "%s"
rootdn "%s"
rootpw %s
uri %s
network-timeout 1
chase-referrals FALSE
idassert-bind bindmethod=simple binddn="%s" credentials="%s" mode=none
overlay rwm
rwm-suffixmassage "%s" "%s"
rwm-map objectClass groupOfNames groupOfUniqueNames
rwm-map attribute member uniqueMember
rwm-map attribute description businessCategory`,
		ldapBackendRWMLocalSuffix,
		ldapBackendRWMLocalRootDN,
		ldapBackendTestLocalRootPW,
		providerURI,
		ldapBackendTestAdminDN,
		ldapBackendTestAdminSecret,
		ldapBackendRWMLocalSuffix,
		ldapBackendTestSuffix,
	)
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		configuration,
		"",
	)
}
