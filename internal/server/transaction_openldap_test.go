package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const openLDAPTransactionReferenceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferenceTransactionSourceSemantics(t *testing.T) {
	_ = requireOpenLDAPReferenceTools(t)
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("transaction source reference requires a verified OpenLDAP build")
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPTransactionReferenceCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPTransactionReferenceCommit)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}

	checks := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: filepath.Join("servers", "slapd", "txn.c"),
			hash: "7445950b28ad4c3d54d43229ead28a885bd64861d9c88b29d49fdbe2cd0ad18b",
			anchors: []string{
				"if ( rs->sr_ctrls ) {",
				"tr->tr_ctrls = ldap_controls_dup( rs->sr_ctrls );",
				"txn_put_ctrls( op, ber, cb.sc_private );",
				"rs->sr_err = LDAP_TXN_SPECIFY_OKAY;",
			},
		},
		{
			path: filepath.Join("servers", "slapd", "passwd.c"),
			hash: "56bfb00af72d7802526b9253bef43aa633b2e01f0e6606b48fc88f343769cd4a",
			anchors: []string{
				"slap_passwd_generate( &qpw->rs_new );",
				"rsp = slap_passwd_return( &qpw->rs_new );",
				"if ( op->o_txnSpec ) {",
				"rc = txn_preop( op, rs );",
			},
		},
		{
			path: filepath.Join("servers", "slapd", "controls.c"),
			hash: "dac19d7202fd319e7d79487a0d3263e5f773750f1459457ae88f5179bb9e61d6",
			anchors: []string{
				"{ LDAP_CONTROL_TXN_SPEC,",
				"SLAP_CTRL_UPDATE|SLAP_CTRL_HIDE,",
				"txn_spec_ctrl, LDAP_SLIST_ENTRY_INITIALIZER(next) }",
			},
		},
		{
			path: filepath.Join("servers", "slapd", "connection.c"),
			hash: "3a4ffeb9a5ba486a08b1a964b50b50e2a2a4af86c90a2179632a63d1c0c782ce",
			anchors: []string{
				"/* remove operations in pending transaction */",
				"c->c_txn = CONN_TXN_INACTIVE;",
				"if(tag == LDAP_REQ_BIND) {",
				"connection_abandon( conn );",
			},
		},
		{
			path: filepath.Join("include", "ldap.h"),
			hash: "18b59070812a4da0bab5ad5972ccccd6fa091d122071464d9cbd96dfc6b88324",
			anchors: []string{
				"#define LDAP_EXOP_TXN_ABORTED_NOTICE\tLDAP_TXN \".4\"",
				"#define LDAP_TXN_SPECIFY_OKAY\t\t0x4120",
			},
		},
	}
	sources := make(map[string]string, len(checks))
	for _, check := range checks {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, check.path))
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", check.path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != check.hash {
			t.Fatalf("pinned OpenLDAP source %s SHA-256 = %s, want %s", check.path, got, check.hash)
		}
		for _, anchor := range check.anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf("pinned OpenLDAP source %s lacks %q", check.path, anchor)
			}
		}
		sources[check.path] = string(contents)
	}

	txnResult := openLDAPSourceSection(
		t,
		sources[filepath.Join("servers", "slapd", "txn.c")],
		"static int txn_result(",
		"static int txn_put_ctrls(",
	)
	if strings.Contains(txnResult, "sr_rspdata") {
		t.Fatal("pinned OpenLDAP txn_result unexpectedly captures operation responseValue")
	}
	for _, path := range []string{
		filepath.Join("servers", "slapd", "txn.c"),
		filepath.Join("servers", "slapd", "passwd.c"),
		filepath.Join("servers", "slapd", "connection.c"),
	} {
		if strings.Contains(sources[path], "LDAP_EXOP_TXN_ABORTED_NOTICE") {
			t.Fatalf("pinned OpenLDAP source %s unexpectedly sends the aborted transaction notice", path)
		}
	}
}

func TestOpenLDAPReferenceTransactionGeneratedPasswordWireBehavior(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServer(t, tools, nil)
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawExtendedRequest(
			passwordModifyOID,
			rawTransactionPasswordModifyRequestValue(
				[]byte("uid=alice,ou=people,dc=example,dc=com"),
				nil,
			),
			true,
		),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPMessageID(t, response, 3)
	assertRawLDAPResult(
		t,
		response,
		int64(ldapwire.ResultUnavailableCriticalExtension),
	)
	if value, present := rawExtendedResponseValue(response); present {
		t.Fatalf("OpenLDAP queued Password Modify responseValue = %x, want absent", value)
	}

	endResponse := endRawLDAPTransaction(t, connection, 4, false, identifier)
	assertRawLDAPMessageID(t, endResponse, 4)
	assertRawLDAPResult(t, endResponse, int64(ldapwire.ResultSuccess))
}

func TestOpenLDAPReferenceBindAbortsTransactionWithoutNotice(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServer(t, tools, nil)
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := transactionTestPerson("openldap-bind-abort")
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(entry),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)

	bindResponse := sendRawLDAPOperation(
		t,
		connection,
		4,
		rawSimpleBindRequest("cn=admin,dc=example,dc=com", "secret"),
	)
	assertRawLDAPMessageID(t, bindResponse, 4)
	assertRawLDAPResult(t, bindResponse, int64(ldapwire.ResultSuccess))
	endResponse := endRawLDAPTransaction(t, connection, 5, true, identifier)
	assertRawLDAPMessageID(t, endResponse, 5)
	assertRawLDAPResult(t, endResponse, int64(ldapwire.ResultTransactionIDInvalid))
}
