package lloadd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	openLDAPReferenceTestsEnv = "LDAP_GO_OPENLDAP_REFERENCE_TESTS"
	openLDAPLloaddCommit      = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
)

func TestOpenLDAPReferenceLloaddSourceContract(t *testing.T) {
	sourceRoot := requirePinnedOpenLDAPLloaddSource(t)

	sources := map[string]string{}
	checks := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: "client.c",
			hash: "ae2f24969883bba77195b8bd5fff2f4f5ee066a8111b05d54e8ebdc4b1283563",
			anchors: []string{
				"operation_init failed",
				"if ( lload_client_max_pending &&",
				"c->c_n_ops_executing >= lload_client_max_pending ) {",
				"op->o_upstream_msgid = msgid = upstream->c_next_msgid++;",
				`ber_printf( output, "t{titOtO}", LDAP_TAG_MESSAGE,`,
				"LDAP_TAG_MSGID, msgid,",
				"op->o_tag, &op->o_request,",
				"if ( entry && op->o_restricted < entry->action ) {",
				"op->o_restricted = entry->action;",
				"if ( op->o_restricted == LLOAD_OP_RESTRICTED_REJECT ) {",
				"case LLOAD_OP_RESTRICTED_BACKEND:",
				"case LLOAD_OP_RESTRICTED_UPSTREAM:",
				"case LLOAD_OP_RESTRICTED_ISOLATE:",
			},
		},
		{
			path: "upstream.c",
			hash: "db9d0725ad5cc3e41be6dd6132e68f28a55138f5544042f658db70a5d138b282",
			anchors: []string{
				"if ( needle.o_upstream_msgid == 0 ) {",
				"return handle_unsolicited( c, ber );",
				"c->c_state = LLOAD_C_CLOSING;",
				"msgid = op->o_client_msgid;",
				"response_tag = ber_skip_element( ber, &response );",
				`ber_printf( output, "t{titOtO}", LDAP_TAG_MESSAGE,`,
				"LDAP_TAG_MSGID, msgid,",
				"response_tag, &response,",
				"tag = ber_get_int( ber, &needle.o_upstream_msgid );",
			},
		},
		{
			path: "operation.c",
			hash: "db8b8afc1e7e8a5dbef7eccf56614c6594a1f2426b118702def0314b3e1552d7",
			anchors: []string{
				"ldap_tavl_insert( &c->c_ops, op, operation_client_cmp, ldap_avl_dup_error );",
				"several operations with same msgid=%d in-flight",
				"c->c_n_ops_executing++;",
			},
		},
		{
			path: "backend.c",
			hash: "fed8ad8953c6e8fc2789f3e44ef3272c6293c2fe82b5d691d7d70589598590ed",
			anchors: []string{
				"if ( b->b_max_pending && b->b_n_ops_executing >= b->b_max_pending ) {",
				"*res = LDAP_BUSY;",
				"return 1;",
				"LDAP_STAILQ_FOREACH( tier, &tiers, t_next ) {",
				"if ( (finished = tier->t_type.tier_select(",
				"break;",
			},
		},
		{
			path: "tier_roundrobin.c",
			hash: "5a8570d33a7c4e176530f44538bde2307cada1bb2bc9ddb86f6d9103cd7613c9",
			anchors: []string{
				"result = backend_select( b, op, cp, res, message );",
				"rc |= result;",
				"if ( result && *cp ) {",
				"return rc;",
			},
		},
		{
			path: "bind.c",
			hash: "f5f4657e98b9f01b5e916ba43b7f049842f28367d70de5d39ecbe5694a721a15",
			anchors: []string{
				"pin = client->c_pin_id;",
				"upstream = op->o_upstream;",
				"} else if ( !pin && client_restricted != LLOAD_OP_RESTRICTED_ISOLATE ) {",
				"pinned upstream lost",
				"pin = op->o_pin_id = lload_next_pin++;",
				"op->o_saved_msgid = op->o_client_msgid;",
				"op->o_client_msgid = 0;",
			},
		},
		{
			path: "config.c",
			hash: "5f71fccca7e06f9c7d6693327856bfb72ecd91659ecf767248660e8147fc1c0e",
			anchors: []string{
				`{ "ignore", LLOAD_OP_NOT_RESTRICTED },`,
				`{ "write", LLOAD_OP_RESTRICTED_WRITE },`,
				`{ "backend", LLOAD_OP_RESTRICTED_BACKEND },`,
				`{ "connection", LLOAD_OP_RESTRICTED_UPSTREAM },`,
				`{ "isolate", LLOAD_OP_RESTRICTED_ISOLATE },`,
				`{ "reject", LLOAD_OP_RESTRICTED_REJECT },`,
			},
		},
		{
			path: "extended.c",
			hash: "0d01482accaec6f45a712c5ab3f1e2d806a9651699bd3c74df254eeed23df47b",
			anchors: []string{
				"op->o_restricted = restriction->action;",
				"op->o_restricted = lload_default_exop_action;",
				"return request_process( c, op );",
			},
		},
	}

	for _, check := range checks {
		path := filepath.Join(sourceRoot, "servers", "lloadd", check.path)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != check.hash {
			t.Fatalf("SHA-256(%s) = %s, want %s", path, got, check.hash)
		}
		for _, anchor := range check.anchors {
			if !strings.Contains(string(contents), anchor) {
				t.Fatalf("pinned OpenLDAP source %s lacks %q", path, anchor)
			}
		}
		sources[check.path] = string(contents)
	}

	assertLloaddTierBusyStopsFallback(t, sources["backend.c"], sources["tier_roundrobin.c"])
}

func requirePinnedOpenLDAPLloaddSource(t *testing.T) string {
	t.Helper()
	if got := os.Getenv(openLDAPReferenceTestsEnv); got != "1" {
		t.Skipf("set %s=1 to run the lloadd source reference test", openLDAPReferenceTestsEnv)
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPLloaddCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPLloaddCommit)
	}
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	return sourceRoot
}

func assertLloaddTierBusyStopsFallback(t *testing.T, backend, roundRobin string) {
	t.Helper()
	busy := lloaddSourceSection(t, backend, "int\nbackend_select(", "int\nupstream_select(")
	for _, anchor := range []string{
		"*res = LDAP_BUSY;",
		"*message = \"server busy\";",
		"return 1;",
	} {
		if !strings.Contains(busy, anchor) {
			t.Fatalf("pinned lloadd backend busy path lacks %q", anchor)
		}
	}

	selection := lloaddSourceSection(
		t,
		backend,
		"int\nupstream_select(",
		"/*\n * Will schedule a connection attempt",
	)
	if !strings.Contains(selection, "if ( (finished = tier->t_type.tier_select(") ||
		!strings.Contains(selection, "break;") {
		t.Fatal("pinned lloadd tier selection does not stop after a tier handles a busy request")
	}
	if !strings.Contains(roundRobin, "rc |= result;") ||
		!strings.Contains(roundRobin, "return rc;") {
		t.Fatal("pinned lloadd round-robin tier does not preserve a handled busy result")
	}
}

func lloaddSourceSection(t *testing.T, source, start, end string) string {
	t.Helper()
	startIndex := strings.Index(source, start)
	if startIndex < 0 {
		t.Fatalf("pinned lloadd source lacks section start %q", start)
	}
	endIndex := strings.Index(source[startIndex+len(start):], end)
	if endIndex < 0 {
		t.Fatalf("pinned lloadd source lacks section end %q", end)
	}
	return source[startIndex : startIndex+len(start)+endIndex]
}
