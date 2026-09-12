package slapdconf

import (
	"reflect"
	"testing"
)

func TestConvertVerifyCredentialsAndAuthzid(t *testing.T) {
	path := configFile(t, `moduleload vc.la
moduleload authzid.la
database frontend
overlay authzid
database mdb
suffix dc=example
directory /unused/data
`)
	document, err := ConvertFile(path, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := values(t, document, "cn=module{0},cn=config", "olcModuleLoad"); !reflect.DeepEqual(got, []string{"{0}vc.la", "{1}authzid.la"}) {
		t.Fatalf("module declarations: %q", got)
	}
	if got := values(t, document, "olcOverlay={0}authzid,olcDatabase={-1}frontend,cn=config", "olcOverlay"); !reflect.DeepEqual(got, []string{"{0}authzid"}) {
		t.Fatalf("authzid overlay: %q", got)
	}
}
