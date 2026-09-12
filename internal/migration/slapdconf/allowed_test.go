package slapdconf

import (
	"reflect"
	"testing"
)

func TestConvertAllowedOverlay(t *testing.T) {
	document, err := ConvertFile(configFile(t, `moduleload allowed.la
database frontend
overlay allowed
database mdb
suffix dc=example
directory /unused/data
overlay allowed
`), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := values(t, document, "cn=module{0},cn=config", "olcModuleLoad"); !reflect.DeepEqual(got, []string{"{0}allowed.la"}) {
		t.Fatalf("module declaration = %q", got)
	}
	for _, parent := range []string{"olcDatabase={-1}frontend,cn=config", "olcDatabase={1}mdb,cn=config"} {
		dn := "olcOverlay={0}allowed," + parent
		if got := values(t, document, dn, "olcOverlay"); !reflect.DeepEqual(got, []string{"{0}allowed"}) {
			t.Fatalf("%s overlay = %q", parent, got)
		}
		if got := values(t, document, dn, "objectClass"); !reflect.DeepEqual(got, []string{"olcOverlayConfig"}) {
			t.Fatalf("%s object classes = %q", parent, got)
		}
	}
	if err := document.Validate(t.Context()); err != nil {
		t.Fatalf("converted allowed configuration is invalid: %v", err)
	}
}
