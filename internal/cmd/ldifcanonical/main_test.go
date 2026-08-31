package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalizeLDIFIgnoresAttributeAndValueOrder(t *testing.T) {
	t.Parallel()

	left := `dn: uid=alice,dc=example,dc=com
objectClass: person
objectClass: top
cn: Alice
description:: AP8Q

`
	right := `dn: uid=alice,dc=example,dc=com
DESCRIPTION:: AP8Q
cn: Alice
objectClass: top
objectClass: person

`
	var leftOutput, rightOutput bytes.Buffer
	if err := canonicalizeLDIF(strings.NewReader(left), &leftOutput); err != nil {
		t.Fatalf("canonicalize left: %v", err)
	}
	if err := canonicalizeLDIF(strings.NewReader(right), &rightOutput); err != nil {
		t.Fatalf("canonicalize right: %v", err)
	}
	if leftOutput.String() != rightOutput.String() {
		t.Fatalf("canonical outputs differ:\nleft:  %sright: %s", leftOutput.String(), rightOutput.String())
	}
}

func TestCanonicalizeLDIFStreamsEntriesWithoutSortingThem(t *testing.T) {
	t.Parallel()

	input := `dn: uid=bob,dc=example,dc=com
uid: bob

dn: uid=alice,dc=example,dc=com
uid: alice

`
	var output bytes.Buffer
	if err := canonicalizeLDIF(strings.NewReader(input), &output); err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "7569643d626f62") ||
		!strings.HasPrefix(lines[1], "7569643d616c696365") {
		t.Fatalf("canonical lines = %q", lines)
	}
}

func TestCanonicalizeLDIFRejectsChangeRecords(t *testing.T) {
	t.Parallel()

	input := `dn: uid=alice,dc=example,dc=com
changetype: delete

`
	if err := canonicalizeLDIF(strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("canonicalize accepted a change record")
	}
}
