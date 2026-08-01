package server

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadValueSortRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	entry := directory.Entry{
		DN: "olcOverlay={0}valsort,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcValSortAttr",
			Values: stringValues(
				`{0}description "ou=people,dc=example,dc=com" alpha-descend`,
				`{1}score "dc=example,dc=com" weighted numeric-ascend`,
				`{2}cn "dc=example,dc=com" alpha-ascend ignored-extra`,
			),
		}},
	}
	configuration, err := loadValueSortRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadValueSortRuntimeConfiguration(): %v", err)
	}
	if len(configuration.rules) != 3 {
		t.Fatalf("rules = %#v", configuration.rules)
	}
	first := configuration.rules[0]
	if first.attribute != "description" || first.kind != valueSortAlpha ||
		!first.descending || first.weighted ||
		first.base.Key() != "ou=people,dc=example,dc=com" {
		t.Fatalf("first rule = %#v", first)
	}
	second := configuration.rules[1]
	if second.attribute != "score" || second.kind != valueSortNumeric ||
		second.descending || !second.weighted {
		t.Fatalf("second rule = %#v", second)
	}
	third := configuration.rules[2]
	if third.kind != valueSortAlpha || third.weighted || third.descending {
		t.Fatalf("third rule = %#v", third)
	}
}

func TestLoadValueSortRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"missing":        nil,
		"ordered":        {"{x}description dc=example,dc=com alpha-ascend"},
		"fields":         {"description dc=example,dc=com"},
		"too many":       {"description dc=example,dc=com weighted alpha-ascend extra"},
		"DN":             {"description not-a-dn alpha-ascend"},
		"sort":           {"description dc=example,dc=com lexical"},
		"secondary sort": {"description dc=example,dc=com weighted lexical"},
		"quote":          {`description "dc=example,dc=com alpha-ascend`},
	}
	for name, values := range tests {
		values := values
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := directory.Entry{
				DN: "olcOverlay=valsort,olcDatabase={1}mdb,cn=config",
			}
			if values != nil {
				entry.Attributes = []directory.Attribute{{
					Description: "olcValSortAttr",
					Values:      stringValues(values...),
				}}
			}
			if _, err := loadValueSortRuntimeConfiguration(entry); err == nil {
				t.Fatal("invalid valsort configuration was accepted")
			}
		})
	}
}

func TestValidateValueSortSchema(t *testing.T) {
	t.Parallel()

	registry := valueSortTestRegistry(t)
	configuration := valueSortRuntimeConfiguration{rules: []valueSortRule{
		{attribute: "rankedLabel", kind: valueSortAlpha},
		{attribute: "score", kind: valueSortNumeric},
		{attribute: "singleRank", kind: valueSortAlpha},
	}}
	if err := validateValueSortSchema(registry, &configuration); err != nil {
		t.Fatalf("validateValueSortSchema(): %v", err)
	}
	if configuration.rules[0].ignored || configuration.rules[1].ignored ||
		!configuration.rules[2].ignored {
		t.Fatalf("validated rules = %#v", configuration.rules)
	}

	undefined := valueSortRuntimeConfiguration{rules: []valueSortRule{{
		attribute: "notInSchema",
		kind:      valueSortAlpha,
	}}}
	if err := validateValueSortSchema(registry, &undefined); err == nil ||
		!strings.Contains(err.Error(), "undefined") {
		t.Fatalf("undefined attribute error = %v", err)
	}
	nonnumeric := valueSortRuntimeConfiguration{rules: []valueSortRule{{
		attribute: "rankedLabel",
		kind:      valueSortNumeric,
	}}}
	if err := validateValueSortSchema(registry, &nonnumeric); err == nil ||
		!strings.Contains(err.Error(), "non-numeric") {
		t.Fatalf("nonnumeric attribute error = %v", err)
	}
}

func TestParseValueSortWeightMatchesStrtolBaseZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value  string
		weight int64
		found  bool
		valid  bool
	}{
		{value: "{10}value", weight: 10, found: true, valid: true},
		{value: "prefix{-2}value", weight: -2, found: true, valid: true},
		{value: "{010}value", weight: 8, found: true, valid: true},
		{value: "{0x10}value", weight: 16, found: true, valid: true},
		{value: "{}value", weight: 0, found: true, valid: true},
		{value: "{ 2}value", weight: 2, found: true, valid: true},
		{value: "value"},
		{value: "{08}value", found: true},
		{value: "{x}value", found: true},
		{value: "{+}value", found: true},
	}
	for _, test := range tests {
		weight, _, found, valid := parseValueSortWeight([]byte(test.value))
		if weight != test.weight || found != test.found || valid != test.valid {
			t.Errorf(
				"parseValueSortWeight(%q) = (%d, %t, %t), want (%d, %t, %t)",
				test.value,
				weight,
				found,
				valid,
				test.weight,
				test.found,
				test.valid,
			)
		}
	}
}

func TestApplyValueSort(t *testing.T) {
	t.Parallel()

	registry := valueSortTestRegistry(t)
	base, _ := directory.ParseDN("ou=people,dc=example,dc=com")
	entry := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "rankedLabel",
				Values: stringValues(
					"{2}Beta",
					"{1}Zulu",
					"{1}alpha",
				),
			},
			{
				Description: "score",
				Values:      stringValues("10", "-1", "2"),
			},
		},
	}
	applyValueSort(registry, []valueSortRule{
		{
			attribute: "rankedLabel",
			base:      base,
			kind:      valueSortAlpha,
			weighted:  true,
		},
		{
			attribute:  "score",
			base:       base,
			kind:       valueSortNumeric,
			descending: true,
		},
	}, &entry)
	assertByteValuesEqual(
		t,
		entry.Values("rankedLabel"),
		stringValues("alpha", "Zulu", "Beta"),
	)
	assertByteValuesEqual(
		t,
		entry.Values("score"),
		stringValues("10", "2", "-1"),
	)
}

func TestApplyValueSortStripsSingleWeightedValue(t *testing.T) {
	t.Parallel()

	base, _ := directory.ParseDN("ou=people,dc=example,dc=com")
	entry := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "rankedLabel",
			Values:      stringValues("{7}only"),
		}},
	}
	applyValueSort(valueSortTestRegistry(t), []valueSortRule{{
		attribute: "rankedLabel",
		base:      base,
		weighted:  true,
	}}, &entry)
	assertByteValuesEqual(
		t,
		entry.Values("rankedLabel"),
		stringValues("only"),
	)
}

func TestApplyValueSortMatchesPartialStripForMalformedStoredWeights(t *testing.T) {
	t.Parallel()

	base, _ := directory.ParseDN("ou=people,dc=example,dc=com")
	entry := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "rankedLabel",
			Values: stringValues(
				"{2}first",
				"missing",
				"{1}third",
			),
		}},
	}
	applyValueSort(valueSortTestRegistry(t), []valueSortRule{{
		attribute: "rankedLabel",
		base:      base,
		kind:      valueSortAlpha,
		weighted:  true,
	}}, &entry)
	assertByteValuesEqual(
		t,
		entry.Values("rankedLabel"),
		stringValues("first", "missing", "{1}third"),
	)
}

func TestValidateValueSortWeightedWrites(t *testing.T) {
	t.Parallel()

	registry := valueSortTestRegistry(t)
	base, _ := directory.ParseDN("ou=people,dc=example,dc=com")
	configuration := &valueSortRuntimeConfiguration{rules: []valueSortRule{{
		attribute: "rankedLabel",
		base:      base,
		kind:      valueSortAlpha,
		weighted:  true,
	}}}
	database := runtimeDatabase{name: "{1}mdb", valueSort: configuration}
	runtime := &runtimeState{schema: registry, databases: []runtimeDatabase{database}}
	valid := directory.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "rankedLabel",
			Values:      stringValues("{1}one", "{}zero"),
		}},
	}
	if err := validateValueSortAdd(runtime, database, valid); err != nil {
		t.Fatalf("validateValueSortAdd(valid): %v", err)
	}
	missing := valid.Clone()
	missing.ReplaceValues("rankedLabel", stringValues("one"))
	err := validateValueSortAdd(runtime, database, missing)
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultConstraintViolation ||
		failure.result.DiagnosticMessage != "weight missing from attribute" {
		t.Fatalf("missing weight error = %v", err)
	}
	malformed := []ldapwire.Modification{{
		Operation: ldapwire.ModificationAdd,
		Attribute: directory.Attribute{
			Description: "rankedLabel",
			Values:      stringValues("{08}eight"),
		},
	}}
	dn, _ := directory.ParseDN(valid.DN)
	err = validateValueSortModify(
		runtime,
		database,
		dn,
		malformed,
	)
	failure = asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultConstraintViolation ||
		failure.result.DiagnosticMessage != "weight is misformatted" {
		t.Fatalf("malformed weight error = %v", err)
	}
}

func TestLoadRuntimeDatabasesLoadsValueSortOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			},
		},
		{
			DN: "olcOverlay={0}valsort,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}valsort")},
				{
					Description: "olcValSortAttr",
					Values: stringValues(
						`description "dc=example,dc=com" alpha-ascend`,
					),
				},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed valsort configuration: %v", err)
	}
	databases, err := loadRuntimeDatabases(context.Background(), store)
	if err != nil {
		t.Fatalf("loadRuntimeDatabases(): %v", err)
	}
	suffix, _ := directory.ParseDN("dc=example,dc=com")
	database := databases[databaseIndexForDN(databases, suffix)]
	if database.valueSort == nil || len(database.valueSort.rules) != 1 {
		t.Fatalf("valueSort = %#v", database.valueSort)
	}
}

func TestParseValueSortControl(t *testing.T) {
	t.Parallel()

	for _, raw := range []bool{false, true} {
		parsed, failure := parseRequestControls(
			[]ldapwire.Control{{
				OID:      valueSortControlOID,
				Critical: true,
				HasValue: true,
				Value:    ldapwire.EncodeValueSortControlValue(raw),
			}},
			supportsValueSort,
		)
		if failure != nil || parsed.valueSort == nil ||
			parsed.valueSort.raw != raw || !parsed.valueSort.critical {
			t.Fatalf("parse valSort(%t) = %#v, %#v", raw, parsed, failure)
		}
	}

	invalid := []struct {
		name     string
		controls []ldapwire.Control
	}{
		{
			name: "absent",
			controls: []ldapwire.Control{{
				OID:      valueSortControlOID,
				Critical: true,
			}},
		},
		{
			name: "empty",
			controls: []ldapwire.Control{{
				OID:      valueSortControlOID,
				Critical: true,
				HasValue: true,
			}},
		},
		{
			name: "malformed",
			controls: []ldapwire.Control{{
				OID:      valueSortControlOID,
				Critical: true,
				HasValue: true,
				Value:    []byte{0x30, 0x00},
			}},
		},
		{
			name: "duplicate",
			controls: []ldapwire.Control{
				{
					OID:      valueSortControlOID,
					HasValue: true,
					Value:    ldapwire.EncodeValueSortControlValue(false),
				},
				{
					OID:      valueSortControlOID,
					HasValue: true,
					Value:    ldapwire.EncodeValueSortControlValue(true),
				},
			},
		},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, failure := parseRequestControls(test.controls, supportsValueSort)
			if failure == nil || failure.Code != ldapwire.ResultProtocolError {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}

	_, unsupported := parseRequestControls(
		[]ldapwire.Control{{
			OID:      valueSortControlOID,
			Critical: true,
			HasValue: true,
			Value:    ldapwire.EncodeValueSortControlValue(true),
		}},
		0,
	)
	if unsupported == nil ||
		unsupported.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("unsupported critical control failure = %#v", unsupported)
	}
	parsed, failure := parseRequestControls(
		[]ldapwire.Control{{
			OID:      valueSortControlOID,
			HasValue: true,
			Value:    ldapwire.EncodeValueSortControlValue(true),
		}},
		0,
	)
	if failure != nil || parsed.valueSort != nil {
		t.Fatalf("unsupported noncritical control = %#v, %#v", parsed, failure)
	}
}

func valueSortTestRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( 1.3.6.1.4.1.99999.10.1 NAME 'rankedLabel' EQUALITY caseIgnoreMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
		"( 1.3.6.1.4.1.99999.10.2 NAME 'score' EQUALITY integerMatch SYNTAX " +
			schema.SyntaxInteger + " )",
		"( 1.3.6.1.4.1.99999.10.3 NAME 'singleRank' EQUALITY caseIgnoreMatch SYNTAX " +
			schema.SyntaxDirectoryString + " SINGLE-VALUE )",
		"( 1.3.6.1.4.1.99999.10.4 NAME 'plainLabel' EQUALITY caseIgnoreMatch SYNTAX " +
			schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("register attribute %q: %v", definition, err)
		}
	}
	if err := registry.ParseAndRegisterObjectClass(
		"( 1.3.6.1.4.1.99999.10.10 NAME 'valueSortData' SUP top AUXILIARY " +
			"MAY ( rankedLabel $ score $ singleRank $ plainLabel ) )",
	); err != nil {
		t.Fatalf("register valueSortData: %v", err)
	}
	return registry
}

func assertByteValuesEqual(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("values = %q, want %q", got, want)
	}
	for index := range want {
		if string(got[index]) != string(want[index]) {
			t.Fatalf("values = %q, want %q", got, want)
		}
	}
}
