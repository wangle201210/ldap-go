package directory

import (
	"errors"
	"testing"
)

type filterEqualityEvaluator struct {
	BasicMatcher
	result          FilterResult
	hasValues       bool
	assertionError  error
	validationCalls int
}

func (matcher *filterEqualityEvaluator) EvaluateEquality(Entry, string, []byte) (FilterResult, bool) {
	return matcher.result, matcher.hasValues
}

func (*filterEqualityEvaluator) Compare(string, string, []byte, []byte) (int, error) {
	panic("equality evaluator must bypass per-value Compare")
}

func (*filterEqualityEvaluator) AttributeValues(Entry, string) [][]byte {
	panic("equality evaluator must bypass value cloning")
}

func (*filterEqualityEvaluator) HasAttributeDescription(Entry, string) bool { return false }

func (matcher *filterEqualityEvaluator) ValidateFilterAssertion(Filter) error {
	matcher.validationCalls++
	return matcher.assertionError
}

func TestFilterEqualityEvaluatorDispatch(t *testing.T) {
	for _, result := range []FilterResult{FilterUndefinedResult, FilterFalseResult, FilterTrueResult} {
		for _, hasValues := range []bool{false, true} {
			for _, assertionError := range []error{nil, errors.New("invalid assertion")} {
				matcher := &filterEqualityEvaluator{result: result, hasValues: hasValues, assertionError: assertionError}
				filter := Filter{Kind: FilterEquality, Attribute: "uid", Assertion: []byte("alice")}
				want, validations := result, 0
				if !hasValues {
					validations = 1
					want = FilterFalseResult
					if assertionError != nil {
						want = FilterUndefinedResult
					}
				}
				got, err := filter.EvaluateWith(Entry{}, matcher)
				if err != nil || got != want || matcher.validationCalls != validations {
					t.Fatalf("result=%v hasValues=%v invalid=%v: got (%v, %v), validations %d; want %v, %d",
						result, hasValues, assertionError != nil, got, err, matcher.validationCalls, want, validations)
				}
			}
		}
	}
}
