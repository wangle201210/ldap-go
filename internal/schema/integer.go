package schema

import (
	"bytes"
	"errors"
)

func validLDAPInteger(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	start := 0
	if value[0] == '-' {
		start = 1
		if len(value) == 1 || value[1] == '0' {
			return false
		}
	} else if value[0] == '0' {
		return len(value) == 1
	}
	for _, character := range value[start:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareLDAPIntegers(left, right []byte) (int, error) {
	if !validLDAPInteger(left) || !validLDAPInteger(right) {
		return 0, errors.New("integer matching rule received invalid integer")
	}
	leftNegative := left[0] == '-'
	rightNegative := right[0] == '-'
	if leftNegative != rightNegative {
		if leftNegative {
			return -1, nil
		}
		return 1, nil
	}
	if leftNegative {
		left = left[1:]
		right = right[1:]
	}
	comparison := 0
	switch {
	case len(left) < len(right):
		comparison = -1
	case len(left) > len(right):
		comparison = 1
	default:
		comparison = bytes.Compare(left, right)
	}
	if leftNegative {
		comparison = -comparison
	}
	return comparison, nil
}
