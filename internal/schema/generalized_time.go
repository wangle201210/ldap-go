package schema

import (
	"errors"
	"fmt"
	"time"
)

func normalizeGeneralizedTime(value []byte) ([]byte, error) {
	const minimumLength = len("YYYYmmddHHZ")
	if len(value) < minimumLength {
		return nil, errors.New("value is not generalized time")
	}

	year, ok := decimalField(value, 0, 4)
	if !ok {
		return nil, errors.New("value is not generalized time")
	}
	month, ok := decimalField(value, 4, 2)
	if !ok || month < 1 || month > 12 {
		return nil, errors.New("value is not generalized time")
	}
	day, ok := decimalField(value, 6, 2)
	if !ok || day < 1 || day > daysInMonth(year, month) {
		return nil, errors.New("value is not generalized time")
	}
	hour, ok := decimalField(value, 8, 2)
	if !ok || hour > 23 {
		return nil, errors.New("value is not generalized time")
	}

	index := 10
	minute := 0
	second := 0
	if index < len(value) && isASCIIDigit(value[index]) {
		minute, ok = decimalField(value, index, 2)
		if !ok || minute > 59 {
			return nil, errors.New("value is not generalized time")
		}
		index += 2
		if index < len(value) && isASCIIDigit(value[index]) {
			second, ok = decimalField(value, index, 2)
			if !ok || second > 60 {
				return nil, errors.New("value is not generalized time")
			}
			index += 2
		}
	}

	var fraction []byte
	if index < len(value) && (value[index] == '.' || value[index] == ',') {
		index++
		start := index
		for index < len(value) && isASCIIDigit(value[index]) {
			index++
		}
		if index == start {
			return nil, errors.New("value is not generalized time")
		}
		end := index
		for end > start && value[end-1] == '0' {
			end--
		}
		fraction = value[start:end]
	}

	if index >= len(value) {
		return nil, errors.New("value is not generalized time")
	}
	offsetMinutes := 0
	switch value[index] {
	case 'Z':
		index++
	case '+', '-':
		sign := 1
		if value[index] == '-' {
			sign = -1
		}
		index++
		remaining := len(value) - index
		if remaining != 2 && remaining != 4 {
			return nil, errors.New("value is not generalized time")
		}
		offsetHour, valid := decimalField(value, index, 2)
		if !valid || offsetHour > 23 {
			return nil, errors.New("value is not generalized time")
		}
		index += 2
		offsetMinute := 0
		if remaining == 4 {
			offsetMinute, valid = decimalField(value, index, 2)
			if !valid || offsetMinute > 59 {
				return nil, errors.New("value is not generalized time")
			}
			index += 2
		}
		offsetMinutes = sign * (offsetHour*60 + offsetMinute)
	default:
		return nil, errors.New("value is not generalized time")
	}
	if index != len(value) {
		return nil, errors.New("value is not generalized time")
	}

	utc := time.Date(year, time.Month(month), day, hour, minute, 0, 0, time.UTC).
		Add(-time.Duration(offsetMinutes) * time.Minute)
	if utc.Year() < 0 || utc.Year() > 9999 {
		return nil, errors.New("value is not generalized time")
	}
	normalized := []byte(fmt.Sprintf(
		"%04d%02d%02d%02d%02d%02d",
		utc.Year(),
		utc.Month(),
		utc.Day(),
		utc.Hour(),
		utc.Minute(),
		second,
	))
	if len(fraction) > 0 {
		normalized = append(normalized, '.')
		normalized = append(normalized, fraction...)
	}
	normalized = append(normalized, 'Z')
	return normalized, nil
}

func validGeneralizedTime(value []byte) bool {
	_, err := normalizeGeneralizedTime(value)
	return err == nil
}

func decimalField(value []byte, start, length int) (int, bool) {
	if start < 0 || length <= 0 || start+length > len(value) {
		return 0, false
	}
	result := 0
	for _, character := range value[start : start+length] {
		if !isASCIIDigit(character) {
			return 0, false
		}
		result = result*10 + int(character-'0')
	}
	return result, true
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func daysInMonth(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%400 == 0 || year%4 == 0 && year%100 != 0 {
			return 29
		}
		return 28
	default:
		return 31
	}
}
