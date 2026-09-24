package directory

// DisplayEquals compares String() with raw without materializing the joined DN.
// It is an exact textual comparison, not schema-aware DN equality.
func (dn DN) DisplayEquals(raw string) bool {
	position := 0
	for index, rdn := range dn.displayRDNs {
		if index > 0 {
			if position == len(raw) || raw[position] != ',' {
				return false
			}
			position++
		}
		if len(rdn) > len(raw)-position || raw[position:position+len(rdn)] != rdn {
			return false
		}
		position += len(rdn)
	}
	return position == len(raw)
}

// DisplaySuffixOf is the literal predicate raw == String() or
// strings.HasSuffix(raw, ","+String()), without constructing either string.
// In particular, it does not interpret escaping or assert DN ancestry.
func (dn DN) DisplaySuffixOf(raw string) bool {
	position := len(raw)
	for index := len(dn.displayRDNs) - 1; index >= 0; index-- {
		rdn := dn.displayRDNs[index]
		if len(rdn) > position || raw[position-len(rdn):position] != rdn {
			return false
		}
		position -= len(rdn)
		if index > 0 {
			if position == 0 || raw[position-1] != ',' {
				return false
			}
			position--
		}
	}
	return position == 0 || raw[position-1] == ','
}
