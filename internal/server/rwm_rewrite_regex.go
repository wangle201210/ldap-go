package server

import (
	"fmt"
	"regexp/syntax"
	"slices"
	"unicode/utf8"
)

const rwmRewriteMaximumRegexSteps = 4 << 20

// Go's regexp finds the POSIX leftmost-longest whole match, but deliberately
// does not choose POSIX longest submatches. Enumerate the capture paths within
// that span with a shared work bound; ambiguous expressions cannot run forever.
func (rule *rwmRewriteRule) match(input string, operation *rwmRewriteOperation) ([]int, error) {
	operation.regexSteps += (len(input) + 1) * len(rule.program.Inst)
	if operation.regexSteps > rwmRewriteMaximumRegexSteps {
		return nil, fmt.Errorf("rewrite regex work exceeds %d steps", rwmRewriteMaximumRegexSteps)
	}
	span := rule.pattern.FindStringIndex(input)
	if span == nil || rule.pattern.NumSubexp() == 0 {
		return span, nil
	}
	type epsilonPath struct {
		pc       uint32
		previous *epsilonPath
	}
	type state struct {
		pc       uint32
		position int
		captures []int
		epsilon  *epsilonPath
	}
	captures := make([]int, 2*(min(rule.pattern.NumSubexp(), 9)+1))
	for index := range captures {
		captures[index] = -1
	}
	captures[0], captures[1] = span[0], span[1]
	pending := []state{{pc: uint32(rule.program.Start), position: span[0], captures: captures}}
	var best []int
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
	path:
		for {
			operation.regexSteps++
			if operation.regexSteps > rwmRewriteMaximumRegexSteps {
				return nil, fmt.Errorf("rewrite regex work exceeds %d steps", rwmRewriteMaximumRegexSteps)
			}
			instruction := &rule.program.Inst[current.pc]
			switch instruction.Op {
			case syntax.InstAlt, syntax.InstAltMatch, syntax.InstCapture, syntax.InstEmptyWidth, syntax.InstNop:
				for previous := current.epsilon; previous != nil; previous = previous.previous {
					if previous.pc == current.pc {
						break path
					}
				}
				current.epsilon = &epsilonPath{pc: current.pc, previous: current.epsilon}
			}
			switch instruction.Op {
			case syntax.InstAlt, syntax.InstAltMatch:
				if len(pending) >= 16384 {
					return nil, fmt.Errorf("rewrite regex pending paths exceed 16384")
				}
				other := current
				other.pc = instruction.Arg
				pending = append(pending, other)
				current.pc = instruction.Out
			case syntax.InstCapture:
				if int(instruction.Arg) < len(current.captures) {
					current.captures = slices.Clone(current.captures)
					current.captures[instruction.Arg] = current.position
				}
				current.pc = instruction.Out
			case syntax.InstEmptyWidth:
				before, after := rune(-1), rune(-1)
				if current.position > 0 {
					before, _ = utf8.DecodeLastRuneInString(input[:current.position])
				}
				if current.position < len(input) {
					after, _ = utf8.DecodeRuneInString(input[current.position:])
				}
				available := syntax.EmptyOpContext(before, after)
				if syntax.EmptyOp(instruction.Arg)&^available != 0 {
					break path
				}
				current.pc = instruction.Out
			case syntax.InstNop:
				current.pc = instruction.Out
			case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				if current.position >= span[1] {
					break path
				}
				character, size := utf8.DecodeRuneInString(input[current.position:span[1]])
				if !instruction.MatchRune(character) {
					break path
				}
				current.position += size
				current.pc = instruction.Out
				current.epsilon = nil
			case syntax.InstMatch:
				if current.position == span[1] && rwmRewritePreferCaptures(current.captures, best) {
					best = current.captures
				}
				break path
			default:
				break path
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("rewrite regex capture selection failed")
	}
	return best, nil
}

// Bound counted-repeat expansion before regexp compiles or simplifies the AST.
func rwmRewritePatternCost(expression *syntax.Regexp) int {
	cost := 1 + len(expression.Rune)
	for _, child := range expression.Sub {
		cost += rwmRewritePatternCost(child)
		if cost > 8192 {
			return 8193
		}
	}
	if expression.Op == syntax.OpRepeat {
		cost *= max(expression.Min+1, expression.Max)
	}
	return min(cost, 8193)
}

func rwmRewritePreferCaptures(candidate, best []int) bool {
	if best == nil {
		return true
	}
	for index := 2; index < len(candidate); index += 2 {
		candidateLength, bestLength := -1, -1
		if candidate[index] >= 0 {
			candidateLength = candidate[index+1] - candidate[index]
		}
		if best[index] >= 0 {
			bestLength = best[index+1] - best[index]
		}
		if candidateLength != bestLength {
			return candidateLength > bestLength
		}
		if candidate[index] != best[index] {
			return candidate[index] < best[index]
		}
	}
	return false
}
