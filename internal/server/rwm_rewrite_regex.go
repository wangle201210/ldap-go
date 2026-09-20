package server

import (
	"fmt"
	"regexp/syntax"
	"runtime"
	"slices"
	"unicode/utf8"
)

const rwmRewriteMaximumRegexSteps = 4 << 20

// Linux follows the tested glibc capture selection using Go's leftmost-longest
// matcher. Other targets retain BSD-style capture selection within that span.
// This does not establish compatibility with musl's regexec implementation.
func (rule *rwmRewriteRule) match(input string, operation *rwmRewriteOperation) ([]int, error) {
	operation.regexSteps += (len(input) + 1) * len(rule.program.Inst)
	if operation.regexSteps > rwmRewriteMaximumRegexSteps {
		return nil, fmt.Errorf("rewrite regex work exceeds %d steps", rwmRewriteMaximumRegexSteps)
	}
	if runtime.GOOS == "linux" {
		return rule.pattern.FindStringSubmatchIndex(input), nil
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
		pc           uint32
		position     int
		captures     []int
		history      [10]*rwmRewriteCaptureHistory
		endPositions [10]int
		epsilon      *epsilonPath
	}
	captures := make([]int, 2*(min(rule.pattern.NumSubexp(), 9)+1))
	for index := range captures {
		captures[index] = -1
	}
	captures[0], captures[1] = span[0], span[1]
	initial := state{pc: uint32(rule.program.Start), position: span[0], captures: captures}
	for group := range initial.endPositions {
		initial.endPositions[group] = -1
	}
	pending := []state{initial}
	var best []int
	var bestHistory [10]*rwmRewriteCaptureHistory
	var bestEndPositions [10]int
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
			for _, group := range rule.captureEndBoundary[current.pc] {
				current.endPositions[group] = current.position
			}
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
					group := int(instruction.Arg) / 2
					if instruction.Arg%2 == 0 {
						for _, child := range rule.captureChildren[group] {
							current.captures[2*child], current.captures[2*child+1] = -1, -1
							current.endPositions[child] = -1
						}
					} else {
						current.history[group] = &rwmRewriteCaptureHistory{
							start: current.captures[instruction.Arg-1], end: current.position,
							previous: current.history[group],
						}
					}
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
				if current.position == span[1] {
					prefer, err := rwmRewritePreferCaptureHistory(current.history, bestHistory, operation)
					if err != nil {
						return nil, err
					}
					if best == nil || prefer {
						best, bestHistory = current.captures, current.history
						bestEndPositions = current.endPositions
					}
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
	for group := 1; group < len(best)/2; group++ {
		if best[2*group] < 0 && bestHistory[group] != nil && bestEndPositions[group] >= 0 {
			best[2*group], best[2*group+1] = bestHistory[group].start, bestEndPositions[group]
		}
		parent := rule.captureEndParent[group]
		if parent >= 0 && bestHistory[group] != nil && best[2*parent+1] >= 0 {
			best[2*group], best[2*group+1] = bestHistory[group].start, best[2*parent+1]
		}
	}
	return best, nil
}

// Darwin TRE merges consecutive unions, including the union generated for an
// ICASE letter. A captured union used as a whole branch retains its start tag
// and shares its enclosing union's end tag across repetitions. Go's parsed AST
// folds both [a] and a to the same node, so preserve this source-level distinction.
func (rule *rwmRewriteRule) configureCaptureTags(pattern string, foldCase bool) {
	for group := range rule.captureEndParent {
		rule.captureEndParent[group] = -1
	}
	if runtime.GOOS != "darwin" {
		return
	}
	type capture struct {
		start, end, parent, branchStart int
		union, wholeBranch              bool
	}
	groups := []capture{{start: -1, end: len(pattern)}}
	stack := []int{0}
	for index := 0; index < len(pattern); index++ {
		parent := stack[len(stack)-1]
		switch pattern[index] {
		case '\\':
			index++
		case '[':
			index++
			if index < len(pattern) && pattern[index] == '^' {
				index++
			}
			if index < len(pattern) && pattern[index] == ']' {
				index++
			}
			for index < len(pattern) && pattern[index] != ']' {
				if pattern[index] == '\\' {
					index++
				} else if pattern[index] == '[' && index+1 < len(pattern) && pattern[index+1] == ':' {
					for index+1 < len(pattern) && !(pattern[index] == ':' && pattern[index+1] == ']') {
						index++
					}
					index++
				}
				index++
			}
		case '(':
			groups = append(groups, capture{start: index, parent: parent,
				branchStart: index + 1, wholeBranch: index == groups[parent].branchStart})
			stack = append(stack, len(groups)-1)
		case ')':
			groups[parent].end = index
			stack = stack[:len(stack)-1]
		case '|':
			groups[parent].union = true
			groups[parent].branchStart = index + 1
		}
	}
	for group := 1; group < min(len(groups), len(rule.captureEndParent)); group++ {
		current := groups[group]
		hasChildren := group+1 < len(groups) && groups[group+1].start < current.end
		if current.union && hasChildren && current.end+1 < len(pattern) {
			switch pattern[current.end+1] {
			case '?', '*', '{':
				// The optional/repeated union's exit also writes its shared end
				// tag when its body is skipped in a later parent iteration.
				for _, instruction := range rule.program.Inst {
					if instruction.Op == syntax.InstCapture && instruction.Arg == uint32(2*group+1) {
						if rule.captureEndBoundary == nil {
							rule.captureEndBoundary = make(map[uint32][]int)
						}
						rule.captureEndBoundary[instruction.Out] = append(rule.captureEndBoundary[instruction.Out], group)
					}
				}
			}
		}
		body := pattern[current.start+1 : current.end]
		foldedLetter := foldCase && len(body) == 1 && (body[0] >= 'a' && body[0] <= 'z' || body[0] >= 'A' && body[0] <= 'Z')
		if !current.union && !foldedLetter || !current.wholeBranch || !groups[current.parent].union {
			continue
		}
		branchEnd := current.end + 1
		if current.union && hasChildren && branchEnd < len(pattern) {
			switch pattern[branchEnd] {
			case '?', '*', '+':
				branchEnd++
			case '{':
				for branchEnd < len(pattern) && pattern[branchEnd] != '}' {
					branchEnd++
				}
				branchEnd++
			}
		}
		if branchEnd == groups[current.parent].end || branchEnd < len(pattern) && pattern[branchEnd] == '|' {
			rule.captureEndParent[group] = current.parent
		}
	}
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

type rwmRewriteCaptureHistory struct {
	start, end int
	previous   *rwmRewriteCaptureHistory
}

func rwmRewriteCaptureChildren(expression *syntax.Regexp) [10][]int {
	var children [10][]int
	var visit func(*syntax.Regexp, []int)
	visit = func(node *syntax.Regexp, parents []int) {
		if node.Op == syntax.OpCapture && node.Cap < len(children) {
			for _, parent := range parents {
				children[parent] = append(children[parent], node.Cap)
			}
			parents = append(slices.Clone(parents), node.Cap)
		}
		for _, child := range node.Sub {
			visit(child, parents)
		}
	}
	visit(expression, nil)
	return children
}

// Compare iterations from first to last; the final register value alone loses
// the greedy choice of earlier iterations. Histories are immutable across paths.
func rwmRewritePreferCaptureHistory(candidate, best [10]*rwmRewriteCaptureHistory, operation *rwmRewriteOperation) (bool, error) {
	for group := 1; group < len(candidate); group++ {
		if candidate[group] == best[group] {
			continue
		}
		var histories [2][]*rwmRewriteCaptureHistory
		for index, history := range [2]*rwmRewriteCaptureHistory{candidate[group], best[group]} {
			for node := history; node != nil; node = node.previous {
				operation.regexSteps++
				if operation.regexSteps > rwmRewriteMaximumRegexSteps {
					return false, fmt.Errorf("rewrite regex work exceeds %d steps", rwmRewriteMaximumRegexSteps)
				}
				histories[index] = append(histories[index], node)
			}
		}
		a, b := histories[0], histories[1]
		for len(a) > 0 && len(b) > 0 {
			left, right := a[len(a)-1], b[len(b)-1]
			if left.end-left.start != right.end-right.start {
				return left.end-left.start > right.end-right.start, nil
			}
			if left.start != right.start {
				return left.start < right.start, nil
			}
			a, b = a[:len(a)-1], b[:len(b)-1]
		}
		if len(a) != len(b) {
			// An empty extra iteration must not overwrite a nonempty capture.
			if len(a) > 0 {
				return best[group] == nil || a[len(a)-1].end > a[len(a)-1].start, nil
			}
			return candidate[group] != nil && b[len(b)-1].end == b[len(b)-1].start, nil
		}
	}
	return false, nil
}
