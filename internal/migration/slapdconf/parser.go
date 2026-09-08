package slapdconf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	defaultMaxFileBytes    int64 = 16 << 20
	defaultMaxTotalBytes   int64 = 64 << 20
	defaultMaxLogicalLine        = 1 << 20
	defaultMaxIncludeDepth       = 32
	defaultMaxFiles              = 256
)

// ParseOptions bounds slapd.conf and schema include expansion. Zero values use
// conservative defaults suitable for normal OpenLDAP configuration trees.
type ParseOptions struct {
	// IncludeBaseDir resolves all relative includes, as OpenLDAP does against
	// its process working directory. Empty uses the current working directory.
	IncludeBaseDir      string
	MaxFileBytes        int64
	MaxTotalBytes       int64
	MaxLogicalLineBytes int
	MaxIncludeDepth     int
	MaxFiles            int
}

// Position identifies the first physical line of a logical directive.
type Position struct {
	Path string
	Line int
}

// Directive is one decoded slapd.conf directive. Arguments follow OpenLDAP's
// double-quote and backslash rules and no longer contain quoting delimiters.
type Directive struct {
	Name      string
	Arguments []string
	Position  Position
}

// ParseError preserves source context across nested include files.
type ParseError struct {
	Position Position
	Err      error
}

func (err *ParseError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Position.Line > 0 {
		return fmt.Sprintf("%s:%d: %v", err.Position.Path, err.Position.Line, err.Err)
	}
	if err.Position.Path != "" {
		return fmt.Sprintf("%s: %v", err.Position.Path, err.Err)
	}
	return err.Err.Error()
}

func (err *ParseError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// ParseFile expands include directives in place, preserving section state.
func ParseFile(path string, options ParseOptions) ([]Directive, error) {
	return ParseFileContext(context.Background(), path, options)
}

// ParseFileContext is ParseFile with cancellation for include expansion and
// bounded file reads.
func ParseFileContext(ctx context.Context, path string, options ParseOptions) ([]Directive, error) {
	if ctx == nil {
		return nil, errors.New("slapd.conf parser context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("slapd.conf path is required")
	}
	options, err := normalizedParseOptions(options)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve slapd.conf path: %w", err)
	}
	parser := fileParser{
		ctx:     ctx,
		options: options,
	}
	if err := parser.parse(filepath.Clean(absolute), 0, Position{Path: absolute, Line: 1}); err != nil {
		return nil, err
	}
	return parser.directives, nil
}

type activeFile struct {
	position Position
	info     os.FileInfo
}

type configurationFileOpener func(string) (*os.File, os.FileInfo, error)

type fileParser struct {
	ctx        context.Context
	options    ParseOptions
	directives []Directive
	active     []activeFile
	totalBytes int64
	files      int
	opener     configurationFileOpener
}

func normalizedParseOptions(options ParseOptions) (ParseOptions, error) {
	base, err := filepath.Abs(options.IncludeBaseDir)
	if err != nil {
		return ParseOptions{}, fmt.Errorf("resolve include base directory: %w", err)
	}
	options.IncludeBaseDir = base
	if options.MaxFileBytes == 0 {
		options.MaxFileBytes = defaultMaxFileBytes
	}
	if options.MaxTotalBytes == 0 {
		options.MaxTotalBytes = defaultMaxTotalBytes
	}
	if options.MaxLogicalLineBytes == 0 {
		options.MaxLogicalLineBytes = defaultMaxLogicalLine
	}
	if options.MaxIncludeDepth == 0 {
		options.MaxIncludeDepth = defaultMaxIncludeDepth
	}
	if options.MaxFiles == 0 {
		options.MaxFiles = defaultMaxFiles
	}
	if options.MaxFileBytes < 1 || options.MaxTotalBytes < 1 ||
		options.MaxLogicalLineBytes < 1 || options.MaxIncludeDepth < 1 ||
		options.MaxFiles < 1 {
		return ParseOptions{}, errors.New("slapd.conf parser limits must be positive")
	}
	if options.MaxFileBytes > options.MaxTotalBytes {
		return ParseOptions{}, errors.New("slapd.conf per-file limit exceeds total limit")
	}
	if options.MaxFileBytes == math.MaxInt64 {
		return ParseOptions{}, errors.New("slapd.conf per-file limit is too large")
	}
	return options, nil
}

func (parser *fileParser) parse(path string, depth int, includedAt Position) error {
	if err := parser.ctx.Err(); err != nil {
		return err
	}
	if depth > parser.options.MaxIncludeDepth {
		return sourceError(includedAt, fmt.Errorf(
			"include depth exceeds %d", parser.options.MaxIncludeDepth,
		))
	}
	if parser.files >= parser.options.MaxFiles {
		return sourceError(includedAt, fmt.Errorf(
			"included file count exceeds %d", parser.options.MaxFiles,
		))
	}
	data, info, err := parser.readBounded(path)
	if err != nil {
		return sourceError(includedAt, err)
	}
	for _, active := range parser.active {
		if os.SameFile(info, active.info) {
			return sourceError(includedAt, fmt.Errorf(
				"include cycle through %s (active from %s:%d)",
				path, active.position.Path, active.position.Line,
			))
		}
	}
	parser.files++
	parser.active = append(parser.active, activeFile{
		position: includedAt, info: info,
	})
	defer func() { parser.active = parser.active[:len(parser.active)-1] }()

	logical, err := logicalLines(path, data, parser.options.MaxLogicalLineBytes)
	if err != nil {
		return err
	}
	for _, line := range logical {
		if err := parser.ctx.Err(); err != nil {
			return err
		}
		trimmed := strings.TrimSpace(line.text)
		if trimmed == "" || strings.HasPrefix(strings.TrimLeft(line.text, " \t"), "#") {
			continue
		}
		arguments, err := splitArguments(line.text)
		position := Position{Path: path, Line: line.line}
		if err != nil {
			return sourceError(position, err)
		}
		if len(arguments) == 0 {
			continue
		}
		name := strings.ToLower(arguments[0])
		if name == "include" {
			if len(arguments) != 2 || strings.TrimSpace(arguments[1]) == "" {
				return sourceError(position, errors.New("include requires exactly one path"))
			}
			includePath := arguments[1]
			if !filepath.IsAbs(includePath) {
				includePath = filepath.Join(parser.options.IncludeBaseDir, includePath)
			}
			if err := parser.parse(filepath.Clean(includePath), depth+1, position); err != nil {
				return err
			}
			continue
		}
		parser.directives = append(parser.directives, Directive{
			Name:      name,
			Arguments: append([]string(nil), arguments[1:]...),
			Position:  position,
		})
	}
	return nil
}

func (parser *fileParser) readBounded(path string) ([]byte, os.FileInfo, error) {
	opener := parser.opener
	if opener == nil {
		opener = openConfigurationFile
	}
	file, info, err := opener(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open configuration file: %w", err)
	}
	defer file.Close()
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("configuration path is not a regular file")
	}
	current, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("restat configuration file: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(info, current) {
		return nil, nil, errors.New("configuration path changed while it was opened")
	}
	if info.Size() > parser.options.MaxFileBytes {
		return nil, nil, fmt.Errorf(
			"configuration file is %d bytes; limit is %d",
			info.Size(), parser.options.MaxFileBytes,
		)
	}
	remaining := parser.options.MaxTotalBytes - parser.totalBytes
	if remaining < 0 {
		remaining = 0
	}
	limit := parser.options.MaxFileBytes
	if remaining < limit {
		limit = remaining
	}
	data, err := readConfigurationFile(parser.ctx, file, limit+1)
	if err != nil {
		return nil, nil, fmt.Errorf("read configuration file: %w", err)
	}
	if int64(len(data)) > parser.options.MaxFileBytes {
		return nil, nil, fmt.Errorf("configuration file exceeds %d bytes", parser.options.MaxFileBytes)
	}
	if int64(len(data)) > remaining {
		return nil, nil, fmt.Errorf("configuration tree exceeds %d bytes", parser.options.MaxTotalBytes)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, nil, errors.New("configuration file contains a NUL byte")
	}
	if !utf8.Valid(data) {
		return nil, nil, errors.New("configuration file contains invalid UTF-8")
	}
	parser.totalBytes += int64(len(data))
	return data, info, nil
}

func readConfigurationFile(ctx context.Context, file *os.File, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = file.Close() })
	defer stop()
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return data, err
}

type logicalLine struct {
	line int
	text string
}

func logicalLines(path string, data []byte, maxBytes int) ([]logicalLine, error) {
	// A final newline terminates a physical line; it is not an extra empty
	// line capable of satisfying a dangling backslash continuation.
	physical := strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), "\n")
	lines := make([]logicalLine, 0, len(physical))
	var current strings.Builder
	startLine := 0
	explicitContinuation := false
	flush := func() {
		if startLine == 0 {
			return
		}
		lines = append(lines, logicalLine{line: startLine, text: current.String()})
		current.Reset()
		startLine = 0
	}
	for index, raw := range physical {
		lineNumber := index + 1
		if strings.HasSuffix(raw, "\r") {
			raw = strings.TrimSuffix(raw, "\r")
		}
		leadingContinuation := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		if startLine == 0 {
			if leadingContinuation {
				return nil, sourceError(Position{Path: path, Line: lineNumber},
					errors.New("continuation line has no preceding directive"))
			}
			startLine = lineNumber
		} else if !explicitContinuation && !leadingContinuation {
			flush()
			startLine = lineNumber
		}
		if leadingContinuation && !explicitContinuation {
			raw = " " + raw[1:]
		}
		if current.Len()+len(raw) > maxBytes {
			return nil, sourceError(Position{Path: path, Line: startLine}, fmt.Errorf(
				"logical line exceeds %d bytes", maxBytes,
			))
		}
		if hasUnescapedTrailingBackslash(raw) {
			current.WriteString(raw[:len(raw)-1])
			explicitContinuation = true
			continue
		}
		current.WriteString(raw)
		explicitContinuation = false
	}
	if explicitContinuation {
		return nil, sourceError(Position{Path: path, Line: startLine},
			errors.New("unterminated backslash continuation"))
	}
	flush()
	return lines, nil
}

func hasUnescapedTrailingBackslash(value string) bool {
	count := 0
	for index := len(value) - 1; index >= 0 && value[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

func splitArguments(line string) ([]string, error) {
	var arguments []string
	var token strings.Builder
	inQuote := false
	escaped := false
	haveToken := false
	flush := func() {
		if !haveToken {
			return
		}
		arguments = append(arguments, token.String())
		token.Reset()
		haveToken = false
	}
	for _, character := range line {
		if escaped {
			token.WriteRune(character)
			haveToken = true
			escaped = false
			continue
		}
		switch character {
		case '\\':
			escaped = true
			haveToken = true
		case '"':
			inQuote = !inQuote
			haveToken = true
		case ' ', '\t':
			if inQuote {
				token.WriteRune(character)
				haveToken = true
			} else {
				flush()
			}
		default:
			token.WriteRune(character)
			haveToken = true
		}
	}
	if escaped {
		return nil, errors.New("unterminated escape")
	}
	if inQuote {
		return nil, errors.New("unterminated quoted string")
	}
	flush()
	return arguments, nil
}

func sourceError(position Position, err error) error {
	if err == nil {
		return nil
	}
	var existing *ParseError
	if errors.As(err, &existing) {
		return err
	}
	return &ParseError{Position: position, Err: err}
}
