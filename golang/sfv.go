package httpsig

// Structured Field Values subset for HTTP Message Signatures (RFC 8941).
// Only implements what RFC 9421 needs: Dictionary, Inner List, Items, Parameters.

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// SFVItem is a single item in a Structured Field Value.
type SFVItem struct {
	Value  any // string, int64, []byte (binary), bool, Token
	Params *SFVParams
}

// Token is an SFV token (unquoted identifier).
type Token string

// SFVParams is an ordered parameter map.
type SFVParams struct {
	Keys   []string
	Values map[string]any // string, int64, bool, Token, []byte
}

func NewSFVParams() *SFVParams {
	return &SFVParams{Values: make(map[string]any)}
}

func (p *SFVParams) Set(key string, value any) {
	if _, exists := p.Values[key]; !exists {
		p.Keys = append(p.Keys, key)
	}
	p.Values[key] = value
}

func (p *SFVParams) Get(key string) (any, bool) {
	v, ok := p.Values[key]
	return v, ok
}

func (p *SFVParams) Len() int {
	if p == nil {
		return 0
	}
	return len(p.Keys)
}

// SFVInnerList is an inner list with parameters.
type SFVInnerList struct {
	Items  []SFVItem
	Params *SFVParams
}

// SFVDictMember is one member of a dictionary.
type SFVDictMember struct {
	Key       string
	InnerList *SFVInnerList // non-nil if this member is an inner list
	Item      *SFVItem      // non-nil if this member is a single item
}

// --- Serialization ---

// SerializeSignatureParams serializes signature parameters as they appear in
// the Signature-Input header value for a single label. Output looks like:
// ("@method" "@path" "content-type");created=1618884473;keyid="test-key"
func SerializeSignatureParams(components []ComponentIdentifier, params *SFVParams) string {
	var b strings.Builder

	// Inner list of component identifiers
	b.WriteByte('(')
	for i, c := range components {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(serializeComponentID(c))
	}
	b.WriteByte(')')

	// Parameters
	if params != nil {
		for _, key := range params.Keys {
			b.WriteByte(';')
			b.WriteString(key)
			val := params.Values[key]
			if boolVal, ok := val.(bool); ok && boolVal {
				// bare boolean true is just the key with no =value
				continue
			}
			b.WriteByte('=')
			b.WriteString(serializeBareItem(val))
		}
	}

	return b.String()
}

func serializeComponentID(c ComponentIdentifier) string {
	var b strings.Builder
	b.WriteString(serializeString(c.Name))
	if c.Params != nil {
		for _, key := range c.Params.Keys {
			b.WriteByte(';')
			b.WriteString(key)
			val := c.Params.Values[key]
			if boolVal, ok := val.(bool); ok && boolVal {
				continue
			}
			b.WriteByte('=')
			b.WriteString(serializeBareItem(val))
		}
	}
	return b.String()
}

func serializeString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		if c == '\\' || c == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	b.WriteByte('"')
	return b.String()
}

func serializeBareItem(v any) string {
	switch val := v.(type) {
	case string:
		return serializeString(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case int:
		return strconv.Itoa(val)
	case bool:
		if val {
			return "?1"
		}
		return "?0"
	case []byte:
		return ":" + base64.StdEncoding.EncodeToString(val) + ":"
	case Token:
		return string(val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// SerializeDictionary serializes a dictionary for a response header.
// Each member is label=inner-list or label=item.
func SerializeDictionary(members []SFVDictMember) string {
	var parts []string
	for _, m := range members {
		var b strings.Builder
		b.WriteString(m.Key)
		b.WriteByte('=')
		if m.InnerList != nil {
			b.WriteString(serializeInnerList(m.InnerList))
		} else if m.Item != nil {
			b.WriteString(serializeBareItem(m.Item.Value))
			if m.Item.Params != nil && m.Item.Params.Len() > 0 {
				b.WriteString(serializeParams(m.Item.Params))
			}
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, ", ")
}

func serializeInnerList(il *SFVInnerList) string {
	var b strings.Builder
	b.WriteByte('(')
	for i, item := range il.Items {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(serializeBareItem(item.Value))
		if item.Params != nil && item.Params.Len() > 0 {
			b.WriteString(serializeParams(item.Params))
		}
	}
	b.WriteByte(')')
	if il.Params != nil && il.Params.Len() > 0 {
		b.WriteString(serializeParams(il.Params))
	}
	return b.String()
}

func serializeParams(p *SFVParams) string {
	var b strings.Builder
	for _, key := range p.Keys {
		b.WriteByte(';')
		b.WriteString(key)
		val := p.Values[key]
		if boolVal, ok := val.(bool); ok && boolVal {
			continue
		}
		b.WriteByte('=')
		b.WriteString(serializeBareItem(val))
	}
	return b.String()
}

// --- Parsing ---

type sfvParser struct {
	input string
	pos   int
}

func (p *sfvParser) peek() (byte, bool) {
	if p.pos >= len(p.input) {
		return 0, false
	}
	return p.input[p.pos], true
}

func (p *sfvParser) advance() {
	p.pos++
}

func (p *sfvParser) skipSP() {
	for p.pos < len(p.input) && p.input[p.pos] == ' ' {
		p.pos++
	}
}

func (p *sfvParser) skipOWS() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t') {
		p.pos++
	}
}

// ParseDictionary parses a Structured Field Values Dictionary (RFC 8941 Section 4.2.2).
func ParseDictionary(input string) ([]SFVDictMember, error) {
	p := &sfvParser{input: strings.TrimSpace(input)}
	var members []SFVDictMember

	for p.pos < len(p.input) {
		m, err := p.parseDictMember()
		if err != nil {
			return nil, err
		}
		members = append(members, m)

		p.skipOWS()
		if p.pos >= len(p.input) {
			break
		}
		ch, _ := p.peek()
		if ch != ',' {
			return nil, fmt.Errorf("sfv: expected ',' at position %d", p.pos)
		}
		p.advance()
		p.skipOWS()
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("sfv: trailing comma")
		}
	}

	return members, nil
}

func (p *sfvParser) parseDictMember() (SFVDictMember, error) {
	key, err := p.parseKey()
	if err != nil {
		return SFVDictMember{}, err
	}

	ch, ok := p.peek()
	if !ok || ch != '=' {
		// bare item (boolean true) with possible parameters
		params, err := p.parseParams()
		if err != nil {
			return SFVDictMember{}, err
		}
		return SFVDictMember{
			Key:  key,
			Item: &SFVItem{Value: true, Params: params},
		}, nil
	}
	p.advance() // skip '='

	ch, ok = p.peek()
	if ok && ch == '(' {
		il, err := p.parseInnerList()
		if err != nil {
			return SFVDictMember{}, err
		}
		return SFVDictMember{Key: key, InnerList: il}, nil
	}

	item, err := p.parseItem()
	if err != nil {
		return SFVDictMember{}, err
	}
	return SFVDictMember{Key: key, Item: &item}, nil
}

func (p *sfvParser) parseKey() (string, error) {
	start := p.pos
	if p.pos >= len(p.input) {
		return "", fmt.Errorf("sfv: expected key at position %d", p.pos)
	}
	ch := p.input[p.pos]
	if ch != '*' && !(ch >= 'a' && ch <= 'z') {
		return "", fmt.Errorf("sfv: invalid key start '%c' at position %d", ch, p.pos)
	}
	p.advance()
	for p.pos < len(p.input) {
		ch = p.input[p.pos]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == '*' {
			p.advance()
		} else {
			break
		}
	}
	return p.input[start:p.pos], nil
}

func (p *sfvParser) parseInnerList() (*SFVInnerList, error) {
	ch, ok := p.peek()
	if !ok || ch != '(' {
		return nil, fmt.Errorf("sfv: expected '(' at position %d", p.pos)
	}
	p.advance()

	var items []SFVItem
	for {
		p.skipSP()
		ch, ok = p.peek()
		if !ok {
			return nil, fmt.Errorf("sfv: unterminated inner list")
		}
		if ch == ')' {
			p.advance()
			break
		}
		item, err := p.parseItem()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	params, err := p.parseParams()
	if err != nil {
		return nil, err
	}
	return &SFVInnerList{Items: items, Params: params}, nil
}

func (p *sfvParser) parseItem() (SFVItem, error) {
	val, err := p.parseBareItem()
	if err != nil {
		return SFVItem{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return SFVItem{}, err
	}
	return SFVItem{Value: val, Params: params}, nil
}

func (p *sfvParser) parseBareItem() (any, error) {
	ch, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("sfv: unexpected end of input")
	}
	switch {
	case ch == '"':
		return p.parseString()
	case ch == ':':
		return p.parseBinary()
	case ch == '?':
		return p.parseBoolean()
	case ch == '-' || (ch >= '0' && ch <= '9'):
		return p.parseNumber()
	case ch == '*' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'):
		return p.parseToken()
	default:
		return nil, fmt.Errorf("sfv: unexpected character '%c' at position %d", ch, p.pos)
	}
}

func (p *sfvParser) parseString() (string, error) {
	if p.pos >= len(p.input) || p.input[p.pos] != '"' {
		return "", fmt.Errorf("sfv: expected '\"'")
	}
	p.advance()
	var b strings.Builder
	for {
		if p.pos >= len(p.input) {
			return "", fmt.Errorf("sfv: unterminated string")
		}
		ch := p.input[p.pos]
		if ch == '"' {
			p.advance()
			return b.String(), nil
		}
		if ch == '\\' {
			p.advance()
			if p.pos >= len(p.input) {
				return "", fmt.Errorf("sfv: unterminated escape")
			}
			escaped := p.input[p.pos]
			if escaped != '"' && escaped != '\\' {
				return "", fmt.Errorf("sfv: invalid escape '\\%c'", escaped)
			}
			b.WriteByte(escaped)
			p.advance()
			continue
		}
		if ch < 0x20 || ch > 0x7e {
			return "", fmt.Errorf("sfv: invalid character in string at position %d", p.pos)
		}
		b.WriteByte(ch)
		p.advance()
	}
}

func (p *sfvParser) parseBinary() ([]byte, error) {
	if p.pos >= len(p.input) || p.input[p.pos] != ':' {
		return nil, fmt.Errorf("sfv: expected ':'")
	}
	p.advance()
	end := strings.IndexByte(p.input[p.pos:], ':')
	if end < 0 {
		return nil, fmt.Errorf("sfv: unterminated binary sequence")
	}
	b64 := p.input[p.pos : p.pos+end]
	p.pos += end + 1
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("sfv: invalid base64: %w", err)
	}
	return data, nil
}

func (p *sfvParser) parseBoolean() (bool, error) {
	if p.pos >= len(p.input) || p.input[p.pos] != '?' {
		return false, fmt.Errorf("sfv: expected '?'")
	}
	p.advance()
	ch, ok := p.peek()
	if !ok {
		return false, fmt.Errorf("sfv: expected '0' or '1'")
	}
	p.advance()
	switch ch {
	case '1':
		return true, nil
	case '0':
		return false, nil
	default:
		return false, fmt.Errorf("sfv: expected '0' or '1', got '%c'", ch)
	}
}

func (p *sfvParser) parseNumber() (int64, error) {
	start := p.pos
	if p.pos < len(p.input) && p.input[p.pos] == '-' {
		p.advance()
	}
	if p.pos >= len(p.input) || p.input[p.pos] < '0' || p.input[p.pos] > '9' {
		return 0, fmt.Errorf("sfv: invalid number at position %d", start)
	}
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.advance()
	}
	// Check for decimal (we'll handle as integer only for our needs)
	if p.pos < len(p.input) && p.input[p.pos] == '.' {
		return 0, fmt.Errorf("sfv: decimal numbers not supported in this subset")
	}
	n, err := strconv.ParseInt(p.input[start:p.pos], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("sfv: %w", err)
	}
	return n, nil
}

func (p *sfvParser) parseToken() (Token, error) {
	start := p.pos
	ch := p.input[p.pos]
	if ch != '*' && !unicode.IsLetter(rune(ch)) {
		return "", fmt.Errorf("sfv: invalid token start '%c' at position %d", ch, p.pos)
	}
	p.advance()
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '_' || ch == '-' || ch == '.' || ch == '*' || ch == ':' || ch == '/' {
			p.advance()
		} else {
			break
		}
	}
	return Token(p.input[start:p.pos]), nil
}

func (p *sfvParser) parseParams() (*SFVParams, error) {
	params := NewSFVParams()
	for p.pos < len(p.input) && p.input[p.pos] == ';' {
		p.advance()
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var val any = true
		if p.pos < len(p.input) && p.input[p.pos] == '=' {
			p.advance()
			val, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		params.Set(key, val)
	}
	if params.Len() == 0 {
		return nil, nil
	}
	return params, nil
}
