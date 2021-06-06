package ctchecker

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

type RawTrace struct {
	idx   int
	trace string
}

type TokenType int

const (
	LP      TokenType = iota // Left Paren: (
	RP                       // Right Paren: )
	LCB                      // Left Curly Bracket: {
	RCB                      // Right Curly Bracket: }
	LSB                      // Left Square Bracket: [
	RSB                      // Right Square Bracket: ]
	COMMA                    // Comma: ,
	EQ                       // Equal: =
	MUL                      // Multiply: *
	OR                       // Or: or
	RA                       // Right Arrow: ->
	RAB                      // Right Arrow Bold: =>
	DOT                      // Dot: .
	SUB                      // Subtract: -
	ADD                      // Add: +
	DIV                      // Div: /
	DEREF                    // Dereference: &
	AT                       // At: @
	LS                       // Left Shift: <<
	NUMSIGN                  // Numsign: #
	COLON                    // Colon: :
	STR                      // String: "abc"
	INT                      // Integer: 123|0xbeef
	ID                       // Variable
	NONE
)

type Rule struct {
	expr string
	ty   TokenType
}

type Token struct {
	ty  TokenType
	val string
	pos int
}

type AST interface {
	IsNil() bool
	Serialze(bool) string
	Children() []AST
	SetND(bool)
	IsND() bool
}

type NdOp struct {
	token Token
	nd    bool
}

type NdInt struct {
	token Token
	nd    bool
}

type NdString struct {
	token Token
	nd    bool
}

type NdID struct {
	token Token
	nd    bool
}

type NdIndex struct {
	name *NdID
	idx  AST
	nd   bool
}

type NdList struct {
	v  []AST
	nd bool
}

type NdFunc struct {
	name *NdID
	args *NdList
	nd   bool
}

type NdInfixExpr struct {
	op *NdOp
	l  AST
	r  AST
	nd bool
}

type NdPrefixExpr struct {
	op *NdOp
	r  AST
	nd bool
}

type NdTrace struct {
	e     AST
	errno *NdInt
	nd    bool
}

func (n *NdOp) IsNil() bool             { return n == nil }
func (n *NdInt) IsNil() bool            { return n == nil }
func (n *NdString) IsNil() bool         { return n == nil }
func (n *NdID) IsNil() bool             { return n == nil }
func (n *NdList) IsNil() bool           { return n == nil }
func (n *NdIndex) IsNil() bool          { return n == nil }
func (n *NdFunc) IsNil() bool           { return n == nil }
func (n *NdInfixExpr) IsNil() bool      { return n == nil }
func (n *NdPrefixExpr) IsNil() bool     { return n == nil }
func (n *NdTrace) IsNil() bool          { return n == nil }
func (n *NdOp) Children() []AST         { return []AST{} }
func (n *NdInt) Children() []AST        { return []AST{} }
func (n *NdString) Children() []AST     { return []AST{} }
func (n *NdID) Children() []AST         { return []AST{} }
func (n *NdList) Children() []AST       { return append([]AST{}, n.v...) }
func (n *NdIndex) Children() []AST      { return []AST{n.name, n.idx} }
func (n *NdFunc) Children() []AST       { return []AST{n.name, n.args} }
func (n *NdInfixExpr) Children() []AST  { return []AST{n.l, n.op, n.r} }
func (n *NdPrefixExpr) Children() []AST { return []AST{n.op, n.r} }
func (n *NdTrace) Children() []AST      { return []AST{n.e, n.errno} }
func (n *NdOp) SetND(f bool)            { n.nd = f }
func (n *NdInt) SetND(f bool)           { n.nd = f }
func (n *NdString) SetND(f bool)        { n.nd = f }
func (n *NdID) SetND(f bool)            { n.nd = f }
func (n *NdList) SetND(f bool)          { n.nd = f }
func (n *NdIndex) SetND(f bool)         { n.nd = f }
func (n *NdFunc) SetND(f bool)          { n.nd = f }
func (n *NdInfixExpr) SetND(f bool)     { n.nd = f }
func (n *NdPrefixExpr) SetND(f bool)    { n.nd = f }
func (n *NdTrace) SetND(f bool)         { n.nd = f }
func (n *NdOp) IsND() bool              { return n.nd }
func (n *NdInt) IsND() bool             { return n.nd }
func (n *NdString) IsND() bool          { return n.nd }
func (n *NdID) IsND() bool              { return n.nd }
func (n *NdList) IsND() bool            { return n.nd }
func (n *NdIndex) IsND() bool           { return n.nd }
func (n *NdFunc) IsND() bool            { return n.nd }
func (n *NdInfixExpr) IsND() bool       { return n.nd }
func (n *NdPrefixExpr) IsND() bool      { return n.nd }
func (n *NdTrace) IsND() bool           { return n.nd }

const ndPlaceHolder = "ND"

func (n *NdString) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.token.val
}
func (n *NdInt) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.token.val
}
func (n *NdOp) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.token.val
}
func (n *NdID) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.token.val
}
func (n *NdIndex) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.name.Serialze(dtm) + `[` + n.idx.Serialze(dtm) + `]`
}
func (n *NdList) Serialze(dtm bool) (s string) {
	s = ""
	if dtm && n.IsND() {
		s = ndPlaceHolder
		return
	}
	if n.IsNil() {
		return
	}
	s += `{`
	for _, e := range n.v {
		s += e.Serialze(dtm) + `, `
	}
	s += `}`
	return
}
func (n *NdFunc) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.name.Serialze(dtm) + `(` + n.args.Serialze(dtm) + `)`
}
func (n *NdInfixExpr) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.l.Serialze(dtm) + n.op.Serialze(dtm) + n.r.Serialze(dtm)
}
func (n *NdPrefixExpr) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.op.Serialze(dtm) + n.r.Serialze(dtm)
}
func (n *NdTrace) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.e.Serialze(dtm) + ` {` + n.errno.Serialze(dtm) + `}`
}

type TokenStream struct {
	t   []Token
	pos int
}

type ProgTrace struct {
	raw    []RawTrace
	traces []*NdTrace
}

func (s *TokenStream) end() bool {
	return s.pos == len(s.t)
}

func (s *TokenStream) pop() (tk Token, err error) {
	if s.pos >= len(s.t) {
		err = fmt.Errorf("Token stream out of bound")
		return
	}
	tk = s.t[s.pos]
	s.pos++
	return
}

func (s *TokenStream) top() (tk Token, err error) {
	if s.pos >= len(s.t) {
		err = fmt.Errorf("Token stream out of bound")
		return
	}
	return s.t[s.pos], nil
}

func getList(s *TokenStream, lty, rty TokenType) (e *NdList, err error) {
	var nxt Token
	e = nil
	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty == lty {
		s.pop()
	} else {
		return
	}
	var l []AST
	for {
		var exp AST
		exp, err = getExpr(s)
		if err != nil {
			return
		}
		if exp.IsNil() {
			break
		}
		l = append(l, exp)
		nxt, err = s.top()
		if err != nil {
			return
		}
		if nxt.ty == COMMA {
			s.pop()
		}
	}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	if nxt.ty != rty {
		err = fmt.Errorf("List paren/bracket does not match")
		return
	}
	e = &NdList{v: l}

	return
}

// TODO: think about if we should merge index into list
func getFuncOrIDOrIndex(s *TokenStream) (e AST, err error) {
	var nilptr *NdFunc = nil
	var nxt Token
	e = nilptr

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty != ID {
		return
	}

	nxt, err = s.pop()
	if err != nil {
		return
	}
	ndID := &NdID{token: nxt}
	if s.end() {
		e = ndID
		return
	}
	pos := s.pos
	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty == LSB {
		s.pop()
		var exp AST
		exp, err = getExpr(s)
		if exp.IsNil() {
			s.pos = pos
		} else {
			nxt, err = s.top()
			if err != nil {
				return
			}
			if nxt.ty == RSB {
				s.pop()
				e = &NdIndex{name: ndID, idx: exp}
				return
			} else {
				// a expression like this could be possible?
				// [a [1 2] ]
				// thus we do not report error
				s.pos = pos
			}
		}
	}
	var l *NdList
	l, err = getList(s, LP, RP)
	if err != nil {
		return
	}
	if l == nil {
		e = ndID
		return
	}
	e = &NdFunc{name: ndID, args: l}
	return
}
func getString(s *TokenStream) (e *NdString, err error) {
	var nxt Token
	e = nil

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty == STR {
		nxt, err = s.pop()
		if err != nil {
			return
		}
		e = &NdString{token: nxt}
	}
	return
}
func getInt(s *TokenStream) (e *NdInt, err error) {
	var nxt Token
	e = nil

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty == INT {
		nxt, err = s.pop()
		if err != nil {
			return
		}
		e = &NdInt{token: nxt}
	}
	return
}
func getInfixExpr(s *TokenStream) (e AST, err error) {
	var nxt Token
	var nilptr *NdInfixExpr = nil
	e = nilptr

	var l, r AST
	var inOp *NdOp

	l, err = getInt(s)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getString(s)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getFuncOrIDOrIndex(s)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getList(s, LSB, RSB)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getList(s, LCB, RCB)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	return

MATCH_L:
	if s.end() {
		e = l
		return
	}
	nxt, err = s.top()
	if err != nil {
		return
	}
	switch nxt.ty {
	case ADD, SUB, MUL, DIV, OR, EQ, RA, RAB, LS:
		nxt, err = s.pop()
		if err != nil {
			return
		}
		inOp = &NdOp{token: nxt}
	default:
		e = l
		return
	}

	r, err = getExpr(s)
	if r.IsNil() {
		return
	}
	e = &NdInfixExpr{
		op: inOp,
		l:  l,
		r:  r,
	}
	return
}
func getPrefixExpr(s *TokenStream) (e *NdPrefixExpr, err error) {
	var nxt Token
	e = nil

	var preOp NdOp
	var r AST

	nxt, err = s.top()
	if err != nil {
		return
	}
	switch nxt.ty {
	case SUB, DEREF, AT:
		nxt, err = s.pop()
		if err != nil {
			return
		}
		preOp = NdOp{token: nxt}
	default:
		return
	}
	r, err = getExpr(s)
	if r.IsNil() {
		if err == nil {
			err = fmt.Errorf("Prefix expression: expected expression!")
		}
		return
	}
	e = &NdPrefixExpr{
		op: &preOp,
		r:  r,
	}
	return
}
func getExpr(s *TokenStream) (e AST, err error) {
	var nxt Token
	var nilptr *NdInfixExpr = nil
	e = nilptr

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty == LP {
		s.pop()
		e, err = getExpr(s)
		if err != nil {
			return
		}
		if e.IsNil() {
			err = fmt.Errorf("Cannot match expression after '('")
			return
		}
		nxt, err = s.pop()
		if err != nil {
			return
		}
		if nxt.ty != RP {
			err = fmt.Errorf("Expecting ')'!")
			return
		}
		return
	}
	e, err = getInfixExpr(s)
	if err != nil || !e.IsNil() {
		return
	}
	e, err = getPrefixExpr(s)
	if err != nil || !e.IsNil() {
		return
	}

	return
}

func Parse(s *TokenStream) (t *NdTrace, err error) {
	var nxt Token
	var e AST
	e, err = getExpr(s)
	if err != nil {
		return
	}

	if e.IsNil() {
		err = fmt.Errorf("Syscall trace: cannot match expression!")
		return
	}
	t = &NdTrace{e: e}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	if nxt.ty != LCB {
		err = fmt.Errorf("Syscall trace: expected '{' for errno")
		return
	}
	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.ty != INT {
		err = fmt.Errorf("Syscall trace: expected integer errno")
		return
	}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	errno := &NdInt{token: nxt}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	if nxt.ty != RCB {
		err = fmt.Errorf("Syscall trace: expected '}' for errno")
		return
	}
	t.errno = errno

	return
}

// In init, all regex expressions will add a `^`
var rules = []Rule{
	{`[ \n\t\r]+`, NONE},
	{`\.\.\.`, NONE},
	// observed case: ioctl(3, SIOCGIFCONF, {ifc_len=2 * sizeof(struct ifreq), ifc_buf=NULL}) = 0
	{`struct`, NONE}, // ignore struct keyword
	{`/\*.*?\*/`, NONE},
	// restart_syscall(<... resuming interrupted system call ...>) = -1 (4)
	{`<\.\.\..*?\.\.\.>`, NONE},
	{`\(`, LP},
	{`\)`, RP},
	{`{`, LCB},
	{`}`, RCB},
	{`\[`, LSB},
	{`\]`, RSB},
	{`,`, COMMA},
	// observed that in some ioctl traces there is '{x=y, ...} => {m=n, ...}'
	{`=>`, RAB},
	{`=`, EQ},
	{`\*`, MUL},
	{`or`, OR},
	{`\|`, OR},
	{`->`, RA},
	{`\.`, DOT},
	{`\-`, SUB},
	{`\+`, ADD},
	{`/`, DIV},
	{`&`, DEREF},
	// observed case: sun_path=@"..."
	{`@`, AT},
	{`<<`, LS},
	{`#`, NUMSIGN},
	// 0x1234
	{`0x[\dA-Fa-f]+\b|\d+\b`, INT},
	// "xxxx", "xyz\d\"abc"
	{`\"(\\.|[^\"\\])*\"`, STR},
	// 'xxxx'
	{`\'(\\.|[^\'\\])*\'`, STR},
	// abc_def
	{`[a-zA-Z_][a-zA-Z0-9_]*`, ID},
	// , cmsg_data=???
	{`\?\?\?`, ID},
}

var regexprs []*regexp.Regexp

func init() {
	for _, rule := range rules {
		regexprs = append(regexprs, regexp.MustCompile(`^(`+rule.expr+`)`))
	}
}

func Lex(s string) (ts *TokenStream, err error) {
	var t []Token
	pos := 0
	l := len(s)
	for pos < l {
		match := false
		for i, re := range regexprs {
			v := re.FindString(s[pos:])
			if len(v) > 0 {
				if rules[i].ty != NONE {
					t = append(t,
						Token{
							ty:  rules[i].ty,
							pos: pos,
							val: v,
						})
				}
				pos += len(v)
				match = true
				break
			}
		}
		if !match {
			err = fmt.Errorf("Match fail: %v ...\n", s[pos:pos+15])
			return
		}
	}
	ts = &TokenStream{
		t:   t,
		pos: 0,
	}
	return
}

func BufTrailingZero(buf []byte) (z int) {
	// Find terminiated position
	z = len(buf)
	for i := 0; i < len(buf); i++ {
		if int(buf[i]) == 0 {
			z = i
			break
		}
	}
	return
}

func DeserizeThreadTrace(buf []byte) (t []RawTrace, err error) {
	// Find terminiated position
	z := BufTrailingZero(buf)

	// Buf must has a zero end
	if z == len(buf) {
		err = fmt.Errorf("Cannot find terminated 0!")
		return
	}

	if z == 0 {
		return
	}
	traceLines := strings.Split(strings.Trim(string(buf[:z]), "\n\r "), "\n")

	for _, l := range traceLines {
		var idx int
		ll := strings.SplitN(l, ":", 2)
		if len(ll) != 2 {
			err = fmt.Errorf("Cannot find index: %v", l)
			return
		}
		idx, err = strconv.Atoi(ll[0])
		if err != nil {
			return
		}
		t = append(t, RawTrace{idx: idx, trace: ll[1]})
	}

	return
}

func DeserizeTraceBuf(bufs [][]byte) (t []RawTrace, err error) {
	for _, buf := range bufs {
		var tt []RawTrace
		tt, err = DeserizeThreadTrace(buf)
		if err != nil {
			return
		}
		t = append(t, tt...)
	}
	sort.Slice(t, func(i, j int) bool {
		return t[i].idx < t[j].idx
	})
	return
}

func TraceNDUpdate(cand, b AST) (updated bool) {
	if cand.IsND() {
		return false
	}
	if reflect.TypeOf(cand) != reflect.TypeOf(b) {
		cand.SetND(true)
		return true
	}
	candChildren, bChildren := cand.Children(), b.Children()
	// E.g. NDList
	if len(candChildren) != len(bChildren) {
		cand.SetND(true)
		return true
	}
	if len(candChildren) == 0 {
		switch cand.(type) {
		case *NdOp:
			nc, nb := cand.(*NdOp), b.(*NdOp)
			if nc.token.val != nb.token.val {
				nc.SetND(true)
				return true
			}
		case *NdInt:
			nc, nb := cand.(*NdInt), b.(*NdInt)
			if nc.token.val != nb.token.val {
				nc.SetND(true)
				return true
			}
		case *NdString:
			nc, nb := cand.(*NdString), b.(*NdString)
			if nc.token.val != nb.token.val {
				nc.SetND(true)
				return true
			}
		case *NdID:
			nc, nb := cand.(*NdID), b.(*NdID)
			if nc.token.val != nb.token.val {
				nc.SetND(true)
				return true
			}
		default:
			// should not go here!
		}
		return false
	}
	for i, ac := range candChildren {
		updated = updated || TraceNDUpdate(ac, bChildren[i])
	}
	return updated
}

func TraceNDEqual(cand, b AST) (equal bool, reason string) {
	if cand.IsND() {
		return true, ""
	}
	if reflect.TypeOf(cand) != reflect.TypeOf(b) {
		return false, fmt.Sprintf("Type:\nCandidate trace:\n%v\nTest trace:\n%v\n", cand.Serialze(false), b.Serialze(false))
	}
	candChildren, bChildren := cand.Children(), b.Children()
	// E.g. NDList
	if len(candChildren) != len(bChildren) {
		return false, fmt.Sprintf("Children counts:\nCandidate trace:\n%v\nTest trace:\n%v\n", cand.Serialze(false), b.Serialze(false))
	}
	if len(candChildren) == 0 {
		switch cand.(type) {
		case *NdOp:
			nc, nb := cand.(*NdOp), b.(*NdOp)
			if nc.token.val != nb.token.val {
				return false, fmt.Sprintf("Token value:\nCandidate trace:\n%v\nTest trace:\n%v\n", cand.Serialze(false), b.Serialze(false))
			}
		case *NdInt:
			nc, nb := cand.(*NdInt), b.(*NdInt)
			if nc.token.val != nb.token.val {
				return false, fmt.Sprintf("Token value:\nCandidate trace:\n%v\nTest trace:\n%v\n", cand.Serialze(false), b.Serialze(false))
			}
		case *NdString:
			nc, nb := cand.(*NdString), b.(*NdString)
			if nc.token.val != nb.token.val {
				return false, fmt.Sprintf("Token value:\nCandidate trace:\n%v\nTest trace:\n%v\n", cand.Serialze(false), b.Serialze(false))
			}
		case *NdID:
			nc, nb := cand.(*NdID), b.(*NdID)
			if nc.token.val != nb.token.val {
				return false, fmt.Sprintf("Token value:\nCandidate trace:\n%v\nTest trace:\n%v\n", cand.Serialze(false), b.Serialze(false))
			}
		default:
			// should not go here!
		}
		return true, ""
	}
	for i, ac := range candChildren {
		equal, reason = TraceNDEqual(ac, bChildren[i])
		if !equal {
			return
		}
	}
	return true, ""
}

func ProgTraceNDEqual(a, b *ProgTrace) (equal bool, reason string) {
	if len(a.traces) != len(b.traces) {
		return false, fmt.Sprintf("Number of traces %v & %v not match.", len(a.traces), len(b.traces))
	}
	for i, ta := range a.traces {
		equal, reason = TraceNDEqual(ta, b.traces[i])
		if !equal {
			reason = fmt.Sprintf("Trace #%v:\n", i) + reason
			return
		}
	}
	return true, ""
}

func ProgTraceNDUpdate(cand *ProgTrace, b *ProgTrace) (nomatch bool, updated bool) {
	if len(cand.traces) != len(b.traces) {
		nomatch = true
		return
	}

	for i, ta := range cand.traces {
		updated = updated || TraceNDUpdate(ta, b.traces[i])
	}
	return
}

func ParseTrace(buf [][]byte) (trace *ProgTrace, err error) {
	var rawTraces []RawTrace
	var ts *TokenStream
	var traceLine *NdTrace
	rawTraces, err = DeserizeTraceBuf(buf)
	if err != nil {
		return
	}
	trace = &ProgTrace{raw: rawTraces}
	log.Logf(4, "Raw trace:\n%v\n", string(trace.RawSerialze()))
	for _, raw := range rawTraces {
		ts, err = Lex(raw.trace)
		if err != nil {
			return
		}
		traceLine, err = Parse(ts)
		if err != nil {
			err = fmt.Errorf("When parsing syscall trace:\n%v\nFound error:\n%v", raw.trace, err)
			return
		}
		trace.traces = append(trace.traces, traceLine)
	}
	return

}

func (trace *ProgTrace) RawSerialze() []byte {
	buf := new(bytes.Buffer)
	for _, r := range trace.raw {
		fmt.Fprintf(buf, "%v: %v\n", r.idx, r.trace)
	}
	return buf.Bytes()
}

func (trace *ProgTrace) DeterminSerialze() []byte {
	buf := new(bytes.Buffer)
	for i, t := range trace.traces {
		fmt.Fprintf(buf, "%v: %v\n", i, t.Serialze(true))
	}
	return buf.Bytes()
}
