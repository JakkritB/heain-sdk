package heain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonical returns the RFC 8785 (JCS) form of v: v is marshalled with
// encoding/json, then re-serialised with sorted keys (by UTF-16 code
// units), no insignificant whitespace, minimal string escaping and ES6
// number formatting. Decided 2026-10-05 for reasoning-record signatures.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := writeJCS(&b, x); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeJCS(b *bytes.Buffer, x any) error {
	switch t := x.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return fmt.Errorf("jcs: number %q", t)
		}
		b.WriteString(es6Number(f))
	case string:
		writeJCSString(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJCSString(b, k)
			b.WriteByte(':')
			if err := writeJCS(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unexpected %T", x)
	}
	return nil
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeJCSString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// es6Number formats f as ECMAScript Number.prototype.toString does:
// plain notation for 1e-6 <= |f| < 1e21, otherwise d.ddde±n.
func es6Number(f float64) string {
	if f == 0 {
		return "0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // shortest round-trip digits
	i := strings.IndexByte(e, 'e')
	mant, exp := e[:i], e[i+1:]
	n, _ := strconv.Atoi(exp)
	if n >= -6 && n < 21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	sign := "+"
	if n < 0 {
		sign, n = "-", -n
	}
	return mant + "e" + sign + strconv.Itoa(n)
}
