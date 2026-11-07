package libv2ray

import "strings"

// normalizeJSONC turns a sing-box configuration written as JSONC into strict
// JSON for encoding/json: a UTF-8 byte order mark, // and /* */ comments and
// trailing commas are removed; string contents are kept as written. sing-box
// itself accepts these, so files exported by sing-box clients carry them.
func normalizeJSONC(content string) string {
	return removeJSONTrailingCommas(removeJSONComments(strings.TrimPrefix(content, "\ufeff")))
}

func removeJSONComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	inString := false
	for i := 0; i < len(src); {
		c := src[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				out.WriteByte(src[i+1])
				i += 2
				continue
			}
			if c == '"' {
				inString = false
			}
			i++
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				i = len(src)
			} else {
				i += end
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				i = len(src)
			} else {
				i += 2 + end + 2
			}
			out.WriteByte(' ')
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

func removeJSONTrailingCommas(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	inString := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				out.WriteByte(src[i+1])
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
		} else if c == ',' {
			j := i + 1
			for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
				j++
			}
			if j < len(src) && (src[j] == '}' || src[j] == ']') {
				continue
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}
