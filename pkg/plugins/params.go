package plugins

import "strings"

// SplitParams splits plugin params at their commas. A comma that is part of a value, as in a
// password, is escaped as \, and a backslash before a comma or another backslash as \\. Other
// backslashes are themselves.
func SplitParams(params string) []string {
	var parts []string
	var part strings.Builder
	for i := 0; i < len(params); i++ {
		c := params[i]
		switch {
		case c == '\\' && i+1 < len(params) && (params[i+1] == ',' || params[i+1] == '\\'):
			part.WriteByte(params[i+1])
			i++
		case c == ',':
			parts = append(parts, part.String())
			part.Reset()
		default:
			part.WriteByte(c)
		}
	}
	return append(parts, part.String())
}

// JoinParams joins values into plugin params, escaping them for SplitParams.
func JoinParams(values ...string) string {
	escaped := make([]string, len(values))
	for i, v := range values {
		escaped[i] = paramEscaper.Replace(v)
	}
	return strings.Join(escaped, ",")
}

var paramEscaper = strings.NewReplacer(`\`, `\\`, `,`, `\,`)
