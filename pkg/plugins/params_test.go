package plugins

import (
	"slices"
	"testing"
)

func TestSplitParams(t *testing.T) {
	for in, want := range map[string][]string{
		"60s,host,user,pass":       {"60s", "host", "user", "pass"},
		`60s,host,user,pa\,ss`:     {"60s", "host", "user", "pa,ss"},
		`60s,host,user,pa\\,ss`:    {"60s", "host", "user", `pa\`, "ss"},
		`60s,host,user,c:\keys\id`: {"60s", "host", "user", `c:\keys\id`},
		`a,,b,`:                    {"a", "", "b", ""},
		``:                         {""},
		`trailing\`:                {`trailing\`},
	} {
		if got := SplitParams(in); !slices.Equal(got, want) {
			t.Errorf("SplitParams(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzJoinParams(f *testing.F) {
	f.Add("pa,ss", `c:\keys\`, "")
	f.Add(`\,`, `\\`, ",")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		values := []string{a, b, c}
		if got := SplitParams(JoinParams(values...)); !slices.Equal(got, values) {
			t.Errorf("SplitParams(JoinParams(%q)) = %q", values, got)
		}
	})
}

func TestParseSSHConfigEscapedComma(t *testing.T) {
	cfg, err := ParseSSHConfig("linux", JoinParams("60s", "192.0.2.1", "user", "p,a\\ss", "", "SHA256:abc"))
	if err != nil || cfg.Password != `p,a\ss` || cfg.HostKey != "SHA256:abc" {
		t.Errorf("got %+v, %v", cfg, err)
	}
}
