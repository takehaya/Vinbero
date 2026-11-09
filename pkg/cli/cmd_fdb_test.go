package cli

import (
	"testing"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func TestFdbEntryType(t *testing.T) {
	cases := []struct {
		name  string
		entry *v1.FdbEntry
		want  string
	}{
		{"learned", &v1.FdbEntry{}, "dynamic"},
		{"configured", &v1.FdbEntry{IsStatic: true}, "static"},
		{"data-plane remote", &v1.FdbEntry{IsRemote: true}, "remote"},
		{"remote from BGP", &v1.FdbEntry{IsRemote: true, IsStatic: true}, "remote"},
	}
	for _, c := range cases {
		if got := fdbEntryType(c.entry); got != c.want {
			t.Errorf("%s: fdbEntryType = %q, want %q", c.name, got, c.want)
		}
	}
}
