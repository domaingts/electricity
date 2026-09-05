// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package godebug

import "testing"

func TestSettingValueAndName(t *testing.T) {
	setting := New("foo")
	for _, test := range []struct {
		godebug string
		want    string
	}{
		{"", ""},
		{"foo=bar", "bar"},
		{"before=x,foo=bar,after=x", "bar"},
		{"foo=first,foo=last", "last"},
		{"foo", ""},
		{"foo=bar,baz", "bar"},
	} {
		t.Setenv("GODEBUG", test.godebug)
		if got := setting.Value(); got != test.want {
			t.Errorf("Value(%q) = %q, want %q", test.godebug, got, test.want)
		}
	}

	t.Setenv("GODEBUG", "foo=bar")
	undocumented := New("#foo")
	if got := undocumented.Name(); got != "foo" {
		t.Errorf("Name() = %q, want foo", got)
	}
	if !undocumented.Undocumented() {
		t.Error("Undocumented() = false, want true")
	}
	if got := undocumented.Value(); got != "bar" {
		t.Errorf("undocumented Value() = %q, want bar", got)
	}
	if got := undocumented.String(); got != "foo=bar" {
		t.Errorf("String() = %q, want foo=bar", got)
	}
}
