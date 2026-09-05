// Package godebug provides the small subset of GODEBUG settings used by
// the forked TLS implementation.
package godebug

import (
	"os"
	"strings"
)

// Setting represents one name in the GODEBUG environment variable.
type Setting struct {
	name string
}

// New returns a setting for name.
func New(name string) *Setting {
	return &Setting{name: name}
}

// Name returns the setting name. A leading # marks an undocumented setting and
// is not part of the name used in GODEBUG.
func (s *Setting) Name() string {
	if strings.HasPrefix(s.name, "#") {
		return s.name[1:]
	}
	return s.name
}

// Undocumented reports whether the setting was created with a leading #.
func (s *Setting) Undocumented() bool {
	return strings.HasPrefix(s.name, "#")
}

// String returns the setting in name=value form.
func (s *Setting) String() string {
	return s.Name() + "=" + s.Value()
}

// Value returns the current value of the setting. An unset setting returns the
// empty string, matching internal/godebug's representation of a setting with
// no explicit environment override.
func (s *Setting) Value() string {
	value := ""
	for _, field := range strings.Split(os.Getenv("GODEBUG"), ",") {
		name, v, ok := strings.Cut(field, "=")
		if ok && name == s.Name() {
			value = v
		}
	}
	return value
}

// IncNonDefault is a compatibility hook for the runtime metrics maintained by
// the standard library's internal/godebug package. External modules cannot
// register those internal metrics, so this implementation intentionally does
// nothing.
func (s *Setting) IncNonDefault() {}
