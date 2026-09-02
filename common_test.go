package reality

import (
	"bytes"
	"testing"
)

func TestConfigClonePreservesMldsa65Key(t *testing.T) {
	key := []byte{1, 2, 3}
	clone := (&Config{Mldsa65Key: key}).Clone()
	if clone == nil {
		t.Fatal("Config.Clone returned nil")
	}
	if !bytes.Equal(clone.Mldsa65Key, key) {
		t.Fatalf("cloned ML-DSA key = %v, want %v", clone.Mldsa65Key, key)
	}
	if &clone.Mldsa65Key[0] != &key[0] {
		t.Fatal("Config.Clone did not preserve shallow ML-DSA key semantics")
	}
}

func TestConfigCloneNil(t *testing.T) {
	var config *Config
	if config.Clone() != nil {
		t.Fatal("Config.Clone on nil receiver returned a non-nil config")
	}
}
