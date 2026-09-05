// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls12

import (
	"bytes"
	"crypto/fips140"
	"crypto/sha256"
	"hash"
	"testing"
)

// concreteHash exercises the generic API with a constructor whose return type
// is not exactly func() hash.Hash.
type concreteHash struct {
	hash.Hash
}

func newConcreteHash() *concreteHash {
	return &concreteHash{Hash: sha256.New()}
}

func TestPRFConcreteHashConstructor(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("custom hash wrappers are not approved in strict FIPS mode")
	}
	secret := []byte("secret key material")
	seed := []byte("seed")
	want := PRF(func() hash.Hash { return sha256.New() }, secret, "label", seed, 97)
	got := PRF(newConcreteHash, secret, "label", seed, 97)
	if !bytes.Equal(got, want) {
		t.Fatalf("PRF mismatch: got %x, want %x", got, want)
	}
}
