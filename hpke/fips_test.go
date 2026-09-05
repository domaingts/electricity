// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"testing"

	"github.com/xtls/reality/hpke"
)

func TestP256RoundTripInStrictFIPSMode(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("requires GODEBUG=fips140=only")
	}

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := hpke.NewDHKEMPublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES128GCM(), nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := hpke.NewDHKEMPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.NewRecipient(enc, recipientKey, hpke.HKDFSHA256(), hpke.AES128GCM(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("strict FIPS HPKE")
	ciphertext, err := sender.Seal(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := recipient.Open(nil, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}
