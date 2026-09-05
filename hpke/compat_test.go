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

func TestLegacyAPI(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("legacy X25519 API is not allowed in strict FIPS mode")
	}

	var _ hpke.KemID = hpke.KemID(hpke.DHKEM_X25519_HKDF_SHA256)
	var _ hpke.KDFID = hpke.KDFID(hpke.KDF_HKDF_SHA256)
	var _ hpke.AEADID = hpke.AEADID(hpke.AEAD_AES_128_GCM)

	kdf := hpke.SupportedKDFs[hpke.KDF_HKDF_SHA256]()
	if _, err := kdf.LabeledExtract([]byte("suite"), nil, "label", []byte("input")); err != nil {
		t.Fatal(err)
	}
	if _, err := kdf.LabeledExpand([]byte("suite"), make([]byte, 32), "label", nil, 16); err != nil {
		t.Fatal(err)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.SetupSender(
		hpke.DHKEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES_128_GCM,
		privateKey.PublicKey(), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := hpke.SetupRecipient(
		hpke.DHKEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES_128_GCM,
		privateKey, nil, enc,
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("legacy API")
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
