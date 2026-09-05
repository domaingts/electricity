// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hpke implements Hybrid Public Key Encryption (HPKE) as defined in
// [RFC 9180], using the standard library implementation.
//
// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
package hpke

import (
	"crypto"
	"crypto/ecdh"

	stdhpke "crypto/hpke"
)

// Keep the public HPKE API type-identical to crypto/hpke. This lets callers
// pass keys and contexts between the two packages without conversion.
type AEAD = stdhpke.AEAD
type KDF = stdhpke.KDF
type KEM = stdhpke.KEM
type PublicKey = stdhpke.PublicKey
type PrivateKey = stdhpke.PrivateKey
type Sender = stdhpke.Sender
type Recipient = stdhpke.Recipient

func NewAEAD(id uint16) (AEAD, error) { return stdhpke.NewAEAD(id) }
func AES128GCM() AEAD                 { return stdhpke.AES128GCM() }
func AES256GCM() AEAD                 { return stdhpke.AES256GCM() }
func ChaCha20Poly1305() AEAD          { return stdhpke.ChaCha20Poly1305() }
func ExportOnly() AEAD                { return stdhpke.ExportOnly() }

func NewKDF(id uint16) (KDF, error) { return stdhpke.NewKDF(id) }
func HKDFSHA256() KDF               { return stdhpke.HKDFSHA256() }
func HKDFSHA384() KDF               { return stdhpke.HKDFSHA384() }
func HKDFSHA512() KDF               { return stdhpke.HKDFSHA512() }
func SHAKE128() KDF                 { return stdhpke.SHAKE128() }
func SHAKE256() KDF                 { return stdhpke.SHAKE256() }

func NewKEM(id uint16) (KEM, error) { return stdhpke.NewKEM(id) }
func DHKEM(curve ecdh.Curve) KEM    { return stdhpke.DHKEM(curve) }

func MLKEM768() KEM       { return stdhpke.MLKEM768() }
func MLKEM1024() KEM      { return stdhpke.MLKEM1024() }
func MLKEM768X25519() KEM { return stdhpke.MLKEM768X25519() }
func MLKEM768P256() KEM   { return stdhpke.MLKEM768P256() }
func MLKEM1024P384() KEM  { return stdhpke.MLKEM1024P384() }

func NewDHKEMPublicKey(pub *ecdh.PublicKey) (PublicKey, error) {
	return stdhpke.NewDHKEMPublicKey(pub)
}
func NewDHKEMPrivateKey(priv ecdh.KeyExchanger) (PrivateKey, error) {
	return stdhpke.NewDHKEMPrivateKey(priv)
}
func NewHybridPublicKey(pq crypto.Encapsulator, t *ecdh.PublicKey) (PublicKey, error) {
	return stdhpke.NewHybridPublicKey(pq, t)
}
func NewHybridPrivateKey(pq crypto.Decapsulator, t ecdh.KeyExchanger) (PrivateKey, error) {
	return stdhpke.NewHybridPrivateKey(pq, t)
}
func NewMLKEMPublicKey(pub crypto.Encapsulator) (PublicKey, error) {
	return stdhpke.NewMLKEMPublicKey(pub)
}
func NewMLKEMPrivateKey(priv crypto.Decapsulator) (PrivateKey, error) {
	return stdhpke.NewMLKEMPrivateKey(priv)
}

func NewSender(pk PublicKey, kdf KDF, aead AEAD, info []byte) (enc []byte, s *Sender, err error) {
	return stdhpke.NewSender(pk, kdf, aead, info)
}
func NewRecipient(enc []byte, k PrivateKey, kdf KDF, aead AEAD, info []byte) (*Recipient, error) {
	return stdhpke.NewRecipient(enc, k, kdf, aead, info)
}
func Seal(pk PublicKey, kdf KDF, aead AEAD, info, plaintext []byte) ([]byte, error) {
	return stdhpke.Seal(pk, kdf, aead, info, plaintext)
}
func Open(k PrivateKey, kdf KDF, aead AEAD, info, ciphertext []byte) ([]byte, error) {
	return stdhpke.Open(k, kdf, aead, info, ciphertext)
}
