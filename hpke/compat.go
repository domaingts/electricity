package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// KemID identifies an HPKE KEM. It is retained for compatibility with the
// original reality HPKE package API.
type KemID uint16

// KDFID identifies an HPKE KDF. It is retained for compatibility with the
// original reality HPKE package API.
type KDFID uint16

// AEADID identifies an HPKE AEAD. It is retained for compatibility with the
// original reality HPKE package API.
type AEADID uint16

const (
	DHKEM_P256_HKDF_SHA256   = 0x0010
	DHKEM_P384_HKDF_SHA384   = 0x0011
	DHKEM_P521_HKDF_SHA512   = 0x0012
	DHKEM_X25519_HKDF_SHA256 = 0x0020

	KDF_HKDF_SHA256 = 0x0001
	KDF_HKDF_SHA384 = 0x0002
	KDF_HKDF_SHA512 = 0x0003

	AEAD_AES_128_GCM      = 0x0001
	AEAD_AES_256_GCM      = 0x0002
	AEAD_ChaCha20Poly1305 = 0x0003
)

// SupportedKEMs is retained for source compatibility with the pre-Go 1.27
// HPKE package. New code should use NewKEM.
var SupportedKEMs = map[uint16]struct {
	curve   ecdh.Curve
	hash    crypto.Hash
	nSecret uint16
}{
	DHKEM_P256_HKDF_SHA256:   {ecdh.P256(), crypto.SHA256, 32},
	DHKEM_P384_HKDF_SHA384:   {ecdh.P384(), crypto.SHA384, 48},
	DHKEM_P521_HKDF_SHA512:   {ecdh.P521(), crypto.SHA512, 64},
	DHKEM_X25519_HKDF_SHA256: {ecdh.X25519(), crypto.SHA256, 32},
}

// hkdfKDF is the legacy KDF representation used by SupportedKDFs. The current
// API intentionally exposes only the stdlib KDF interface, whose implementation
// methods are package-private and therefore cannot be called from this package.
type hkdfKDF struct {
	hash func() hash.Hash
}

func (kdf *hkdfKDF) LabeledExtract(suiteID []byte, salt []byte, label string, inputKey []byte) ([]byte, error) {
	labeledIKM := make([]byte, 0, 7+len(suiteID)+len(label)+len(inputKey))
	labeledIKM = append(labeledIKM, "HPKE-v1"...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, inputKey...)
	return hkdf.Extract(kdf.hash, labeledIKM, salt)
}

func (kdf *hkdfKDF) LabeledExpand(suiteID []byte, randomKey []byte, label string, info []byte, length uint16) ([]byte, error) {
	labeledInfo := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	labeledInfo = append(labeledInfo, byte(length>>8), byte(length))
	labeledInfo = append(labeledInfo, "HPKE-v1"...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(kdf.hash, randomKey, string(labeledInfo), int(length))
}

var (
	hkdfSHA256 = &hkdfKDF{hash: sha256.New}
	hkdfSHA384 = &hkdfKDF{hash: sha512.New384}
	hkdfSHA512 = &hkdfKDF{hash: sha512.New}
)

// SupportedKDFs is retained for source compatibility with the pre-Go 1.27
// HPKE package. New code should use NewKDF.
var SupportedKDFs = map[uint16]func() *hkdfKDF{
	KDF_HKDF_SHA256: func() *hkdfKDF { return hkdfSHA256 },
	KDF_HKDF_SHA384: func() *hkdfKDF { return hkdfSHA384 },
	KDF_HKDF_SHA512: func() *hkdfKDF { return hkdfSHA512 },
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// SupportedAEADs is retained for source compatibility with the pre-Go 1.27
// HPKE package. New code should use NewAEAD.
var SupportedAEADs = map[uint16]struct {
	keySize   int
	nonceSize int
	aead      func([]byte) (cipher.AEAD, error)
}{
	AEAD_AES_128_GCM:      {16, 12, newAESGCM},
	AEAD_AES_256_GCM:      {32, 12, newAESGCM},
	AEAD_ChaCha20Poly1305: {chacha20poly1305.KeySize, chacha20poly1305.NonceSize, chacha20poly1305.New},
}

// SetupSender is the pre-Go 1.27 spelling of NewSender. It supports the
// classical DHKEM keys accepted by the original package.
func SetupSender(kemID, kdfID, aeadID uint16, pub *ecdh.PublicKey, info []byte) ([]byte, *Sender, error) {
	pk, err := NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	if pk.KEM().ID() != kemID {
		return nil, nil, errors.New("HPKE KEM does not match public key")
	}
	kdf, err := NewKDF(kdfID)
	if err != nil {
		return nil, nil, err
	}
	aead, err := NewAEAD(aeadID)
	if err != nil {
		return nil, nil, err
	}
	return NewSender(pk, kdf, aead, info)
}

// SetupRecipient is the pre-Go 1.27 spelling of NewRecipient. It supports the
// classical DHKEM keys accepted by the original package.
func SetupRecipient(kemID, kdfID, aeadID uint16, priv *ecdh.PrivateKey, info, encPubEph []byte) (*Recipient, error) {
	key, err := NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if key.KEM().ID() != kemID {
		return nil, errors.New("HPKE KEM does not match private key")
	}
	kdf, err := NewKDF(kdfID)
	if err != nil {
		return nil, err
	}
	aead, err := NewAEAD(aeadID)
	if err != nil {
		return nil, err
	}
	return NewRecipient(encPubEph, key, kdf, aead, info)
}

// ParseHPKEPublicKey is retained for compatibility with the original package.
func ParseHPKEPublicKey(kemID uint16, data []byte) (*ecdh.PublicKey, error) {
	kem, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported KEM id")
	}
	return kem.curve.NewPublicKey(data)
}

// ParseHPKEPrivateKey is retained for compatibility with the original package.
func ParseHPKEPrivateKey(kemID uint16, data []byte) (*ecdh.PrivateKey, error) {
	kem, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported KEM id")
	}
	return kem.curve.NewPrivateKey(data)
}
