package tls13

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestEarlySecretRFC8448(t *testing.T) {
	want, err := hex.DecodeString("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	if err != nil {
		t.Fatal(err)
	}
	if got := NewEarlySecret(sha256.New, nil).secret; !bytes.Equal(got, want) {
		t.Fatalf("early secret = %x, want RFC 8448 value %x", got, want)
	}
}

func TestExpandLabel(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, sha256.Size)
	context := bytes.Repeat([]byte{2}, sha256.Size)
	for _, length := range []int{0, 16, 32, 64, 255 * sha256.Size} {
		info := []byte{byte(length >> 8), byte(length), byte(len("tls13 test"))}
		info = append(info, "tls13 test"...)
		info = append(info, byte(len(context)))
		info = append(info, context...)
		want := make([]byte, length)
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), want); err != nil {
			t.Fatal(err)
		}
		if got := ExpandLabel(sha256.New, secret, "test", context, length); !bytes.Equal(got, want) {
			t.Fatalf("HKDF label mismatch at length %d", length)
		}
	}
}

func TestExpandLabelRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name    string
		label   string
		context []byte
		length  int
	}{
		{name: "negative-length", length: -1},
		{name: "counter-overflow", length: 255*sha256.Size + 1},
		{name: "label-too-long", label: strings.Repeat("a", 250), length: 32},
		{name: "context-too-long", context: make([]byte, 256), length: 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid key schedule input did not panic")
				}
			}()
			ExpandLabel(sha256.New, make([]byte, 32), test.label, test.context, test.length)
		})
	}
}
