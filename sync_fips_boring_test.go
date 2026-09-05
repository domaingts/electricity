//go:build boringcrypto

package reality

import (
	"slices"
	"testing"

	"github.com/xtls/reality/fips140tls"
)

func TestSyncBoringFIPSPolicy(t *testing.T) {
	wasRequired := fips140tls.Required()
	fips140tls.Force()
	t.Cleanup(func() {
		if !wasRequired {
			fips140tls.TestingOnlyAbandon()
		}
	})
	config := &Config{CurvePreferences: curvePreferenceOrder()}
	want := []CurveID{CurveP256, CurveP384, CurveP521}
	if got := config.curvePreferences(VersionTLS13); !slices.Equal(got, want) {
		t.Fatalf("BoringCrypto FIPS groups = %v, want %v", got, want)
	}
	for _, alg := range []SignatureScheme{Ed25519, MLDSA44, MLDSA65, MLDSA87} {
		if slices.Contains(supportedSignatureAlgorithms(VersionTLS13, VersionTLS13), alg) {
			t.Fatalf("BoringCrypto FIPS policy accepted %s", alg)
		}
	}
}
