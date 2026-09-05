//go:build !boringcrypto

package reality

import (
	"slices"
	"testing"

	"github.com/xtls/reality/fips140tls"
)

func TestSyncNativeFIPSPolicy(t *testing.T) {
	wasRequired := fips140tls.Required()
	fips140tls.Force()
	t.Cleanup(func() {
		if !wasRequired {
			fips140tls.TestingOnlyAbandon()
		}
	})
	config := &Config{CurvePreferences: curvePreferenceOrder()}
	want := []CurveID{X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM1024, CurveP256, CurveP384, CurveP521}
	if got := config.curvePreferences(VersionTLS13); !slices.Equal(got, want) {
		t.Fatalf("native FIPS groups = %v, want %v", got, want)
	}
	for _, alg := range []SignatureScheme{Ed25519, MLDSA44, MLDSA65, MLDSA87} {
		if !slices.Contains(supportedSignatureAlgorithms(VersionTLS13, VersionTLS13), alg) {
			t.Fatalf("native FIPS policy rejected %s", alg)
		}
	}
}
