# Go source synchronization

The forked TLS implementation is synchronized with the **Go 1.27.1** source baseline. The module directive remains `go 1.27`; unrelated dependency versions are unchanged.

## Fork-specific adaptations

- `Server(ctx, conn, config)` remains the REALITY constructor. Ordinary TLS and QUIC use a separate internal server constructor and handshake path.
- REALITY preserves the target's serialized ServerHello, replacing only its key share. Authentication, fallback forwarding, optional half-close, rate-limit wrappers, target record lengths, and post-handshake imitation remain fork-owned behavior.
- REALITY authentication still requires X25519 key material, including the X25519 component of X25519MLKEM768. Supporting additional target-selected TLS groups does not introduce a different authentication scheme.
- Circl ML-DSA-65 certificate-extension signatures remain separate from the new standard-library ML-DSA TLS certificate/signature support.
- The exported `EchCipher`/`EchConfig` types, context-aware `Server`, `ConnectionState.LocalCertificate`, and `QUICConfig.ClientHelloInfoConn` are retained.
- `hpke` delegates its modern API to the public `crypto/hpke` package. Legacy setup, parsing, identifiers, and lookup maps remain available through a compatibility layer. This avoids copying or bypassing the standard library's internal HPKE nonce-policy enforcement.
- `tls12` and `tls13` use public HMAC/HKDF APIs in place of inaccessible Go-internal packages. The TLS 1.3 adapter propagates otherwise unrepresentable HKDF errors as panics rather than silently returning an empty secret.
- `godebug` reads explicit environment overrides, including the last duplicate value. It does not reproduce runtime telemetry, bisect behavior, or defaults supplied through a consuming module's `godebug` directive or `//go:debug` comments.
- `record_detect.go` remains project-owned and was not replaced by upstream code.

## FIPS limitations

Native FIPS and BoringCrypto negotiation policies remain separate. The native policy includes approved post-quantum mechanisms from the selected baseline; the BoringCrypto policy remains classical-only when explicitly enabled.

This synchronization does **not** make REALITY or this external TLS fork FIPS validated:

- Ordinary TLS/QUIC negotiation tests pass with native `GODEBUG=fips140=on`.
- The TLS AES-GCM adapter still uses public `cipher.NewGCM`. Strict `GODEBUG=fips140=only` rejects that constructor; full TLS connections in this fork remain unsupported in that mode. No enforcement bypass was added. Use standard `crypto/tls` for strict FIPS requirements.
- The HPKE adapter uses standard `crypto/hpke`, and its P-256/AES-GCM path is tested with strict native enforcement.
- The TLS 1.2 public HMAC adapter cannot reproduce the internal TLS-KDF-specific service indicator.
- Under BoringCrypto, importing standard `crypto/tls/fipsonly` does not update this fork's separate policy flag. Call `github.com/xtls/reality/fips140tls.Force` to enable the fork's classical-only policy. Policy selection is not a certification claim.
- Native FIPS mode and `GOEXPERIMENT=boringcrypto` cannot be combined; the Go toolchain rejects that combination.

## Regression coverage

Tests cover:

- Standard-library interoperability for TLS 1.2/1.3 in both client/server roles, on local pipes and loopback TCP.
- All eight implemented TLS key-exchange groups, malformed key-share lengths, and ML-DSA-44/65/87 mutual certificate authentication.
- TLS 1.3 resumption and ticket consumption, QUIC events and connection metadata, and cross-stack ECH acceptance/rejection.
- Authenticated REALITY handshakes with every supported target group, with and without Circl ML-DSA-65 extensions, separate/coalesced records, synthetic tickets, and post-handshake imitation.
- Synthetic-certificate authentication bindings, exact target ServerHello serialization, target record lengths, and application traffic after client Finished.
- Fallback rejection for invalid authentication, timestamps, short IDs, server names, and client versions, plus existing closure and detector tests.
- HPKE compatibility, GODEBUG parsing, TLS 1.2 generic hash constructors, TLS 1.3 key-schedule vectors/bounds, and the non-advancing record limit.

The REALITY target tests use deterministic local target doubles; they do not establish compatibility with every Internet target or downstream client implementation.

Run with a consistent Go 1.27.1 command, GOROOT, and compiler installation:

```sh
go test -count=1 ./...
go test -race -count=3 ./...
go vet ./...
GOEXPERIMENT=boringcrypto go test -count=1 ./...
GODEBUG=fips140=only go test -count=1 ./hpke
```
