# JWKT

A tiny Kotlin/JVM JWT (JWS Compact) library with no JSON runtime dependency.

JWKT does one thing: it hands the header and claims to the JSON implementation you choose, then handles signing, verification, and registered-claim validation. It is not tied to Jackson, Gson, kotlinx.serialization, or any other JSON framework; Kotlin stdlib is its only runtime dependency.

- **Package:** `com.rainccup.jwkt`
- **JVM:** 17+
- **Kotlin:** 2.4.20
- **Gradle:** 9.8.0
- **Algorithms:** HS256/384/512, RS256/384/512, ES256/384/512, plus custom `JwsAlgorithm` implementations
- **Format:** JWS Compact Serialization (three segments)

[中文文档](README.zh-CN.md)

## Features

- JSON is injected through `JsonCodec`; the library never exposes a JSON type
- Header and claims are available as `Map<String, Any?>`, with typed accessors for `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, and `jti`
- `JwtClaims.asType<T>()` decodes the original payload into your own claims model with the same codec
- Extensible signing algorithms, verification-key resolvers, and application validators
- Strict algorithm matching prevents algorithm-confusion attacks
- Constant-time HMAC comparison and RFC 7518 minimum HMAC key sizes
- `clockSkew` support for `exp` / `nbf`
- Distinct exceptions for malformed tokens, bad headers, invalid signatures, expired tokens, and missing claims

## Out of Scope

JWKT intentionally stays small and does **not** support:

- JWE (encrypted tokens)
- Unsecured `alg=none`
- RFC 7797 `b64=false`
- Unrecognized `crit` extensions
- Automatic JWKS download; plug in your own `JwsKeyResolver`

## Installation

```kotlin
dependencies {
    implementation("com.rainccup.jwkt:jwkt:0.1.0")
}
```

For local development, publish both modules first:

```bash
./gradlew publishToMavenLocal
```

## Spring Boot Starter

The `jwkt-spring-boot-starter` module provides auto-configuration for Spring Boot 3.5.x and 4.1.x:

```kotlin
dependencies {
    implementation("com.rainccup.jwkt:jwkt-spring-boot-starter:0.1.0")
}
```

```yaml
jwkt:
  algorithm: HS256
  issuer: https://example.com
  audience: [api]
  secret: "0123456789abcdef0123456789abcdef"
```

```kotlin
@Service
class TokenService(private val jwkt: JwktTemplate) {
    fun issue(userId: String): String = jwkt.issue { subject(userId) }
    fun verify(token: String) = jwkt.parse(token)
}
```

The starter creates `JwtParser`, `JwktSigner`, and `JwktTemplate` as configured. It registers a Jackson 2 or Jackson 3 `JsonCodec` when the matching library is on the classpath, and backs off for application-provided codecs, algorithms, validators, and clocks. See [jwkt-spring-boot-starter/README.md](jwkt-spring-boot-starter/README.md) for all properties and key formats.

## Quick Start

### 1. Implement `JsonCodec`

Jackson is shown only as the application's JSON library; JWKT does not depend on it.

```kotlin
import com.fasterxml.jackson.databind.ObjectMapper
import com.rainccup.jwkt.JsonCodec

class JacksonJsonCodec(
    private val mapper: ObjectMapper = ObjectMapper(),
) : JsonCodec {

    override fun encode(value: Any?): String =
        mapper.writeValueAsString(value)

    override fun decode(json: String, type: Class<*>): Any? =
        mapper.readValue(json, type)
}
```

`JsonCodec` contract:

1. `encode` must serialize `Map`, `Collection`, `String`, `Number`, `Boolean`, and `null`.
2. When called with `Map::class.java`, `decode` must return a `Map<String, Any?>` for a top-level JSON object.
3. `decode` must honor the supplied `type`; `JwtClaims.asType` uses this path.
4. Implementations must be thread-safe if the codec is shared between threads.

### 2. Issue a token

```kotlin
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.JwsAlgorithms
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val codec = JacksonJsonCodec()
val secret = ByteArray(32) { (it + 1).toByte() } // HS256 requires at least 32 bytes

val token = Jwkt.builder(codec)
    .issuer("https://example.com")
    .subject("user-42")
    .audience("api")
    .jwtId("token-001")
    .issuedAt(Clock.System.now())
    .expiresIn(15.minutes)
    .keyId("key-2026-01")
    .claim("role", "admin")
    .claim("tenant", "acme")
    .signWith(JwsAlgorithms.HS256, secret)
    .compact()
```

`typ` defaults to `JWT`. Use `.header(name, value)` for custom protected headers; `alg`, `b64`, and `crit` cannot be set through that method.

### 3. Parse and verify

```kotlin
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.JwsAlgorithms
import kotlin.time.Duration.Companion.seconds

val parser = Jwkt.parser(codec)
    .verifyWith(JwsAlgorithms.HS256, secret)
    .requireIssuer("https://example.com")
    .requireAudience("api")
    .requireClaim("tenant", "acme")
    .requireExpiration()
    .clockSkew(30.seconds)
    .maxTokenLength(16 * 1024)
    .build()

val jwt = parser.parse(token)

check(jwt.isVerified)
println(jwt.claims.subject)     // user-42
println(jwt.claims["role"])     // admin
println(jwt.header.keyId)       // key-2026-01
```

`parse` splits the token, validates the header, selects a verification key, verifies the signature, and only then decodes the claims JSON. It then checks `exp` / `nbf`, required claims, and custom validators. `Jwt.isVerified` is `true` only after all checks pass.

`maxTokenLength` defaults to 16 KiB and is checked before any base64 or JSON work. This bounds pre-verification memory use.

## Typed Claims

You do not need to convert claims to a map and map them by hand:

```kotlin
class AccountClaims {
    @JvmField var sub: String? = null
    @JvmField var role: String? = null
    @JvmField var tenant: String? = null
}

val account = jwt.claims.asType<AccountClaims>()
```

To deserialize Kotlin `data class` types with Jackson, add `jackson-module-kotlin` and register the Kotlin module. That is the codec implementation's responsibility, not JWKT's.

## Custom Algorithms

Implement `JwsAlgorithm` to add a scheme that is not built in. This example uses the JDK 17 Ed25519 provider:

```kotlin
import com.rainccup.jwkt.JwsAlgorithm
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

object Ed25519Algorithm : JwsAlgorithm {

    override val name: String = "EdDSA"

    override fun sign(input: ByteArray, key: Any): ByteArray =
        Signature.getInstance("Ed25519").run {
            initSign(key as PrivateKey)
            update(input)
            sign()
        }

    override fun verify(
        input: ByteArray,
        signature: ByteArray,
        key: Any,
    ): Boolean =
        Signature.getInstance("Ed25519").run {
            initVerify(key as PublicKey)
            update(input)
            verify(signature)
        }
}

val token = Jwkt.builder(codec)
    .subject("user-42")
    .signWith(Ed25519Algorithm, privateKey)
    .compact()

val jwt = Jwkt.parser(codec)
    .verifyWith(Ed25519Algorithm, publicKey)
    .build()
    .parse(token)
```

Contract:

- `sign` / `verify` receive the ASCII bytes of `base64url(header) + "." + base64url(payload)`.
- `sign` returns raw signature bytes; JWKT performs base64url encoding.
- `key` is the exact object passed by the caller.
- Implementations should be thread-safe.

## Key Rotation

A static key map holds one key per algorithm. Use `JwsKeyResolver` when keys rotate by `kid`:

```kotlin
val parser = Jwkt.parser(codec)
    .verifyWith { header ->
        when (header.keyId) {
            "2026-01" -> JwsVerificationKey(JwsAlgorithms.HS256, oldSecret)
            "2026-02" -> JwsVerificationKey(JwsAlgorithms.HS256, newSecret)
            else -> null
        }
    }
    .build()
```

The resolver receives an unverified header, so never trust its fields blindly. JWKT also checks that the returned algorithm name matches the header's `alg`. A resolver can cache and refresh keys from a remote JWKS.

## Expiration and Clocks

```kotlin
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

val parser = Jwkt.parser(codec)
    .verifyWith(JwsAlgorithms.HS256, secret)
    .clock(Clock.System)          // default
    .clockSkew(30.seconds)        // allow 30 seconds of skew
    .build()
```

- `exp`: throws `ExpiredToken` when `now >= exp + skew`
- `nbf`: throws `NotYetValidToken` when `now + skew < nbf`
- `iat` is exposed as `Instant` but does not affect validity by default

## Built-in Algorithms

| `JwsAlgorithm` | JCA name | Key |
| --- | --- | --- |
| `HS256` / `HS384` / `HS512` | `HmacSHA256/384/512` | `ByteArray` or `SecretKey`, at least 32/48/64 bytes |
| `RS256` / `RS384` / `RS512` | `SHA256/384/512withRSA` | `PrivateKey` / `PublicKey` / `KeyPair`, at least 2048 bits |
| `ES256` / `ES384` / `ES512` | `SHA256/384/512withECDSAinP1363Format` | EC key on P-256 / P-384 / P-521 |

HMAC minimum sizes come from RFC 7518. RSA keys below 2048 bits are rejected. If you must interoperate with legacy short HMAC keys, you can construct `HmacJwsAlgorithm(name, jcaName, minimumKeySizeBytes)`, but lowering the strength is not recommended.

## API Overview

| Type | Role |
| --- | --- |
| `Jwkt` | Factory entry point: `builder`, `parser`, `parseUnverified` |
| `JsonCodec` | JSON encoding/decoding extension point |
| `JwsAlgorithm` | Signing algorithm extension point |
| `JwsKeyResolver` | Selects a verification key from the header |
| `JwsVerificationKey` | Algorithm + key pair |
| `JwtBuilder` | Builds and signs a token |
| `JwtParserBuilder` / `JwtParser` | Configures and runs verification/validation |
| `Jwt` | Header, claims, signature, original token, `isVerified` |
| `JwtHeader` / `JwtClaims` | Typed header / claims access |
| `JwtValidator` | Application-level validation extension |
| `JwtException` | Base class for all library errors |

### Exceptions

| Exception | Situation |
| --- | --- |
| `MalformedToken` | Not three segments, invalid base64url/UTF-8/JSON, or payload is not an object |
| `InvalidHeader` | Missing or non-string `alg`, `alg=none`, or unsupported `crit` / `b64` |
| `UnsupportedAlgorithm` | No verification key matches the header `alg` |
| `AlgorithmMismatch` | Resolver returned an algorithm different from the header `alg` |
| `InvalidSignature` | Signature verification failed |
| `InvalidClaims` | Registered claim has the wrong type or a validator rejected it |
| `ExpiredToken` / `NotYetValidToken` | `exp` / `nbf` validation failed |
| `MissingClaim` / `ClaimMismatch` | A required claim is absent or does not match |
| `JsonCodecException` | Codec encoding/decoding failed |
| `InvalidKeyException` | Key type or size is unsuitable |
| `SigningException` / `VerificationException` | Algorithm execution failed |
| `ConfigurationException` | Builder/parser is missing required configuration |

## Security Notes

- Use `parse` for authorization decisions. `parseUnverified` does not verify signatures and is only suitable for reading `kid` / `alg` before key selection.
- Never choose an arbitrary algorithm from the token's `alg`. JWKT cross-checks the configured algorithm name against the header.
- Use at least 32-byte HMAC secrets, RSA keys of at least 2048 bits, and the EC curve that matches the algorithm.
- Pin the accepted algorithm set in production; do not let untrusted input choose it.
- `kid` comes from an unverified header. Treat it as a lookup hint and verify the ownership of the resolved key.
- Call `requireExpiration()` on the parser when every accepted token must carry `exp`; the Spring Boot starter enables this by default.
- JWS does not provide confidentiality. Use JWE or application-level encryption when the payload must be secret.
- Protect private keys and HMAC secrets; do not log `JwsVerificationKey` or builder key fields.

## Development

```bash
./gradlew test
./gradlew build
```

The tests cover HS/RS/ES signing, non-JSON codecs, custom algorithms, `kid` rotation, expiration/clock skew, required claims, malformed tokens, algorithm confusion, and key-type errors. Jackson in the tests only supplies a `JsonCodec` implementation.

## Releasing

Publishing to Maven Central is handled by `.github/workflows/release.yml` through the
[GradleUp NMCP](https://gradleup.com/nmcp/) plugin and the Central Portal.

Configure these repository secrets:

| Secret | Purpose |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` / `MAVEN_CENTRAL_PASSWORD` | Central Portal user token |
| `SIGNING_KEY` | ASCII-armored GPG private key |
| `SIGNING_PASSWORD` | GPG key passphrase (empty if the key has none) |

Then either push a `v*` tag or run the **Release** workflow manually with a version such as `0.2.0`.
The workflow builds both modules, signs every publication, and uploads the aggregation to the
Central Portal.

## License

Apache License 2.0. See [LICENSE](LICENSE).
