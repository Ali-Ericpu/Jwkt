# JWKT Spring Boot Starter

Spring Boot auto-configuration for JWKT, supporting **Spring Boot 3.5.x** and **Spring Boot 4.1.x**.

It registers JWKT's `JwtParser`, `JwktSigner`, and `JwktTemplate` as Spring beans and loads HMAC, RSA, or EC keys from `jwkt.*` properties. The starter has no hard JSON dependency: when Jackson 2 (Boot 3) or Jackson 3 (Boot 4) is on the classpath, the matching `JsonCodec` is auto-configured; an application-provided codec always wins.

- **Coordinates:** `com.rainccup:jwkt-spring-boot-starter:0.1.0`
- **Package:** `com.rainccup.jwkt.spring`
- **Java:** 17+
- **Boot baseline:** compiled against Boot 3.5.16 and tested independently on Boot 4.1.2

[中文文档](README.zh-CN.md)

## Installation

Publish both modules to your local Maven repository from the project root:

```bash
./gradlew publishToMavenLocal
```

Then add the starter:

```kotlin
dependencies {
    implementation("com.rainccup:jwkt-spring-boot-starter:0.1.0")
    // Usually already present in a web application.
    implementation("org.springframework.boot:spring-boot-starter-web")
}
```

For Boot 4 with Jackson 3, make sure the application has:

```kotlin
implementation("org.springframework.boot:spring-boot-starter-jackson")
```

For Boot 3, the equivalent is `spring-boot-starter-json`. Web starters normally bring one of them transitively.

## Quick Start

### application.yml

```yaml
jwkt:
  algorithm: HS256
  issuer: https://example.com
  audience:
    - api
  secret: "0123456789abcdef0123456789abcdef" # at least 32 bytes
  expires-in: 15m
  include-issued-at: true
  required-claims:
    - tenant
```

### Inject and use

```kotlin
import com.rainccup.jwkt.spring.JwktTemplate
import org.springframework.stereotype.Service

@Service
class TokenService(
    private val jwkt: JwktTemplate,
) {

    fun issue(userId: String, tenant: String): String =
        jwkt.issue {
            subject(userId)
            claim("tenant", tenant)
            claim("role", "user")
        }

    fun verify(token: String) =
        jwkt.parse(token)
}
```

`JwktTemplate` holds both a signer and a parser and fits most issue-and-verify use cases. You can also inject the pieces separately:

- `JwktSigner`: signing only
- `JwtParser`: verification only
- `JwsAlgorithm`: the active algorithm
- `JwktProperties`: the raw configuration

## Auto-configuration

| Condition | Bean |
| --- | --- |
| Any key configured | `JwktKeyMaterial` |
| A verification key (secret or public key) | `JwtParser` |
| A signing key (secret or private key) | `JwktSigner` |
| Parser and signer both present | `JwktTemplate` |
| No application `Clock` | `Clock.systemUTC()` |
| No application `JwsAlgorithm` | Built-in algorithm selected by `jwkt.algorithm` |
| Jackson 2 on classpath and no `JsonCodec` | `Jackson2JsonCodec` |
| Jackson 3 on classpath and no `JsonCodec` | `Jackson3JsonCodec` |

Every bean uses `@ConditionalOnMissingBean`, so an application can take full control by defining a bean of the same type. Set `jwkt.enabled=false` to disable the whole starter.

## Key Configuration

### HMAC

```yaml
jwkt:
  algorithm: HS256
  secret: "0123456789abcdef0123456789abcdef"
```

Or use Base64 (standard and URL-safe Base64 are accepted):

```yaml
jwkt:
  algorithm: HS256
  secret-base64: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
```

`HS256` / `HS384` / `HS512` require at least 32 / 48 / 64 bytes. Configure exactly one of `secret` or `secret-base64`, and do not mix either with PEM keys.

### RSA

```yaml
jwkt:
  algorithm: RS256
  private-key: classpath:keys/private.pem   # signing
  public-key: classpath:keys/public.pem     # verification
```

- Private keys must be PKCS#8 PEM (`BEGIN PRIVATE KEY`).
- Public keys must be X.509 PEM (`BEGIN PUBLIC KEY`).
- RSA keys must be at least 2048 bits.
- Private key only: signer only. Public key only: parser only.

Convert PKCS#1 keys first:

```bash
openssl pkcs8 -topk8 -nocrypt -in private-pkcs1.pem -out private.pem
openssl rsa -in private-pkcs1.pem -pubout -out public.pem
```

### ECDSA

```yaml
jwkt:
  algorithm: ES256
  private-key: classpath:keys/ec-private.pem
  public-key: classpath:keys/ec-public.pem
```

`ES256` / `ES384` / `ES512` require P-256 / P-384 / P-521 respectively. A curve mismatch fails at startup.

### Custom Algorithms

Register a `JwsAlgorithm` bean whose `name` matches `jwkt.algorithm`:

```kotlin
@Configuration
class JwtAlgorithmConfiguration {

    @Bean
    fun ed25519(): JwsAlgorithm = object : JwsAlgorithm {
        override val name: String = "EdDSA"

        // Implement sign / verify.
    }
}
```

With PEM keys, also set `jwkt.key-algorithm` (for example `Ed25519`):

```yaml
jwkt:
  algorithm: EdDSA
  key-algorithm: Ed25519
  private-key: classpath:keys/ed25519-private.pem
  public-key: classpath:keys/ed25519-public.pem
```

## Custom JsonCodec

The starter does not force Jackson. Define your own `JsonCodec` bean for Gson, kotlinx.serialization, or an internal protocol:

```kotlin
@Configuration
class JsonConfiguration {

    @Bean
    fun jsonCodec(): JsonCodec = MyJsonCodec()
}
```

The Jackson adapters back off whenever a `JsonCodec` bean is present.

## Jackson Adapters

### Boot 3 / Jackson 2

```kotlin
val codec = Jackson2JsonCodec(objectMapper)
```

### Boot 4 / Jackson 3

```kotlin
val codec = Jackson3JsonCodec(jsonMapper)
```

Both adapters are public and can be used directly without auto-configuration. They wrap Jackson failures in `JwtException.JsonCodecException`.

## Custom Validators

Implement `JwtValidator`, register it as a bean, and the starter adds it to the parser:

```kotlin
@Bean
fun tenantValidator(): JwtValidator = JwtValidator { jwt ->
    if (jwt.claims["tenant"] == null) {
        throw JwtException.MissingClaim("tenant")
    }
}
```

You can also define your own `JwtParser`, `JwktSigner`, or `JwktTemplate` bean; auto-configuration backs off.

## Custom Clock

```kotlin
@Bean
fun clock(): Clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC)
```

The same clock is used for signing and for `exp` / `nbf` validation.

## Configuration Properties

| Property | Default | Description |
| --- | --- | --- |
| `jwkt.enabled` | `true` | Enable the starter |
| `jwkt.algorithm` | `HS256` | JOSE algorithm name |
| `jwkt.issuer` | none | Writes and requires `iss` |
| `jwkt.audience` | empty | Writes and requires `aud`; repeatable |
| `jwkt.key-id` | none | Writes `kid` |
| `jwkt.secret` | none | UTF-8 HMAC secret |
| `jwkt.secret-base64` | none | Base64 HMAC secret |
| `jwkt.private-key` | none | PKCS#8 PEM private-key resource |
| `jwkt.public-key` | none | X.509 PEM public-key resource |
| `jwkt.key-algorithm` | none | JCA key algorithm for PEM; inferred for RS*/ES* |
| `jwkt.clock-skew` | `0s` | Allowed `exp` / `nbf` skew |
| `jwkt.expires-in` | `15m` | Default signer lifetime |
| `jwkt.include-issued-at` | `true` | Add `iat` automatically |
| `jwkt.require-expiration` | `true` | Reject tokens without `exp` |
| `jwkt.headers` | empty | Extra protected headers |
| `jwkt.claims` | empty | Extra default claims |
| `jwkt.required-claims` | empty | Claims the parser requires |

`jwkt.headers` cannot set `alg`, `b64`, or `crit` (case-insensitive). Explicit `jwkt.headers` and `jwkt.claims` are applied last, so they can override computed defaults such as `iat`, `exp`, and `kid`; avoid setting registered claims there unless you intend to.

## Relationship to the Core Library

The starter exposes the core library through `api(project(":"))`, so applications do not need a separate `jwkt` dependency. The core remains free of JSON runtime dependencies. The starter does not bring Jackson 2 or Jackson 3 transitively; an adapter is enabled only when the application classpath already has that Jackson major version.

## Tests

```bash
# Boot 3.5.16
./gradlew :jwkt-spring-boot-starter:test

# Boot 4.1.2
./gradlew :jwkt-spring-boot-starter:boot4Test

# Both
./gradlew :jwkt-spring-boot-starter:check
```

Coverage includes HMAC/RSA/EC key loading, PEM parsing, auto-configuration backoff, required claims, Jackson 2/3 adapters, and full-context startup through `AutoConfiguration.imports`.

## License

Apache License 2.0. See [../LICENSE](../LICENSE).
