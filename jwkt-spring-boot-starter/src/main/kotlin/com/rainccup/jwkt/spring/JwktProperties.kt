package com.rainccup.jwkt.spring

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.Resource
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Configuration properties for the JWKT Spring Boot starter.
 *
 * All properties are optional. The starter creates a parser when a verification key is
 * configured, a signer when a signing key is configured, and a template when both are
 * available.
 */
@ConfigurationProperties(prefix = "jwkt")
public class JwktProperties {

    /** Enables or disables the starter. */
    public var enabled: Boolean = true

    /**
     * JOSE algorithm name, for example `HS256`, `RS256`, `ES256`, or the name of a custom
     * [com.rainccup.jwkt.JwsAlgorithm] bean.
     */
    public var algorithm: String = "HS256"

    /** Value written to the `iss` claim and required by the parser when set. */
    public var issuer: String? = null

    /** Audiences written to `aud`; each one is also required by the parser. */
    public var audience: MutableList<String> = mutableListOf()

    /** Optional `kid` header. */
    public var keyId: String? = null

    /** HMAC secret as UTF-8 text. Mutually exclusive with [secretBase64] and PEM keys. */
    public var secret: String? = null

    /** HMAC secret encoded as standard or URL-safe Base64. */
    public var secretBase64: String? = null

    /** PKCS#8 PEM private key used for signing. */
    public var privateKey: Resource? = null

    /** X.509 PEM public key used for verification. */
    public var publicKey: Resource? = null

    /**
     * JCA key algorithm for PEM material when it cannot be inferred from [algorithm]
     * (`RSA` for `RS*`, `EC` for `ES*`). Set this for custom algorithms such as `EdDSA`.
     */
    public var keyAlgorithm: String? = null

    /** Allowed clock skew for `exp` and `nbf`. */
    public var clockSkew: Duration = Duration.ZERO

    /**
     * JavaBean accessor used by Spring Boot's configuration binder.
     *
     * Kotlin's inline [Duration] getter has a mangled JVM name, so this String accessor keeps
     * `jwkt.clock-skew` bindable without relying on Java time types.
     */
    public fun getClockSkew(): String = clockSkew.toString()

    /** JavaBean accessor used by Spring Boot's configuration binder. */
    public fun setClockSkew(value: String) {
        clockSkew = parseDuration("jwkt.clock-skew", value)
    }

    /** Default lifetime applied by [JwktSigner]; individual tokens can override it. */
    public var expiresIn: Duration = 15.minutes

    /** JavaBean accessor used by Spring Boot's configuration binder. */
    public fun getExpiresIn(): String = expiresIn.toString()

    /** JavaBean accessor used by Spring Boot's configuration binder. */
    public fun setExpiresIn(value: String) {
        expiresIn = parseDuration("jwkt.expires-in", value)
    }

    /** Whether [JwktSigner] adds `iat` automatically. */
    public var includeIssuedAt: Boolean = true

    /** Whether parsing requires an `exp` claim. */
    public var requireExpiration: Boolean = true

    /** Extra protected header parameters applied by [JwktSigner]. */
    public var headers: MutableMap<String, Any> = linkedMapOf()

    /** Extra claims applied by [JwktSigner]. */
    public var claims: MutableMap<String, Any> = linkedMapOf()

    /** Claims that must be present when parsing. */
    public var requiredClaims: MutableSet<String> = linkedSetOf()

    override fun toString(): String =
        "JwktProperties(enabled=$enabled, algorithm=$algorithm, issuer=$issuer, " +
            "audience=$audience, keyId=$keyId, secret=<redacted>, " +
            "secretBase64=<redacted>, privateKey=$privateKey, publicKey=$publicKey, " +
            "keyAlgorithm=$keyAlgorithm, clockSkew=$clockSkew, expiresIn=$expiresIn, " +
            "includeIssuedAt=$includeIssuedAt, requireExpiration=$requireExpiration, " +
            "headerNames=${headers.keys}, " +
            "claimNames=${claims.keys}, requiredClaims=$requiredClaims)"

    private fun parseDuration(property: String, value: String): Duration =
        try {
            Duration.parse(value.trim())
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException(
                "$property must be a Kotlin duration such as '30s' or 'PT15M'",
                e,
            )
        }
}
