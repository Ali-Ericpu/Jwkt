package com.rainccup.jwkt

/**
 * A JWS signature algorithm.
 *
 * Implement this interface to add algorithms that are not built in. The `alg` parameter in
 * the token header is always the [name] of the configured algorithm.
 *
 * ### Signing input
 *
 * [sign] and [verify] receive the exact ASCII bytes of
 * `base64url(header) + "." + base64url(payload)`. Return or verify the raw signature bytes;
 * JWKT applies base64url encoding itself.
 *
 * ### Key type
 *
 * [key] is whatever the caller supplied through [JwtBuilder.signWith] or
 * [JwtParserBuilder.verifyWith]. Built-in algorithms accept [ByteArray] or
 * [javax.crypto.SecretKey] for HMAC, and [java.security.PrivateKey],
 * [java.security.PublicKey], or [java.security.KeyPair] for asymmetric algorithms.
 *
 * Implementations should be thread-safe.
 */
public interface JwsAlgorithm {

    /** The JOSE `alg` value, for example `HS256` or `RS256`. */
    public val name: String

    /** Produces a raw signature. */
    public fun sign(input: ByteArray, key: Any): ByteArray

    /** Verifies a raw signature. Returns `false` for an invalid signature. */
    public fun verify(input: ByteArray, signature: ByteArray, key: Any): Boolean
}

/**
 * An algorithm and key pair configured on [JwtParserBuilder].
 *
 * The algorithm name is checked against the token header before verification to prevent
 * algorithm-confusion attacks.
 */
public class JwsVerificationKey(
    public val algorithm: JwsAlgorithm,
    public val key: Any,
) {

    init {
        require(algorithm.name.isNotBlank()) { "Algorithm name must not be blank" }
    }

    override fun toString(): String =
        "JwsVerificationKey(algorithm=${algorithm.name}, key=<redacted>)"
}

/**
 * Resolves a verification algorithm and key from an untrusted, decoded header.
 *
 * A resolver is useful for key rotation, where the `kid` header selects a key. JWKT still
 * requires the returned algorithm name to equal the header `alg`. A resolver may throw
 * [JwtException] to reject a token; other exceptions are wrapped as
 * [JwtException.VerificationException].
 */
public fun interface JwsKeyResolver {
    public fun resolve(header: JwtHeader): JwsVerificationKey?
}
