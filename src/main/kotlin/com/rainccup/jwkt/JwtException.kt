package com.rainccup.jwkt

import kotlin.time.Instant

/**
 * Base class for every failure raised by JWKT.
 *
 * Specific subclasses allow callers to distinguish malformed input, failed verification,
 * expired tokens, and configuration mistakes without parsing exception messages.
 */
public open class JwtException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {

    /** The compact token is not a syntactically valid JWS compact serialization. */
    public class MalformedToken(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** The protected header is missing, malformed, or uses an unsupported JWS extension. */
    public class InvalidHeader(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** No verifier is configured for the `alg` value in the token header. */
    public class UnsupportedAlgorithm(
        public val algorithm: String,
    ) : JwtException("No verifier is configured for JWT algorithm '$algorithm'")

    /**
     * A verifier returned a key for a different algorithm than the one in the token header.
     *
     * This check prevents algorithm-confusion attacks.
     */
    public class AlgorithmMismatch(
        public val headerAlgorithm: String,
        public val configuredAlgorithm: String,
    ) : JwtException(
        "JWT header algorithm '$headerAlgorithm' does not match verifier algorithm " +
            "'$configuredAlgorithm'",
    )

    /** The cryptographic signature did not verify. */
    public class InvalidSignature : JwtException("JWT signature verification failed")

    /** A registered claim has an invalid JSON type or value. */
    public class InvalidClaims(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** The token is expired. */
    public class ExpiredToken(
        public val expiredAt: Instant,
        public val now: Instant,
    ) : JwtException("JWT expired at $expiredAt (current time: $now)")

    /** The token is not valid yet because of its `nbf` claim. */
    public class NotYetValidToken(
        public val notBefore: Instant,
        public val now: Instant,
    ) : JwtException("JWT is not valid before $notBefore (current time: $now)")

    /** A claim required by the parser is absent. */
    public class MissingClaim(
        public val claimName: String,
    ) : JwtException("Required JWT claim '$claimName' is missing")

    /** A registered claim or a required claim does not have the expected value. */
    public class ClaimMismatch(
        public val claimName: String,
        public val expected: Any?,
        public val actual: Any?,
    ) : JwtException(
        "JWT claim '$claimName' mismatch: expected '$expected', got '$actual'",
    )

    /** The configured [JsonCodec] failed while encoding or decoding JSON. */
    public class JsonCodecException(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** The signing key is invalid, missing, or unsuitable for the selected algorithm. */
    public class InvalidKeyException(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** An algorithm failed while producing a signature. */
    public class SigningException(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** An algorithm failed while verifying a signature. */
    public class VerificationException(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)

    /** The builder or parser is missing required configuration. */
    public class ConfigurationException(
        message: String,
        cause: Throwable? = null,
    ) : JwtException(message, cause)
}
