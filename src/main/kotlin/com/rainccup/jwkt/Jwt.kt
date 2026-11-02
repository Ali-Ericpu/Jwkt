package com.rainccup.jwkt

/**
 * A parsed JWT.
 *
 * Instances returned by [JwtParser.parse] have a verified signature and passed claim
 * validation. Instances returned by [JwtParser.parseUnverified] are explicitly unverified;
 * check [isVerified] before trusting them.
 */
public class Jwt internal constructor(
    /** The decoded protected header. */
    public val header: JwtHeader,
    /** The decoded payload. */
    public val claims: JwtClaims,
    signature: ByteArray,
    /** The exact compact serialization that was parsed. */
    public val token: String,
    /** `true` only when the signature was verified and parser validation succeeded. */
    public val isVerified: Boolean,
) {

    private val signatureBytes: ByteArray = signature.copyOf()

    /** A defensive copy of the raw JWS signature bytes. */
    public val signature: ByteArray
        get() = signatureBytes.copyOf()

    override fun toString(): String =
        "Jwt(header=$header, claims=$claims, isVerified=$isVerified)"
}
