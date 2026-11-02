package com.rainccup.jwkt

import com.rainccup.jwkt.internal.CLAIM_AUDIENCE
import com.rainccup.jwkt.internal.CLAIM_EXPIRATION
import com.rainccup.jwkt.internal.CLAIM_ISSUED_AT
import com.rainccup.jwkt.internal.CLAIM_ISSUER
import com.rainccup.jwkt.internal.CLAIM_JWT_ID
import com.rainccup.jwkt.internal.CLAIM_NOT_BEFORE
import com.rainccup.jwkt.internal.CLAIM_SUBJECT
import com.rainccup.jwkt.internal.Encoding
import com.rainccup.jwkt.internal.isNumericDateClaim
import java.time.Clock
import java.time.Duration
import java.time.Instant

/**
 * Fluent builder for a signed JWT.
 *
 * Obtain an instance with [Jwkt.builder]. A [JsonCodec] and a signing algorithm are required
 * before [compact] can be called.
 *
 * ```kotlin
 * val token = Jwkt.builder(codec)
 *     .subject("user-42")
 *     .expiresIn(Duration.ofMinutes(15))
 *     .signWith(JwsAlgorithms.HS256, secret)
 *     .compact()
 * ```
 *
 * Builders are mutable and not thread-safe. Do not share one between threads.
 */
public class JwtBuilder internal constructor() {

    private var codec: JsonCodec? = null
    private var clock: Clock = Clock.systemUTC()
    private var signingAlgorithm: JwsAlgorithm? = null
    private var signingKey: Any? = null
    private val headerValues: MutableMap<String, Any?> = LinkedHashMap()
    private val claimValues: MutableMap<String, Any?> = LinkedHashMap()

    /** Sets the JSON implementation used for the header and payload. */
    public fun codec(codec: JsonCodec): JwtBuilder = apply {
        this.codec = codec
    }

    /** Sets the clock used by [expiresIn]. */
    public fun clock(clock: Clock): JwtBuilder = apply {
        this.clock = clock
    }

    /**
     * Adds or replaces a custom protected header parameter.
     *
     * `alg` cannot be set here; use [signWith]. `typ` defaults to `JWT` when omitted.
     */
    public fun header(name: String, value: Any?): JwtBuilder = apply {
        require(name.isNotBlank()) { "Header name must not be blank" }
        val normalized = name.lowercase()
        require(normalized != "alg") { "The 'alg' header is set by signWith(...)" }
        require(normalized != "b64") {
            "The 'b64' header is not supported; JWKT always uses base64url-encoded payloads"
        }
        require(normalized != "crit") {
            "The 'crit' header is not supported; JWKT understands no critical extensions"
        }
        headerValues[name] = value
    }

    /** Adds or replaces several custom protected header parameters. */
    public fun headers(values: Map<String, Any?>): JwtBuilder = apply {
        values.forEach { (name, value) -> header(name, value) }
    }

    /** Sets the `typ` header. The default is `JWT`. */
    public fun type(type: String): JwtBuilder = apply {
        require(type.isNotBlank()) { "JWT type must not be blank" }
        headerValues["typ"] = type
    }

    /** Sets the `cty` header. */
    public fun contentType(contentType: String): JwtBuilder = apply {
        require(contentType.isNotBlank()) { "Content type must not be blank" }
        headerValues["cty"] = contentType
    }

    /** Sets the `kid` header, typically used to select a verification key. */
    public fun keyId(keyId: String): JwtBuilder = apply {
        require(keyId.isNotBlank()) { "Key id must not be blank" }
        headerValues["kid"] = keyId
    }

    /** Sets the `iss` claim. */
    public fun issuer(issuer: String): JwtBuilder = apply {
        require(issuer.isNotBlank()) { "Issuer must not be blank" }
        claimValues[CLAIM_ISSUER] = issuer
    }

    /** Sets the `sub` claim. */
    public fun subject(subject: String): JwtBuilder = apply {
        require(subject.isNotBlank()) { "Subject must not be blank" }
        claimValues[CLAIM_SUBJECT] = subject
    }

    /**
     * Sets the `aud` claim to a single audience.
     *
     * Calling this method again replaces the previous audience.
     */
    public fun audience(audience: String): JwtBuilder = apply {
        require(audience.isNotBlank()) { "Audience must not be blank" }
        claimValues[CLAIM_AUDIENCE] = audience
    }

    /**
     * Sets the `aud` claim to [audiences].
     *
     * One audience is encoded as a string and multiple audiences as a JSON array, matching
     * the JWT specification. Calling this method again replaces the previous audience.
     */
    public fun audience(audiences: Collection<String>): JwtBuilder = apply {
        require(audiences.isNotEmpty()) { "At least one audience is required" }
        audiences.forEach { require(it.isNotBlank()) { "Audience must not be blank" } }
        claimValues[CLAIM_AUDIENCE] = when (audiences.size) {
            1 -> audiences.first()
            else -> audiences.toList()
        }
    }

    /** Vararg overload of [audience]. */
    public fun audience(vararg audiences: String): JwtBuilder = audience(audiences.toList())

    /** Sets the `jti` claim. */
    public fun jwtId(jwtId: String): JwtBuilder = apply {
        require(jwtId.isNotBlank()) { "JWT id must not be blank" }
        claimValues[CLAIM_JWT_ID] = jwtId
    }

    /** Sets the `iat` claim. Sub-second precision is truncated to whole seconds. */
    public fun issuedAt(instant: Instant): JwtBuilder = apply {
        claimValues[CLAIM_ISSUED_AT] = instant.epochSecond
    }

    /** Sets the `nbf` claim. Sub-second precision is truncated to whole seconds. */
    public fun notBefore(instant: Instant): JwtBuilder = apply {
        claimValues[CLAIM_NOT_BEFORE] = instant.epochSecond
    }

    /** Sets the `exp` claim. Sub-second precision is truncated to whole seconds. */
    public fun expiresAt(instant: Instant): JwtBuilder = apply {
        claimValues[CLAIM_EXPIRATION] = instant.epochSecond
    }

    /** Sets `exp` to [clock]'s current instant plus [duration]. */
    public fun expiresIn(duration: Duration): JwtBuilder =
        expiresAt(clock.instant().plus(duration))

    /**
     * Adds or replaces a claim.
     *
     * An [Instant] supplied for `exp`, `nbf`, or `iat` is converted to a NumericDate.
     * Other values are passed to the [JsonCodec] unchanged.
     */
    public fun claim(name: String, value: Any?): JwtBuilder = apply {
        require(name.isNotBlank()) { "Claim name must not be blank" }
        claimValues[name] = normalizeClaim(name, value)
    }

    /** Adds or replaces several claims. */
    public fun claims(values: Map<String, Any?>): JwtBuilder = apply {
        values.forEach { (name, value) -> claim(name, value) }
    }

    /** Sets the signing algorithm and key. Calling this again replaces the previous signer. */
    public fun signWith(algorithm: JwsAlgorithm, key: Any): JwtBuilder = apply {
        signingAlgorithm = algorithm
        signingKey = key
    }

    /**
     * Signs the header and claims and returns the compact JWS serialization.
     *
     * @throws JwtException.ConfigurationException when the codec or signer is missing.
     * @throws JwtException.JsonCodecException when JSON encoding fails.
     * @throws JwtException.SigningException when the algorithm cannot sign.
     */
    public fun compact(): String {
        val codec = configured(codec) {
            "A JsonCodec is required. Call codec(...) before compact()."
        }
        val algorithm = configured(signingAlgorithm) {
            "A signing algorithm is required. Call signWith(...) before compact()."
        }
        val key = configured(signingKey) {
            "A signing key is required. Call signWith(...) before compact()."
        }
        if (algorithm.name.equals("none", ignoreCase = true)) {
            throw JwtException.ConfigurationException(
                "Unsecured JWTs (alg=none) are not supported",
            )
        }

        val header = LinkedHashMap<String, Any?>()
        header["alg"] = algorithm.name
        if (!headerValues.containsKey("typ")) {
            header["typ"] = "JWT"
        }
        header.putAll(headerValues)

        val headerJson = encode(codec, header, "header")
        val claimsJson = encode(codec, claimValues, "claims")

        val headerPart = Encoding.base64UrlEncode(headerJson.toByteArray(Charsets.UTF_8))
        val payloadPart = Encoding.base64UrlEncode(claimsJson.toByteArray(Charsets.UTF_8))
        val signingInput = "$headerPart.$payloadPart".toByteArray(Charsets.US_ASCII)

        val signature = try {
            algorithm.sign(signingInput, key)
        } catch (e: JwtException) {
            throw e
        } catch (e: Exception) {
            throw JwtException.SigningException(
                "Algorithm ${algorithm.name} failed to sign the JWT",
                e,
            )
        }

        if (signature.isEmpty()) {
            throw JwtException.SigningException(
                "Algorithm ${algorithm.name} produced an empty signature",
            )
        }

        return "$headerPart.$payloadPart.${Encoding.base64UrlEncode(signature)}"
    }

    private fun <T : Any> configured(value: T?, message: () -> String): T =
        value ?: throw JwtException.ConfigurationException(message())

    private fun normalizeClaim(name: String, value: Any?): Any? {
        return if (isNumericDateClaim(name) && value is Instant) value.epochSecond else value
    }

    private fun encode(codec: JsonCodec, value: Any?, partName: String): String {
        val json = try {
            codec.encode(value)
        } catch (e: JwtException) {
            throw e
        } catch (e: Exception) {
            throw JwtException.JsonCodecException(
                "Failed to encode JWT $partName as JSON",
                e,
            )
        }
        if (json.isBlank()) {
            throw JwtException.JsonCodecException(
                "JsonCodec returned blank JSON for the JWT $partName",
            )
        }
        return json
    }
}
