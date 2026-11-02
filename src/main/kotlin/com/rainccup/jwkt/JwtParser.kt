package com.rainccup.jwkt

import com.rainccup.jwkt.internal.CLAIM_AUDIENCE
import com.rainccup.jwkt.internal.CLAIM_EXPIRATION
import com.rainccup.jwkt.internal.CLAIM_ISSUER
import com.rainccup.jwkt.internal.CLAIM_SUBJECT
import com.rainccup.jwkt.internal.Encoding
import java.math.BigDecimal
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant

private const val DEFAULT_MAX_TOKEN_LENGTH = 16 * 1024

/**
 * Fluent builder for a thread-safe [JwtParser].
 *
 * ```kotlin
 * val parser = Jwkt.parser(codec)
 *     .verifyWith(JwsAlgorithms.HS256, secret)
 *     .requireIssuer("https://issuer.example")
 *     .requireAudience("api")
 *     .build()
 *
 * val jwt = parser.parse(token)
 * ```
 *
 * A parser can be built without a verification key and used only with
 * [JwtParser.parseUnverified], but [JwtParser.parse] then fails with a configuration error.
 *
 * Builders are mutable and not thread-safe. Do not share one between threads.
 */
public class JwtParserBuilder internal constructor() {

    private var codec: JsonCodec? = null
    private var keyResolver: JwsKeyResolver? = null
    private val verificationKeys: MutableMap<String, JwsVerificationKey> = LinkedHashMap()
    private var clock: Clock = Clock.System
    private var clockSkew: Duration = Duration.ZERO
    private var maxTokenLength: Int = DEFAULT_MAX_TOKEN_LENGTH
    private var requireExpiration: Boolean = false
    private var requiredIssuer: String? = null
    private var requiredSubject: String? = null
    private val requiredAudiences: MutableSet<String> = LinkedHashSet()
    private val requiredClaimNames: MutableSet<String> = LinkedHashSet()
    private val requiredClaimValues: MutableMap<String, Any?> = LinkedHashMap()
    private val validators: MutableList<JwtValidator> = ArrayList()

    /** Sets the JSON implementation used to decode the header and payload. */
    public fun codec(codec: JsonCodec): JwtParserBuilder = apply {
        this.codec = codec
    }

    /** Sets the clock used for `exp` and `nbf` validation. */
    public fun clock(clock: Clock): JwtParserBuilder = apply {
        this.clock = clock
    }

    /**
     * Sets the allowed clock skew for `exp` and `nbf`.
     *
     * The value must be zero or positive.
     */
    public fun clockSkew(skew: Duration): JwtParserBuilder = apply {
        require(!skew.isNegative()) { "Clock skew must not be negative" }
        clockSkew = skew
    }

    /**
     * Sets the maximum accepted compact-token length in characters.
     *
     * The default is 16 KiB. The limit is checked before any base64 or JSON work.
     */
    public fun maxTokenLength(length: Int): JwtParserBuilder = apply {
        require(length > 0) { "Maximum token length must be positive" }
        maxTokenLength = length
    }

    /** Rejects tokens that do not carry an `exp` claim. */
    public fun requireExpiration(): JwtParserBuilder = apply {
        requireExpiration = true
    }

    /** Adds a static verification algorithm and key. */
    public fun verifyWith(algorithm: JwsAlgorithm, key: Any): JwtParserBuilder =
        verifyWith(JwsVerificationKey(algorithm, key))

    /**
     * Adds a static verification algorithm and key.
     *
     * Only one key is allowed per algorithm name. Use [verifyWith] with a [JwsKeyResolver]
     * for key rotation.
     */
    public fun verifyWith(verificationKey: JwsVerificationKey): JwtParserBuilder = apply {
        addVerificationKey(verificationKey)
    }

    /** Adds several static verification keys. */
    public fun verifyWith(vararg verificationKeys: JwsVerificationKey): JwtParserBuilder = apply {
        verificationKeys.forEach { addVerificationKey(it) }
    }

    /**
     * Sets a resolver that selects a key from the token header.
     *
     * Static keys are checked first; the resolver is called when no static key matches the
     * header algorithm. A resolver result whose algorithm name differs from the header
     * `alg` is rejected.
     */
    public fun verifyWith(resolver: JwsKeyResolver): JwtParserBuilder = apply {
        keyResolver = resolver
    }

    /** Requires an exact `iss` value. */
    public fun requireIssuer(issuer: String): JwtParserBuilder = apply {
        require(issuer.isNotBlank()) { "Issuer must not be blank" }
        requiredIssuer = issuer
    }

    /** Requires an exact `sub` value. */
    public fun requireSubject(subject: String): JwtParserBuilder = apply {
        require(subject.isNotBlank()) { "Subject must not be blank" }
        requiredSubject = subject
    }

    /** Requires the `aud` claim to contain [audience]. */
    public fun requireAudience(audience: String): JwtParserBuilder = apply {
        require(audience.isNotBlank()) { "Audience must not be blank" }
        requiredAudiences += audience
    }

    /** Requires a claim to be present. A JSON null value counts as present. */
    public fun requireClaim(name: String): JwtParserBuilder = apply {
        require(name.isNotBlank()) { "Claim name must not be blank" }
        requiredClaimNames += name
    }

    /** Requires a claim to be present and equal to [expected]. */
    public fun requireClaim(name: String, expected: Any?): JwtParserBuilder = apply {
        require(name.isNotBlank()) { "Claim name must not be blank" }
        requiredClaimNames += name
        requiredClaimValues[name] = expected
    }

    /** Adds an application-specific validator. */
    public fun validateWith(validator: JwtValidator): JwtParserBuilder = apply {
        validators += validator
    }

    /** Builds an immutable parser. */
    public fun build(): JwtParser {
        val codec = codec ?: throw JwtException.ConfigurationException(
            "A JsonCodec is required. Call codec(...) before build().",
        )
        return JwtParser(
            codec = codec,
            verificationKeys = verificationKeys.toMap(),
            keyResolver = keyResolver,
            clock = clock,
            clockSkew = clockSkew,
            maxTokenLength = maxTokenLength,
            requireExpiration = requireExpiration,
            requiredIssuer = requiredIssuer,
            requiredSubject = requiredSubject,
            requiredAudiences = requiredAudiences.toSet(),
            requiredClaimNames = requiredClaimNames.toSet(),
            requiredClaimValues = requiredClaimValues.toMap(),
            validators = validators.toList(),
        )
    }

    private fun addVerificationKey(verificationKey: JwsVerificationKey) {
        val name = verificationKey.algorithm.name
        val previous = verificationKeys.putIfAbsent(name, verificationKey)
        if (previous != null) {
            throw JwtException.ConfigurationException(
                "A verification key for algorithm '$name' is already configured. " +
                    "Use a JwsKeyResolver for multiple keys with the same algorithm.",
            )
        }
    }
}

/**
 * A thread-safe JWT parser.
 *
 * [parse] verifies the signature, validates `exp` and `nbf`, checks required claims, and
 * then runs application validators. [parseUnverified] performs syntax and JSON decoding only;
 * never use it to authorize a request.
 */
public class JwtParser internal constructor(
    private val codec: JsonCodec,
    private val verificationKeys: Map<String, JwsVerificationKey>,
    private val keyResolver: JwsKeyResolver?,
    private val clock: Clock,
    private val clockSkew: Duration,
    private val maxTokenLength: Int,
    private val requireExpiration: Boolean,
    private val requiredIssuer: String?,
    private val requiredSubject: String?,
    private val requiredAudiences: Set<String>,
    private val requiredClaimNames: Set<String>,
    private val requiredClaimValues: Map<String, Any?>,
    private val validators: List<JwtValidator>,
) {

    /**
     * Parses, verifies, and validates a compact JWS token.
     *
     * @throws JwtException.MalformedToken for a malformed compact serialization or invalid JSON.
     * @throws JwtException.InvalidHeader for an unsupported or malformed protected header.
     * @throws JwtException.UnsupportedAlgorithm when no verifier matches the header.
     * @throws JwtException.InvalidSignature when the signature is invalid.
     * @throws JwtException.InvalidClaims when a registered claim has the wrong type.
     * @throws JwtException.ExpiredToken when `exp` has passed (plus allowed skew).
     * @throws JwtException.NotYetValidToken when `nbf` is in the future (plus allowed skew).
     * @throws JwtException.MissingClaim / [JwtException.ClaimMismatch] for required claims.
     */
    public fun parse(token: String): Jwt {
        val parts = splitCompact(token)
        val header = parseHeader(parts[0])

        if (verificationKeys.isEmpty() && keyResolver == null) {
            throw JwtException.ConfigurationException(
                "No verification key is configured. Call verifyWith(...) before parse().",
            )
        }

        val verifier = selectVerifier(header)
        val signature = Encoding.base64UrlDecode(parts[2], "signature")
        val signingInput = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)

        val valid = try {
            verifier.algorithm.verify(signingInput, signature, verifier.key)
        } catch (e: JwtException) {
            throw e
        } catch (e: Exception) {
            throw JwtException.VerificationException(
                "Algorithm ${verifier.algorithm.name} failed to verify the JWT",
                e,
            )
        }
        if (!valid) {
            throw JwtException.InvalidSignature()
        }

        // Decode untrusted JSON only after the signature has been verified.
        val payloadJson = decodeJsonPart(parts[1], "payload")
        val claims = JwtClaims(decodeObject(payloadJson, "payload"), payloadJson, codec)
        val jwt = Jwt(
            header = header,
            claims = claims,
            signature = signature,
            token = token,
            isVerified = true,
        )
        validate(jwt)
        return jwt
    }

    /**
     * Decodes a compact JWS without verifying its signature or validating its claims.
     *
     * The returned [Jwt.isVerified] is `false`. This is useful for reading `kid` or `alg`
     * before key selection, but the result must not be trusted for authorization.
     */
    public fun parseUnverified(token: String): Jwt {
        val parts = splitCompact(token)
        val header = parseHeader(parts[0])
        val payloadJson = decodeJsonPart(parts[1], "payload")
        val claims = JwtClaims(decodeObject(payloadJson, "payload"), payloadJson, codec)
        val signature = Encoding.base64UrlDecode(parts[2], "signature")
        return Jwt(
            header = header,
            claims = claims,
            signature = signature,
            token = token,
            isVerified = false,
        )
    }

    private fun splitCompact(token: String): Array<String> {
        if (token.length > maxTokenLength) {
            throw JwtException.MalformedToken(
                "JWT exceeds the maximum length of $maxTokenLength characters",
            )
        }
        val firstDot = token.indexOf('.')
        if (firstDot <= 0) {
            throw JwtException.MalformedToken(
                "JWT must have three dot-separated parts",
            )
        }
        val secondDot = token.indexOf('.', firstDot + 1)
        if (secondDot < 0) {
            throw JwtException.MalformedToken(
                "JWT must have three dot-separated parts",
            )
        }
        if (token.indexOf('.', secondDot + 1) >= 0) {
            throw JwtException.MalformedToken(
                "JWT must have exactly three dot-separated parts",
            )
        }
        if (secondDot == firstDot + 1) {
            throw JwtException.MalformedToken("JWT payload must not be empty")
        }
        return arrayOf(
            token.substring(0, firstDot),
            token.substring(firstDot + 1, secondDot),
            token.substring(secondDot + 1),
        )
    }

    private fun parseHeader(encodedHeader: String): JwtHeader {
        val headerJson = decodeJsonPart(encodedHeader, "header")
        val header = JwtHeader(decodeObject(headerJson, "header"))
        if (header.algorithm.equals("none", ignoreCase = true)) {
            throw JwtException.InvalidHeader(
                "Unsecured JWTs (alg=none) are not supported",
            )
        }
        if (header.values.containsKey("crit")) {
            val critical = header.critical
            val message = if (critical.isEmpty()) {
                "The 'crit' JWS header must not be empty"
            } else {
                "Unsupported critical JWS header(s): ${critical.joinToString()}"
            }
            throw JwtException.InvalidHeader(message)
        }
        if (!header.isPayloadEncoded) {
            throw JwtException.InvalidHeader(
                "JWS b64=false (RFC 7797 unencoded payload) is not supported",
            )
        }
        return header
    }

    private fun decodeJsonPart(encoded: String, partName: String): String {
        if (encoded.isEmpty()) {
            throw JwtException.MalformedToken("JWT $partName must not be empty")
        }
        val bytes = Encoding.base64UrlDecode(encoded, partName)
        if (bytes.isEmpty()) {
            throw JwtException.MalformedToken("JWT $partName must not be empty")
        }
        return Encoding.utf8Decode(bytes, partName)
    }

    private fun decodeObject(json: String, partName: String): Map<String, Any?> {
        val decoded = try {
            codec.decode(json, Map::class.java)
        } catch (e: JwtException.JsonCodecException) {
            throw JwtException.MalformedToken(
                "Failed to decode JWT $partName JSON",
                e,
            )
        } catch (e: JwtException) {
            throw e
        } catch (e: Exception) {
            throw JwtException.MalformedToken(
                "Failed to decode JWT $partName JSON",
                e,
            )
        }

        if (decoded !is Map<*, *>) {
            throw JwtException.MalformedToken("JWT $partName must be a JSON object")
        }

        val result = LinkedHashMap<String, Any?>(decoded.size)
        for ((name, value) in decoded) {
            if (name !is String) {
                throw JwtException.MalformedToken(
                    "JWT $partName must contain only string keys",
                )
            }
            result[name] = value
        }
        return result
    }

    private fun selectVerifier(header: JwtHeader): JwsVerificationKey {
        val static = verificationKeys[header.algorithm]
        val selected = static
            ?: try {
                keyResolver?.resolve(header)
            } catch (e: JwtException) {
                throw e
            } catch (e: Exception) {
                throw JwtException.VerificationException("JWT key resolver failed", e)
            } ?: throw JwtException.UnsupportedAlgorithm(header.algorithm)

        if (selected.algorithm.name != header.algorithm) {
            throw JwtException.AlgorithmMismatch(
                headerAlgorithm = header.algorithm,
                configuredAlgorithm = selected.algorithm.name,
            )
        }
        return selected
    }

    private fun validate(jwt: Jwt) {
        val claims = jwt.claims
        val now = clock.now()

        val expiration = claims.expiration
        if (requireExpiration && expiration == null) {
            throw JwtException.MissingClaim(CLAIM_EXPIRATION)
        }
        if (expiration != null && now >= expiration.plus(clockSkew)) {
            throw JwtException.ExpiredToken(expiration, now)
        }

        val notBefore = claims.notBefore
        if (notBefore != null && now.plus(clockSkew) < notBefore) {
            throw JwtException.NotYetValidToken(notBefore, now)
        }

        val issuer = requiredIssuer
        if (issuer != null && claims.issuer != issuer) {
            throw JwtException.ClaimMismatch(CLAIM_ISSUER, issuer, claims.issuer)
        }

        val subject = requiredSubject
        if (subject != null && claims.subject != subject) {
            throw JwtException.ClaimMismatch(CLAIM_SUBJECT, subject, claims.subject)
        }

        if (requiredAudiences.isNotEmpty()) {
            for (audience in requiredAudiences) {
                if (audience !in claims.audience) {
                    throw JwtException.ClaimMismatch(
                        CLAIM_AUDIENCE,
                        audience,
                        claims.audience,
                    )
                }
            }
        }

        for (name in requiredClaimNames) {
            if (!claims.values.containsKey(name)) {
                throw JwtException.MissingClaim(name)
            }
            if (requiredClaimValues.containsKey(name)) {
                val expected = requiredClaimValues[name]
                val actual = claims.values[name]
                if (!claimValueMatches(expected, actual)) {
                    throw JwtException.ClaimMismatch(name, expected, actual)
                }
            }
        }

        for (validator in validators) {
            validator.validate(jwt)
        }
    }

    /**
     * Compares required claim values without depending on the JSON number subtype.
     * [Instant] expectations match numeric dates written as epoch seconds.
     */
    private fun claimValueMatches(expected: Any?, actual: Any?): Boolean {
        if (expected == actual) {
            return true
        }
        if (expected is Number && actual is Number) {
            return decimal(expected).compareTo(decimal(actual)) == 0
        }
        if (expected is Instant) {
            val timestamp = BigDecimal.valueOf(expected.epochSeconds)
                .add(expected.nanosecondsOfSecond.toBigDecimal().movePointLeft(9))
            if (actual is Number) {
                return timestamp.compareTo(decimal(actual)) == 0
            }
            if (actual is Instant) {
                return expected == actual
            }
        }
        return false
    }

    private fun decimal(number: Number): BigDecimal =
        try {
            number.toString().toBigDecimal()
        } catch (e: NumberFormatException) {
            throw JwtException.InvalidClaims("JWT claim value is not a finite number", e)
        }
}
