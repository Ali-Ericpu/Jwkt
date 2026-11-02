package com.rainccup.jwkt

import com.rainccup.jwkt.internal.CLAIM_AUDIENCE
import com.rainccup.jwkt.internal.CLAIM_EXPIRATION
import com.rainccup.jwkt.internal.CLAIM_ISSUED_AT
import com.rainccup.jwkt.internal.CLAIM_ISSUER
import com.rainccup.jwkt.internal.CLAIM_JWT_ID
import com.rainccup.jwkt.internal.CLAIM_NOT_BEFORE
import com.rainccup.jwkt.internal.CLAIM_SUBJECT
import com.rainccup.jwkt.internal.numericDate
import java.time.Instant
import java.util.Collections

/**
 * The decoded JWT payload.
 *
 * Registered claims are available through typed properties. Every claim, including custom
 * ones, is available through [values] and [get]. Values use the types produced by the
 * configured [JsonCodec].
 */
public class JwtClaims internal constructor(
    values: Map<String, Any?>,
    /** The original payload JSON. Useful for typed decoding. */
    public val rawJson: String,
    private val codec: JsonCodec,
) {

    private val data: Map<String, Any?> = Collections.unmodifiableMap(LinkedHashMap(values))

    /** All payload claims. */
    public val values: Map<String, Any?> = data

    /** The `iss` claim. */
    public val issuer: String? = optionalString(CLAIM_ISSUER)

    /** The `sub` claim. */
    public val subject: String? = optionalString(CLAIM_SUBJECT)

    /**
     * The `aud` claim normalized to a list.
     *
     * JWT permits either a single string or an array of strings, so both forms are exposed
     * as a list. An absent claim produces an empty list.
     */
    public val audience: List<String> = parseAudience()

    /** The `exp` claim as an instant. */
    public val expiration: Instant? = numericDate(CLAIM_EXPIRATION, data[CLAIM_EXPIRATION])

    /** The `nbf` claim as an instant. */
    public val notBefore: Instant? = numericDate(CLAIM_NOT_BEFORE, data[CLAIM_NOT_BEFORE])

    /** The `iat` claim as an instant. */
    public val issuedAt: Instant? = numericDate(CLAIM_ISSUED_AT, data[CLAIM_ISSUED_AT])

    /** The `jti` claim. */
    public val jwtId: String? = optionalString(CLAIM_JWT_ID)

    /** Returns a claim by name, or `null` when it is absent. */
    public operator fun get(name: String): Any? = data[name]

    /**
     * Decodes the original payload into [type] with the [JsonCodec] used to parse the token.
     *
     * This is intended for applications that prefer a typed claims model over a map.
     *
     * @throws JwtException.JsonCodecException when decoding fails or returns an incompatible type.
     */
    public fun <T : Any> asType(type: Class<T>): T {
        val decoded = try {
            codec.decode(rawJson, type)
        } catch (e: JwtException) {
            throw e
        } catch (e: Exception) {
            throw JwtException.JsonCodecException(
                "Failed to decode JWT claims as ${type.name}",
                e,
            )
        }

        if (decoded == null) {
            throw JwtException.JsonCodecException(
                "JsonCodec returned null when decoding JWT claims as ${type.name}",
            )
        }
        if (!type.isInstance(decoded)) {
            throw JwtException.JsonCodecException(
                "JsonCodec returned ${decoded.javaClass.name} when decoding JWT claims " +
                    "as ${type.name}",
            )
        }
        return type.cast(decoded)
    }

    /** Reified convenience overload of [asType]. Primitive Kotlin types use their boxed class. */
    public inline fun <reified T : Any> asType(): T = asType(T::class.javaObjectType)

    override fun toString(): String = "JwtClaims(values=$data)"

    private fun optionalString(name: String): String? {
        val value = data[name] ?: return null
        if (value !is String) {
            throw JwtException.InvalidClaims("JWT claim '$name' must be a JSON string")
        }
        return value
    }

    private fun parseAudience(): List<String> {
        val value = data[CLAIM_AUDIENCE] ?: return emptyList()
        if (value is String) {
            return listOf(value)
        }
        if (value !is Iterable<*>) {
            throw JwtException.InvalidClaims(
                "JWT claim '$CLAIM_AUDIENCE' must be a string or an array of strings",
            )
        }

        val result = ArrayList<String>()
        for (item in value) {
            if (item !is String) {
                throw JwtException.InvalidClaims(
                    "JWT claim '$CLAIM_AUDIENCE' must contain only strings",
                )
            }
            result += item
        }
        return Collections.unmodifiableList(result)
    }
}
