package com.rainccup.jwkt

import java.util.Collections

/**
 * A decoded JOSE protected header.
 *
 * Unknown header parameters are preserved and available through [values] and [get].
 */
public class JwtHeader internal constructor(values: Map<String, Any?>) {

    private val data: Map<String, Any?> = Collections.unmodifiableMap(LinkedHashMap(values))

    /** All protected header parameters, including the registered ones. */
    public val values: Map<String, Any?> = data

    /** The required `alg` header value. */
    public val algorithm: String = requiredString("alg")

    /** The optional `typ` header value. */
    public val type: String? = optionalString("typ")

    /** The optional `kid` header value, commonly used for key rotation. */
    public val keyId: String? = optionalString("kid")

    /** The optional `cty` header value. */
    public val contentType: String? = optionalString("cty")

    /**
     * The `crit` header values.
     *
     * JWKT supports no JWS extensions, so a non-empty list is rejected by the parser.
     * It is exposed for inspection and for callers that implement their own checks.
     */
    public val critical: List<String> = parseCritical()

    /**
     * Whether the payload is base64url encoded according to the `b64` header (RFC 7797).
     * Defaults to `true`. The parser rejects `false`, because JWKT only supports regular
     * JWS compact serialization.
     */
    public val isPayloadEncoded: Boolean = parsePayloadEncoding()

    /** Returns a header parameter, or `null` when it is absent. */
    public operator fun get(name: String): Any? = data[name]

    /** A copy of all header parameters. */
    public fun toMap(): Map<String, Any?> = LinkedHashMap(data)

    override fun toString(): String = "JwtHeader(values=$data)"

    private fun requiredString(name: String): String {
        val value = data[name]
            ?: throw JwtException.InvalidHeader("JWT header is missing '$name'")
        if (value !is String || value.isBlank()) {
            throw JwtException.InvalidHeader("JWT header '$name' must be a non-blank string")
        }
        return value
    }

    private fun optionalString(name: String): String? {
        val value = data[name] ?: return null
        if (value !is String) {
            throw JwtException.InvalidHeader("JWT header '$name' must be a JSON string")
        }
        return value
    }

    private fun parseCritical(): List<String> {
        val value = data["crit"] ?: return emptyList()
        if (value !is Iterable<*>) {
            throw JwtException.InvalidHeader("JWT header 'crit' must be an array of strings")
        }
        val result = ArrayList<String>()
        for (item in value) {
            if (item !is String || item.isBlank()) {
                throw JwtException.InvalidHeader(
                    "JWT header 'crit' must contain only non-blank strings",
                )
            }
            if (item in result) {
                throw JwtException.InvalidHeader(
                    "JWT header 'crit' contains duplicate entry '$item'",
                )
            }
            result += item
        }
        return Collections.unmodifiableList(result)
    }

    private fun parsePayloadEncoding(): Boolean {
        return when (val value = data["b64"]) {
            null -> true
            is Boolean -> value
            else -> throw JwtException.InvalidHeader(
                "JWT header 'b64' must be a JSON boolean",
            )
        }
    }
}
