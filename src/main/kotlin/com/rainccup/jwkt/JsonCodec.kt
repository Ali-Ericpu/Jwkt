package com.rainccup.jwkt

/**
 * The only bridge between JWKT and a JSON implementation.
 *
 * JWKT deliberately has no JSON dependency. Implement this interface with Jackson, Gson,
 * kotlinx.serialization, Moshi, or any other library that fits the application.
 *
 * Contract:
 * * [encode] must serialize maps, collections, strings, numbers, booleans, and `null`.
 * * [decode] with `Map::class.java` must return a JSON object as `Map<String, Any?>`.
 *   Nested objects may be maps or implementation-specific values; JWKT only reads the
 *   top-level header/claim values.
 * * [decode] must use the requested type for typed claim access through
 *   [JwtClaims.asType].
 *
 * Implementations must be thread-safe if a single instance is shared between threads.
 */
public interface JsonCodec {

    /**
     * Serializes [value] to a JSON string.
     *
     * @throws Exception when the value cannot be serialized. JWKT wraps non-JWT exceptions
     * in [JwtException.JsonCodecException].
     */
    public fun encode(value: Any?): String

    /**
     * Deserializes [json] into [type].
     *
     * @return the decoded value. For a JSON object this must be a [Map] with string keys.
     * @throws Exception when the JSON is invalid or cannot be converted to [type].
     */
    public fun decode(json: String, type: Class<*>): Any?
}
