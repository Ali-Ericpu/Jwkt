package com.rainccup.jwkt

/**
 * Entry points for JWKT.
 *
 * JWKT does not bundle a JSON library. Supply a [JsonCodec] backed by kotlinx.serialization,
 * Jackson, Gson, Moshi, or a hand-written encoder:
 *
 * ```kotlin
 * val codec = MyJsonCodec()
 *
 * val token = Jwkt.builder(codec)
 *     .subject("user-42")
 *     .expiresIn(15.minutes)
 *     .signWith(JwsAlgorithms.HS256, secret)
 *     .compact()
 *
 * val jwt = Jwkt.parser(codec)
 *     .verifyWith(JwsAlgorithms.HS256, secret)
 *     .requireSubject("user-42")
 *     .build()
 *     .parse(token)
 * ```
 */
public object Jwkt {

    /** The JWKT library version. */
    public const val VERSION: String = "0.1.0"

    /** Creates a builder without a codec. Call [JwtBuilder.codec] before [JwtBuilder.compact]. */
    @JvmStatic
    public fun builder(): JwtBuilder = JwtBuilder()

    /** Creates a builder that uses [codec] for header and payload JSON. */
    @JvmStatic
    public fun builder(codec: JsonCodec): JwtBuilder = JwtBuilder().codec(codec)

    /** Creates a parser builder without a codec. Call [JwtParserBuilder.codec] before build(). */
    @JvmStatic
    public fun parser(): JwtParserBuilder = JwtParserBuilder()

    /** Creates a parser builder that uses [codec] for header and payload JSON. */
    @JvmStatic
    public fun parser(codec: JsonCodec): JwtParserBuilder =
        JwtParserBuilder().codec(codec)

    /**
     * Decodes a token without verifying it.
     *
     * This is a convenience for reading `kid` or `alg` before key selection. The returned
     * [Jwt.isVerified] is `false`; never authorize a request from this result.
     */
    @JvmStatic
    public fun parseUnverified(token: String, codec: JsonCodec): Jwt =
        parser(codec).build().parseUnverified(token)
}
