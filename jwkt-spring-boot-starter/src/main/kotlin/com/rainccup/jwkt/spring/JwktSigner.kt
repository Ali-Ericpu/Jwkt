package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JsonCodec
import com.rainccup.jwkt.JwsAlgorithm
import com.rainccup.jwkt.JwtBuilder
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.spring.internal.JwktDefaults
import kotlin.time.Clock

/**
 * Thread-safe factory for JWTs signed with a fixed algorithm and key.
 *
 * The starter supplies a configured instance. It can also be constructed directly:
 *
 * ```kotlin
 * val signer = JwktSigner(codec, JwsAlgorithms.HS256, secret)
 * val token = signer.issue { subject("user-42") }
 * ```
 */
public class JwktSigner
internal constructor(
    private val codec: JsonCodec,
    algorithm: JwsAlgorithm,
    key: Any,
    private val clock: Clock,
    private val defaults: JwktDefaults,
) {

    /**
     * Creates a signer without starter defaults.
     *
     * No `exp`, `iat`, `iss`, or `aud` claims are added automatically; use [builder] or the
     * `issue` lambda to add them.
     */
    public constructor(
        codec: JsonCodec,
        algorithm: JwsAlgorithm,
        key: Any,
        clock: Clock = Clock.System,
    ) : this(codec, algorithm, key, clock, JwktDefaults.empty())

    private val algorithm: JwsAlgorithm = algorithm
    private val key: Any = if (key is ByteArray) key.copyOf() else key

    /** The algorithm used by this signer. */
    public val algorithmName: String
        get() = algorithm.name

    /** Creates a builder pre-populated with the configured defaults and signing key. */
    public fun builder(): JwtBuilder {
        val builder = Jwkt.builder(codec).clock(clock)
        defaults.issuer?.let(builder::issuer)
        if (defaults.audience.isNotEmpty()) {
            builder.audience(defaults.audience)
        }
        defaults.keyId?.let(builder::keyId)
        if (defaults.includeIssuedAt) {
            builder.issuedAt(clock.now())
        }
        defaults.expiresIn?.let(builder::expiresIn)
        // Explicitly configured headers and claims win over computed defaults.
        defaults.headers.forEach { (name, value) -> builder.header(name, value) }
        defaults.claims.forEach { (name, value) -> builder.claim(name, value) }
        return builder.signWith(algorithm, key)
    }

    /** Issues a token with the configured defaults. */
    public fun issue(): String = builder().compact()

    /** Issues a token after applying [configure] to the default-populated builder. */
    public fun issue(configure: JwtBuilder.() -> Unit): String =
        builder().apply(configure).compact()

    /** Issues a token with extra or overridden claims. */
    public fun issue(claims: Map<String, Any?>): String = issue {
        claims.forEach { (name, value) -> claim(name, value) }
    }
}
