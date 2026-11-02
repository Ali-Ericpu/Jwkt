package com.rainccup.jwkt.spring

import com.rainccup.jwkt.Jwt
import com.rainccup.jwkt.JwtBuilder
import com.rainccup.jwkt.JwtParser

/**
 * Convenience facade combining a [JwktSigner] and a [JwtParser].
 *
 * Both delegates are thread-safe.
 */
public class JwktTemplate(
    public val signer: JwktSigner,
    public val parser: JwtParser,
) {

    /** Creates a builder pre-populated by [signer]. */
    public fun builder(): JwtBuilder = signer.builder()

    /** Issues a token with the signer defaults. */
    public fun issue(): String = signer.issue()

    /** Issues a token after applying [configure]. */
    public fun issue(configure: JwtBuilder.() -> Unit): String = signer.issue(configure)

    /** Issues a token with extra or overridden claims. */
    public fun issue(claims: Map<String, Any?>): String = signer.issue(claims)

    /** Parses and verifies a token. */
    public fun parse(token: String): Jwt = parser.parse(token)

    /** Decodes a token without verifying it. Never use the result for authorization. */
    public fun parseUnverified(token: String): Jwt = parser.parseUnverified(token)
}
