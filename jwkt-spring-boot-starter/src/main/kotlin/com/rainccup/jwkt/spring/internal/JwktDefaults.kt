package com.rainccup.jwkt.spring.internal

import com.rainccup.jwkt.JwtException
import com.rainccup.jwkt.spring.JwktProperties
import java.time.Duration
import java.util.Collections

/** Immutable snapshot of the token defaults from [JwktProperties]. */
internal class JwktDefaults private constructor(
    val issuer: String?,
    val audience: List<String>,
    val keyId: String?,
    val expiresIn: Duration?,
    val includeIssuedAt: Boolean,
    val headers: Map<String, Any>,
    val claims: Map<String, Any>,
) {

    companion object {
        private val RESERVED_HEADERS = setOf("alg", "b64", "crit")

        fun empty(): JwktDefaults = JwktDefaults(
            issuer = null,
            audience = emptyList(),
            keyId = null,
            expiresIn = null,
            includeIssuedAt = false,
            headers = emptyMap(),
            claims = emptyMap(),
        )

        fun from(properties: JwktProperties): JwktDefaults {
            val issuer = properties.issuer?.also {
                if (it.isBlank()) {
                    throw JwtException.ConfigurationException("jwkt.issuer must not be blank")
                }
            }
            val keyId = properties.keyId?.also {
                if (it.isBlank()) {
                    throw JwtException.ConfigurationException("jwkt.key-id must not be blank")
                }
            }
            if (properties.clockSkew.isNegative) {
                throw JwtException.ConfigurationException("jwkt.clock-skew must not be negative")
            }
            if (properties.expiresIn.isNegative) {
                throw JwtException.ConfigurationException("jwkt.expires-in must not be negative")
            }

            val audience = ArrayList<String>(properties.audience.size)
            for (value in properties.audience) {
                if (value.isBlank()) {
                    throw JwtException.ConfigurationException(
                        "jwkt.audience must not contain blank values",
                    )
                }
                audience += value
            }

            val headers = LinkedHashMap<String, Any>(properties.headers.size)
            for ((name, value) in properties.headers) {
                if (name.isBlank()) {
                    throw JwtException.ConfigurationException(
                        "jwkt.headers must not contain a blank header name",
                    )
                }
                if (name.lowercase() in RESERVED_HEADERS) {
                    throw JwtException.ConfigurationException(
                        "jwkt.headers must not set the reserved header '$name'",
                    )
                }
                headers[name] = value
            }

            val claims = LinkedHashMap<String, Any>(properties.claims.size)
            for ((name, value) in properties.claims) {
                if (name.isBlank()) {
                    throw JwtException.ConfigurationException(
                        "jwkt.claims must not contain a blank claim name",
                    )
                }
                claims[name] = value
            }

            return JwktDefaults(
                issuer = issuer,
                audience = Collections.unmodifiableList(audience),
                keyId = keyId,
                expiresIn = properties.expiresIn,
                includeIssuedAt = properties.includeIssuedAt,
                headers = Collections.unmodifiableMap(headers),
                claims = Collections.unmodifiableMap(claims),
            )
        }
    }
}
