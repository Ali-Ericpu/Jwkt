package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JsonCodec
import com.rainccup.jwkt.JwsAlgorithm
import com.rainccup.jwkt.JwsAlgorithms
import com.rainccup.jwkt.JwtException
import com.rainccup.jwkt.JwtParser
import com.rainccup.jwkt.JwtValidator
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.spring.internal.JwktAnyKeyCondition
import com.rainccup.jwkt.spring.internal.JwktDefaults
import com.rainccup.jwkt.spring.internal.JwktKeyMaterial
import com.rainccup.jwkt.spring.internal.JwktKeys
import com.rainccup.jwkt.spring.internal.JwktSigningKeyCondition
import com.rainccup.jwkt.spring.internal.JwktVerificationKeyCondition
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Conditional
import kotlin.time.Clock

/**
 * Core auto-configuration for JWKT.
 *
 * A [JwtParser] is created when a verification key is configured, a [JwktSigner] when a
 * signing key is configured, and a [JwktTemplate] when both are available.
 */
@AutoConfiguration(
    after = [JwktJackson2AutoConfiguration::class, JwktJackson3AutoConfiguration::class],
)
@ConditionalOnProperty(prefix = "jwkt", name = ["enabled"], matchIfMissing = true)
@EnableConfigurationProperties(JwktProperties::class)
public class JwktAutoConfiguration {

    /** Provides a UTC clock unless the application defines one. */
    @Bean
    @ConditionalOnMissingBean(Clock::class)
    public fun jwktClock(): Clock = Clock.System

    /** Resolves the configured built-in algorithm unless a custom bean is present. */
    @Bean
    @ConditionalOnMissingBean(JwsAlgorithm::class)
    public fun jwktAlgorithm(properties: JwktProperties): JwsAlgorithm {
        val name = properties.algorithm.trim()
        if (name.isEmpty()) {
            throw JwtException.ConfigurationException("jwkt.algorithm must not be blank")
        }
        return JwsAlgorithms.find(name)
            ?: throw JwtException.ConfigurationException(
                "Unknown JWS algorithm '$name'. Define a JwsAlgorithm bean with that name " +
                    "or use a built-in algorithm.",
            )
    }

    /** Loads the configured key material. */
    @Bean
    @ConditionalOnMissingBean(JwktKeyMaterial::class)
    @Conditional(JwktAnyKeyCondition::class)
    public fun jwktKeyMaterial(
        properties: JwktProperties,
        algorithms: ObjectProvider<JwsAlgorithm>,
    ): JwktKeyMaterial = JwktKeys.create(properties, algorithms.orderedStream().toList())

    /** Creates the parser when a verification key and a JSON codec are available. */
    @Bean
    @ConditionalOnMissingBean(JwtParser::class)
    @ConditionalOnBean(JsonCodec::class)
    @Conditional(JwktVerificationKeyCondition::class)
    public fun jwktParser(
        properties: JwktProperties,
        codec: JsonCodec,
        clock: Clock,
        material: JwktKeyMaterial,
        validators: ObjectProvider<JwtValidator>,
    ): JwtParser {
        validateParsing(properties)
        val key = material.verificationKey
            ?: throw JwtException.ConfigurationException(
                "No verification key is available for algorithm ${material.algorithm.name}",
            )

        val builder = Jwkt.parser(codec)
            .clock(clock)
            .clockSkew(properties.clockSkew)
            .verifyWith(material.algorithm, key)

        if (properties.requireExpiration) {
            builder.requireExpiration()
        }
        properties.issuer?.let(builder::requireIssuer)
        properties.audience.forEach(builder::requireAudience)
        properties.requiredClaims.forEach(builder::requireClaim)
        validators.orderedStream().forEach(builder::validateWith)
        return builder.build()
    }

    /** Creates the signer when a signing key and a JSON codec are available. */
    @Bean
    @ConditionalOnMissingBean(JwktSigner::class)
    @ConditionalOnBean(JsonCodec::class)
    @Conditional(JwktSigningKeyCondition::class)
    public fun jwktSigner(
        properties: JwktProperties,
        codec: JsonCodec,
        clock: Clock,
        material: JwktKeyMaterial,
    ): JwktSigner {
        val key = material.signingKey
            ?: throw JwtException.ConfigurationException(
                "No signing key is available for algorithm ${material.algorithm.name}",
            )
        return JwktSigner(
            codec = codec,
            algorithm = material.algorithm,
            key = key,
            clock = clock,
            defaults = JwktDefaults.from(properties),
        )
    }

    private fun validateParsing(properties: JwktProperties) {
        if (properties.clockSkew.isNegative()) {
            throw JwtException.ConfigurationException("jwkt.clock-skew must not be negative")
        }
        if (properties.issuer?.isBlank() == true) {
            throw JwtException.ConfigurationException("jwkt.issuer must not be blank")
        }
        if (properties.audience.any { it.isBlank() }) {
            throw JwtException.ConfigurationException(
                "jwkt.audience must not contain blank values",
            )
        }
        if (properties.requiredClaims.any { it.isBlank() }) {
            throw JwtException.ConfigurationException(
                "jwkt.required-claims must not contain blank values",
            )
        }
    }
}
