package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JsonCodec
import com.rainccup.jwkt.JwsAlgorithms
import com.rainccup.jwkt.JwtException
import com.rainccup.jwkt.JwtParser
import com.rainccup.jwkt.Jwkt
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import java.util.function.Supplier
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class JwktAutoConfigurationTest {

    private val secret = "0123456789abcdef0123456789abcdef"

    private fun runner(): ApplicationContextRunner =
        ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(
                    JwktAutoConfiguration::class.java,
                    JwktTemplateAutoConfiguration::class.java,
                ),
            )
            .withBean(JsonCodec::class.java, Supplier { SerializationJsonCodec() })

    @Test
    fun `auto-configures signer parser and template for HMAC`() {
        runner()
            .withPropertyValues(
                "jwkt.secret=$secret",
                "jwkt.issuer=https://issuer.example",
                "jwkt.audience=api",
                "jwkt.required-claims=tenant",
                "jwkt.claims.tenant=acme",
                "jwkt.expires-in=5m",
            )
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context).hasSingleBean(JwktSigner::class.java)
                assertThat(context).hasSingleBean(JwtParser::class.java)
                assertThat(context).hasSingleBean(JwktTemplate::class.java)
                assertThat(context.getBean(JsonCodec::class.java))
                    .isInstanceOf(SerializationJsonCodec::class.java)

                val template = context.getBean(JwktTemplate::class.java)
                val jwt = template.parse(template.issue { subject("user-42") })

                assertThat(jwt.isVerified).isTrue()
                assertThat(jwt.claims.subject).isEqualTo("user-42")
                assertThat(jwt.claims.issuer).isEqualTo("https://issuer.example")
                assertThat(jwt.claims.audience).containsExactly("api")
                assertThat(jwt.claims["tenant"]).isEqualTo("acme")
                assertThat(jwt.claims.expiration).isNotNull()
                assertThat(jwt.claims.issuedAt).isNotNull()
            }
    }

    @Test
    fun `binds Kotlin duration properties`() {
        runner()
            .withPropertyValues(
                "jwkt.secret=$secret",
                "jwkt.clock-skew=30s",
                "jwkt.expires-in=2m",
            )
            .run { context ->
                assertThat(context).hasNotFailed()
                val properties = context.getBean(JwktProperties::class.java)
                assertThat(properties.clockSkew).isEqualTo(30.seconds)
                assertThat(properties.expiresIn).isEqualTo(2.minutes)
            }
    }

    @Test
    fun `does not create key-dependent beans without a key`() {
        runner().run { context ->
            assertThat(context).hasNotFailed()
            assertThat(context).doesNotHaveBean(JwktSigner::class.java)
            assertThat(context).doesNotHaveBean(JwtParser::class.java)
            assertThat(context).doesNotHaveBean(JwktTemplate::class.java)
        }
    }

    @Test
    fun `can be disabled`() {
        runner()
            .withPropertyValues("jwkt.enabled=false")
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context).doesNotHaveBean(JwktSigner::class.java)
                assertThat(context).doesNotHaveBean(JwtParser::class.java)
                assertThat(context).doesNotHaveBean(JwktTemplate::class.java)
            }
    }

    @Test
    fun `enforces required claims during parsing`() {
        runner()
            .withPropertyValues(
                "jwkt.secret=$secret",
                "jwkt.required-claims=tenant",
            )
            .run { context ->
                assertThat(context).hasNotFailed()
                val template = context.getBean(JwktTemplate::class.java)
                val token = template.issue { subject("user-42") }

                assertThatThrownBy { template.parse(token) }
                    .isInstanceOf(JwtException.MissingClaim::class.java)
            }
    }

    @Test
    fun `honors an application-defined parser`() {
        val codec = SerializationJsonCodec()
        val parser = Jwkt.parser(codec)
            .verifyWith(JwsAlgorithms.HS256, secret.toByteArray())
            .build()

        ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(
                    JwktAutoConfiguration::class.java,
                    JwktTemplateAutoConfiguration::class.java,
                ),
            )
            .withBean(JsonCodec::class.java, Supplier { codec })
            .withBean(JwtParser::class.java, Supplier { parser })
            .withPropertyValues("jwkt.secret=$secret")
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context.getBean(JwktTemplate::class.java).parser)
                    .isSameAs(parser)
            }
    }
}
