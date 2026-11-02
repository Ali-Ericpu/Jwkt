package com.rainccup.jwkt.spring

import com.fasterxml.jackson.databind.ObjectMapper
import com.rainccup.jwkt.JsonCodec
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import java.util.function.Supplier

class Jackson2JsonCodecTest {

    private val secret = "0123456789abcdef0123456789abcdef"

    @Test
    fun `auto-configures the Jackson 2 codec`() {
        ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(
                    JwktJackson2AutoConfiguration::class.java,
                    JwktAutoConfiguration::class.java,
                    JwktTemplateAutoConfiguration::class.java,
                ),
            )
            .withBean(ObjectMapper::class.java, Supplier { ObjectMapper() })
            .withPropertyValues("jwkt.secret=$secret")
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context.getBean(JsonCodec::class.java))
                    .isInstanceOf(Jackson2JsonCodec::class.java)

                val template = context.getBean(JwktTemplate::class.java)
                val jwt = template.parse(
                    template.issue {
                        subject("user-42")
                        claim("role", "admin")
                    },
                )
                assertThat(jwt.claims.subject).isEqualTo("user-42")
                assertThat(jwt.claims["role"]).isEqualTo("admin")
            }
    }

    @Test
    fun `does not configure the codec when jwkt is disabled`() {
        ApplicationContextRunner()
            .withConfiguration(
                AutoConfigurations.of(JwktJackson2AutoConfiguration::class.java),
            )
            .withBean(ObjectMapper::class.java, Supplier { ObjectMapper() })
            .withPropertyValues("jwkt.enabled=false")
            .run { context ->
                assertThat(context).hasNotFailed()
                assertThat(context).doesNotHaveBean(JsonCodec::class.java)
            }
    }

    @Test
    fun `wraps Jackson failures as JsonCodecException`() {
        val codec = Jackson2JsonCodec(ObjectMapper())
        val result = runCatching { codec.decode("{not-json", Map::class.java) }
        assertThat(result.exceptionOrNull())
            .isInstanceOf(com.rainccup.jwkt.JwtException.JsonCodecException::class.java)
    }
}
