package com.rainccup.jwkt.spring

import com.fasterxml.jackson.databind.ObjectMapper
import com.rainccup.jwkt.JsonCodec
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean

/**
 * Auto-configures a [JsonCodec] from Jackson 2 when Jackson 2 is on the classpath.
 *
 * The adapter is optional; applications can provide their own [JsonCodec] bean.
 */
@AutoConfiguration(
    afterName = [
        "org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration",
        "org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration",
    ],
)
@ConditionalOnClass(name = ["com.fasterxml.jackson.databind.ObjectMapper"])
@ConditionalOnProperty(prefix = "jwkt", name = ["enabled"], matchIfMissing = true)
public class JwktJackson2AutoConfiguration {

    /** Creates a Jackson 2 codec unless another [JsonCodec] bean exists. */
    @Bean
    @ConditionalOnBean(type = ["com.fasterxml.jackson.databind.ObjectMapper"])
    @ConditionalOnMissingBean(JsonCodec::class)
    public fun jackson2JsonCodec(mapper: ObjectMapper): JsonCodec =
        Jackson2JsonCodec(mapper)
}
