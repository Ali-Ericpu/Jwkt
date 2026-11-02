package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JsonCodec
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import tools.jackson.databind.ObjectMapper

/**
 * Auto-configures a [JsonCodec] from Jackson 3 when Jackson 3 is on the classpath.
 *
 * The adapter is optional; applications can provide their own [JsonCodec] bean.
 */
@AutoConfiguration(
    beforeName = ["com.rainccup.jwkt.spring.JwktJackson2AutoConfiguration"],
    afterName = [
        "org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration",
        "org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration",
    ],
)
@ConditionalOnClass(name = ["tools.jackson.databind.ObjectMapper"])
@ConditionalOnProperty(prefix = "jwkt", name = ["enabled"], matchIfMissing = true)
public class JwktJackson3AutoConfiguration {

    /** Creates a Jackson 3 codec unless another [JsonCodec] bean exists. */
    @Bean
    @ConditionalOnBean(type = ["tools.jackson.databind.ObjectMapper"])
    @ConditionalOnMissingBean(JsonCodec::class)
    public fun jackson3JsonCodec(mapper: ObjectMapper): JsonCodec =
        Jackson3JsonCodec(mapper)
}
