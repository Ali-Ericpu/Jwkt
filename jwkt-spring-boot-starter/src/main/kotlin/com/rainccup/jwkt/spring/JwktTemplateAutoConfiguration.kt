package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JwtParser
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean

/**
 * Auto-configures a [JwktTemplate] when both a signer and a parser are available.
 */
@AutoConfiguration(after = [JwktAutoConfiguration::class])
@ConditionalOnBean(value = [JwtParser::class, JwktSigner::class])
@ConditionalOnProperty(prefix = "jwkt", name = ["enabled"], matchIfMissing = true)
public class JwktTemplateAutoConfiguration {

    /** Creates the combined template unless the application defines one. */
    @Bean
    @ConditionalOnMissingBean(JwktTemplate::class)
    public fun jwktTemplate(parser: JwtParser, signer: JwktSigner): JwktTemplate =
        JwktTemplate(signer, parser)
}
