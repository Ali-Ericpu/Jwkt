package com.rainccup.jwkt.spring

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.SpringBootConfiguration
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.beans.factory.annotation.Autowired

@SpringBootTest(
    classes = [StarterIntegrationTest.TestApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.NONE,
    properties = ["jwkt.secret=0123456789abcdef0123456789abcdef"],
)
class StarterIntegrationTest {

    @Autowired
    private lateinit var template: JwktTemplate

    @Test
    fun `auto-configuration is discovered from the imports file`() {
        val token = template.issue {
            subject("user-42")
            audience("api")
        }

        val jwt = template.parse(token)
        assertThat(jwt.isVerified).isTrue()
        assertThat(jwt.claims.subject).isEqualTo("user-42")
        assertThat(jwt.claims.audience).containsExactly("api")
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    class TestApplication
}
