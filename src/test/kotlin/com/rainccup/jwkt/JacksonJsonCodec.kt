package com.rainccup.jwkt

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper

/**
 * Test-only adapter showing the intended integration point. Applications can use any JSON
 * library; JWKT itself has no Jackson dependency.
 */
internal class JacksonJsonCodec : JsonCodec {

    private val mapper = ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    override fun encode(value: Any?): String = mapper.writeValueAsString(value)

    override fun decode(json: String, type: Class<*>): Any? = mapper.readValue(json, type)
}
