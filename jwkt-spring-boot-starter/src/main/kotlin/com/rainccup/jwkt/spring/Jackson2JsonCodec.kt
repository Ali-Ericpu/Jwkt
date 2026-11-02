package com.rainccup.jwkt.spring

import com.fasterxml.jackson.databind.ObjectMapper
import com.rainccup.jwkt.JsonCodec
import com.rainccup.jwkt.JwtException

/**
 * [JsonCodec] backed by Jackson 2.
 *
 * The mapper must be thread-safe; Jackson's default configuration is. This adapter is
 * optional and is not a runtime dependency of the starter.
 */
public class Jackson2JsonCodec(
    private val mapper: ObjectMapper,
) : JsonCodec {

    override fun encode(value: Any?): String = try {
        mapper.writeValueAsString(value)
    } catch (e: Exception) {
        throw JwtException.JsonCodecException("Jackson 2 failed to encode JWT JSON", e)
    }

    override fun decode(json: String, type: Class<*>): Any? = try {
        mapper.readValue(json, type)
    } catch (e: Exception) {
        throw JwtException.JsonCodecException("Jackson 2 failed to decode JWT JSON", e)
    }
}
