package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JsonCodec
import com.rainccup.jwkt.JwtException
import tools.jackson.databind.ObjectMapper

/**
 * [JsonCodec] backed by Jackson 3.
 *
 * The mapper must be thread-safe; Jackson's default configuration is. This adapter is
 * optional and is not a runtime dependency of the starter.
 */
public class Jackson3JsonCodec(
    private val mapper: ObjectMapper,
) : JsonCodec {

    override fun encode(value: Any?): String = try {
        mapper.writeValueAsString(value)
    } catch (e: Exception) {
        throw JwtException.JsonCodecException("Jackson 3 failed to encode JWT JSON", e)
    }

    override fun decode(json: String, type: Class<*>): Any? = try {
        mapper.readValue(json, type)
    } catch (e: Exception) {
        throw JwtException.JsonCodecException("Jackson 3 failed to decode JWT JSON", e)
    }
}
