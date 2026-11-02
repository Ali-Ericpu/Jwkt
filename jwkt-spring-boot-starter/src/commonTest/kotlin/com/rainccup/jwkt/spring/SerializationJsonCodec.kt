package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JsonCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.util.Base64

/**
 * Test codec that deliberately uses Java serialization instead of JSON.
 *
 * It proves that auto-configuration and the JWT pipeline do not depend on any JSON library.
 */
class SerializationJsonCodec : JsonCodec {

    override fun encode(value: Any?): String {
        val bytes = ByteArrayOutputStream().use { output ->
            ObjectOutputStream(output).use { it.writeObject(value) }
            output.toByteArray()
        }
        return Base64.getEncoder().encodeToString(bytes)
    }

    override fun decode(json: String, type: Class<*>): Any? {
        val bytes = Base64.getDecoder().decode(json)
        return ObjectInputStream(ByteArrayInputStream(bytes)).use { it.readObject() }
    }
}
