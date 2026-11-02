package com.rainccup.jwkt.internal

import com.rainccup.jwkt.JwtException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Base64

internal object Encoding {

    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    fun base64UrlEncode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun base64UrlDecode(segment: String, partName: String): ByteArray {
        return try {
            Base64.getUrlDecoder().decode(segment)
        } catch (e: IllegalArgumentException) {
            throw JwtException.MalformedToken(
                "JWT $partName is not valid base64url",
                e,
            )
        }
    }

    fun utf8Decode(bytes: ByteArray, partName: String): String {
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (e: CharacterCodingException) {
            throw JwtException.MalformedToken("JWT $partName is not valid UTF-8", e)
        }
    }
}
