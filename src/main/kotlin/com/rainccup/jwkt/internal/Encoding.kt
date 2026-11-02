package com.rainccup.jwkt.internal

import com.rainccup.jwkt.JwtException
import java.nio.charset.CharacterCodingException
import kotlin.io.encoding.Base64

internal object Encoding {

    private val encoder: Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
    private val decoder: Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    fun base64UrlEncode(bytes: ByteArray): String = encoder.encode(bytes)

    fun base64UrlDecode(segment: String, partName: String): ByteArray {
        return try {
            decoder.decode(segment)
        } catch (e: IllegalArgumentException) {
            throw JwtException.MalformedToken(
                "JWT $partName is not valid base64url",
                e,
            )
        }
    }

    fun utf8Decode(bytes: ByteArray, partName: String): String {
        return try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (e: CharacterCodingException) {
            throw JwtException.MalformedToken("JWT $partName is not valid UTF-8", e)
        }
    }
}
