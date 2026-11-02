package com.rainccup.jwkt

import com.rainccup.jwkt.JwsAlgorithms.ES256
import com.rainccup.jwkt.JwsAlgorithms.ES384
import com.rainccup.jwkt.JwsAlgorithms.HS256
import com.rainccup.jwkt.JwsAlgorithms.RS256
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.time.Duration.Companion.seconds
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class JwktErrorTest {

    private val codec = JacksonJsonCodec()
    private val secret = ByteArray(32) { (it + 1).toByte() }
    private val parser: JwtParser = Jwkt.parser(codec)
        .verifyWith(HS256, secret)
        .build()

    @Test
    fun `compact requires a codec and a signer`() {
        assertThrows(JwtException.ConfigurationException::class.java) {
            Jwkt.builder().signWith(HS256, secret).compact()
        }
        assertThrows(JwtException.ConfigurationException::class.java) {
            Jwkt.builder(codec).compact()
        }
        assertThrows(JwtException.ConfigurationException::class.java) {
            Jwkt.parser().build()
        }
    }

    @Test
    fun `rejects tokens over the configured maximum length`() {
        val shortParser = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .maxTokenLength(16)
            .build()

        assertThrows(JwtException.MalformedToken::class.java) {
            shortParser.parse("x".repeat(17))
        }
    }

    @Test
    fun `parse requires a verification key`() {
        val token = Jwkt.builder(codec).subject("x").signWith(HS256, secret).compact()
        val unconfigured = Jwkt.parser(codec).build()

        assertThrows(JwtException.ConfigurationException::class.java) {
            unconfigured.parse(token)
        }
    }

    @Test
    fun `rejects duplicate verification keys`() {
        assertThrows(JwtException.ConfigurationException::class.java) {
            Jwkt.parser(codec)
                .verifyWith(HS256, secret)
                .verifyWith(HS256, secret)
                .build()
        }
    }

    @Test
    fun `rejects short HMAC keys`() {
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.builder(codec)
                .signWith(HS256, ByteArray(31))
                .compact()
        }

        val token = Jwkt.builder(codec).signWith(HS256, secret).compact()
        val shortKeyParser = Jwkt.parser(codec)
            .verifyWith(HS256, ByteArray(31))
            .build()
        assertThrows(JwtException.InvalidKeyException::class.java) {
            shortKeyParser.parse(token)
        }
    }

    @Test
    fun `rejects non byte array HMAC keys`() {
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.builder(codec).signWith(HS256, "a string key").compact()
        }
    }

    @Test
    fun `rejects tampered payloads and signatures`() {
        val token = Jwkt.builder(codec).subject("original").signWith(HS256, secret).compact()
        val parts = token.split('.')

        val tamperedPayload = "${parts[0]}.${flipFirst(parts[1])}.${parts[2]}"
        assertThrows(JwtException.InvalidSignature::class.java) {
            parser.parse(tamperedPayload)
        }

        val tamperedSignature = "${parts[0]}.${parts[1]}.${flipFirst(parts[2])}"
        assertThrows(JwtException.InvalidSignature::class.java) {
            parser.parse(tamperedSignature)
        }

        assertThrows(JwtException.InvalidSignature::class.java) {
            parser.parse("${parts[0]}.${parts[1]}.")
        }
    }

    @Test
    fun `rejects malformed compact serializations`() {
        assertThrows(JwtException.MalformedToken::class.java) { parser.parse("one.two") }
        assertThrows(JwtException.MalformedToken::class.java) { parser.parse("one.two.three.four") }
        assertThrows(JwtException.MalformedToken::class.java) { parser.parse(".payload.signature") }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse("${base64("{}")}..signature")
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse("%%%.${base64("{}")}.signature")
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse("${base64("""{"alg":"HS256"}""")}.${base64("{}")}.%%%")
        }
    }

    @Test
    fun `rejects invalid UTF-8 and invalid base64 content`() {
        val invalidUtf8Header = base64(byteArrayOf(0xC3.toByte(), 0x28))
        val token = "$invalidUtf8Header.${base64("{}")}.${base64(ByteArray(32))}"
        assertThrows(JwtException.MalformedToken::class.java) { parser.parse(token) }
    }

    @Test
    fun `rejects invalid header JSON and non object headers`() {
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse(token(headerJson = "not-json"))
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse(token(headerJson = "[]"))
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse(token(headerJson = "\"text\""))
        }
    }

    @Test
    fun `rejects missing or malformed alg`() {
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"typ":"JWT"}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":123}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"  "}"""))
        }
    }

    @Test
    fun `rejects unsecured none tokens`() {
        val token = "${base64("""{"alg":"none"}""")}.${base64("""{"sub":"x"}""")}."

        assertThrows(JwtException.InvalidHeader::class.java) { parser.parse(token) }
        assertThrows(JwtException.ConfigurationException::class.java) {
            Jwkt.builder(codec)
                .signWith(
                    object : JwsAlgorithm {
                        override val name: String = "none"
                        override fun sign(input: ByteArray, key: Any): ByteArray = ByteArray(0)
                        override fun verify(
                            input: ByteArray,
                            signature: ByteArray,
                            key: Any,
                        ): Boolean = true
                    },
                    "key",
                )
                .compact()
        }
    }

    @Test
    fun `rejects unsupported critical headers and unencoded payloads`() {
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"HS256","crit":["exp"]}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"HS256","crit":["foo","foo"]}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"HS256","crit":"exp"}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"HS256","b64":false}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"HS256","b64":"false"}"""))
        }
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(token(headerJson = """{"alg":"HS256","kid":7}"""))
        }
    }

    @Test
    fun `rejects an empty crit header`() {
        assertThrows(JwtException.InvalidHeader::class.java) {
            parser.parse(
                token(headerJson = """{"alg":"HS256","typ":"JWT","crit":[]}"""),
            )
        }
    }

    @Test
    fun `accepts an explicit b64 true header`() {
        val jwt = parser.parse(
            token(headerJson = """{"alg":"HS256","typ":"JWT","b64":true}"""),
        )
        assertEquals("HS256", jwt.header.algorithm)
        assertEquals(true, jwt.header.isPayloadEncoded)
    }

    @Test
    fun `rejects invalid payload JSON and non object payloads`() {
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse(token(payloadJson = "{"))
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse(token(payloadJson = "[]"))
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            parser.parse(token(payloadJson = "\"text\""))
        }
    }

    @Test
    fun `rejects invalid registered claim types`() {
        assertInvalidClaims(Jwkt.builder(codec).claim("exp", "tomorrow"))
        assertInvalidClaims(Jwkt.builder(codec).claim("nbf", true))
        assertInvalidClaims(Jwkt.builder(codec).claim("iat", listOf(1)))
        assertInvalidClaims(Jwkt.builder(codec).claim("iss", 42))
        assertInvalidClaims(Jwkt.builder(codec).claim("sub", false))
        assertInvalidClaims(Jwkt.builder(codec).claim("jti", 9))
        assertInvalidClaims(Jwkt.builder(codec).claim("aud", listOf("ok", 2)))
    }

    @Test
    fun `rejects numeric dates outside the Instant range`() {
        assertThrows(JwtException.InvalidClaims::class.java) {
            parser.parse(token(payloadJson = """{"exp":9223372036854775808}"""))
        }
    }

    @Test
    fun `rejects RSA keys below 2048 bits`() {
        val weak = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.builder(codec).signWith(RS256, weak.private).compact()
        }
        val token = Jwkt.builder(codec)
            .signWith(RS256, generateRsaKeyPair().private)
            .compact()
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.parser(codec).verifyWith(RS256, weak.public).build().parse(token)
        }
    }

    @Test
    fun `rejects wrong asymmetric key types and curves`() {
        val rsa = generateRsaKeyPair()
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.builder(codec).signWith(RS256, secret).compact()
        }
        val rsaToken = Jwkt.builder(codec).signWith(RS256, rsa.private).compact()
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.parser(codec).verifyWith(RS256, rsa.private).build().parse(rsaToken)
        }

        val p384 = generateEcKeyPair("secp384r1")
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.builder(codec).signWith(ES256, p384.private).compact()
        }
        val p256 = generateEcKeyPair("secp256r1")
        val wrongCurveToken = "${base64("""{"alg":"ES384"}""")}." +
            "${base64("""{"sub":"x"}""")}.${base64(ByteArray(96))}"
        assertThrows(JwtException.InvalidKeyException::class.java) {
            Jwkt.parser(codec).verifyWith(ES384, p256.public).build().parse(wrongCurveToken)
        }
    }

    @Test
    fun `wraps resolver failures`() {
        val token = Jwkt.builder(codec).keyId("x").signWith(HS256, secret).compact()
        val failing = Jwkt.parser(codec)
            .verifyWith { throw IllegalStateException("key store unavailable") }
            .build()

        val exception = assertThrows(JwtException.VerificationException::class.java) {
            failing.parse(token)
        }
        assertEquals("key store unavailable", exception.cause?.message)
    }

    @Test
    fun `wraps codec failures`() {
        val failing = object : JsonCodec {
            override fun encode(value: Any?): String = error("no encoder")
            override fun decode(json: String, type: Class<*>): Any? = error("no decoder")
        }

        assertThrows(JwtException.JsonCodecException::class.java) {
            Jwkt.builder(failing).signWith(HS256, secret).compact()
        }
        assertThrows(JwtException.MalformedToken::class.java) {
            Jwkt.parser(failing).verifyWith(HS256, secret).build()
                .parse("${base64("{}")}.${base64("{}")}.")
        }
    }

    @Test
    fun `rejects blank codec output`() {
        val blank = object : JsonCodec {
            override fun encode(value: Any?): String = "   "
            override fun decode(json: String, type: Class<*>): Any? = emptyMap<String, Any?>()
        }

        assertThrows(JwtException.JsonCodecException::class.java) {
            Jwkt.builder(blank).signWith(HS256, secret).compact()
        }
    }

    @Test
    fun `rejects empty custom signatures`() {
        val emptySigner = object : JwsAlgorithm {
            override val name: String = "X-EMPTY"
            override fun sign(input: ByteArray, key: Any): ByteArray = ByteArray(0)
            override fun verify(input: ByteArray, signature: ByteArray, key: Any): Boolean = true
        }

        assertThrows(JwtException.SigningException::class.java) {
            Jwkt.builder(codec).signWith(emptySigner, Unit).compact()
        }
    }

    @Test
    fun `typed decoding failures are reported as codec errors`() {
        val token = Jwkt.builder(codec).subject("x").signWith(HS256, secret).compact()
        val jwt = parser.parse(token)

        assertThrows(JwtException.JsonCodecException::class.java) {
            jwt.claims.asType<String>()
        }
    }

    @Test
    fun `rejects restricted builder headers and invalid settings`() {
        assertThrows(IllegalArgumentException::class.java) {
            Jwkt.builder(codec).header("alg", "HS256")
        }
        assertThrows(IllegalArgumentException::class.java) {
            Jwkt.builder(codec).header("b64", false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Jwkt.builder(codec).header("crit", listOf("exp"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            Jwkt.parser(codec).clockSkew((-1).seconds)
        }
    }

    private fun assertInvalidClaims(builder: JwtBuilder) {
        val token = builder.signWith(HS256, secret).compact()
        assertThrows(JwtException.InvalidClaims::class.java) {
            parser.parse(token)
        }
    }

    private fun token(
        headerJson: String = """{"alg":"HS256","typ":"JWT"}""",
        payloadJson: String = """{"sub":"x"}""",
        key: ByteArray = secret,
    ): String {
        val header = base64(headerJson)
        val payload = base64(payloadJson)
        val signature = hmac("$header.$payload", key)
        return "$header.$payload.${base64(signature)}"
    }

    private fun hmac(input: String, key: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(input.toByteArray(StandardCharsets.US_ASCII))
    }

    private fun base64(value: String): String =
        base64(value.toByteArray(StandardCharsets.UTF_8))

    private fun base64(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun flipFirst(value: String): String {
        val replacement = if (value.first() == 'A') 'B' else 'A'
        return replacement + value.drop(1)
    }

    private fun generateRsaKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun generateEcKeyPair(curve: String): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec(curve))
        }.generateKeyPair()
}
