package com.rainccup.jwkt

import com.rainccup.jwkt.JwsAlgorithms.ES256
import com.rainccup.jwkt.JwsAlgorithms.ES384
import com.rainccup.jwkt.JwsAlgorithms.ES512
import com.rainccup.jwkt.JwsAlgorithms.HS256
import com.rainccup.jwkt.JwsAlgorithms.HS384
import com.rainccup.jwkt.JwsAlgorithms.HS512
import com.rainccup.jwkt.JwsAlgorithms.RS256
import com.rainccup.jwkt.JwsAlgorithms.RS384
import com.rainccup.jwkt.JwsAlgorithms.RS512
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.spec.SecretKeySpec
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JwktTest {

    private val codec = JacksonJsonCodec()
    private val secret = ByteArray(32) { (it + 1).toByte() }
    private val now: Instant = Instant.parse("2030-01-01T00:00:00Z")

    @Test
    fun `round trips a signed token with registered and custom claims`() {
        val expiration = now.plusSeconds(300)
        val token = Jwkt.builder(codec)
            .clock(fixedClock(now))
            .issuer("https://issuer.example")
            .subject("user-42")
            .audience("api", "web")
            .jwtId("token-1")
            .issuedAt(now)
            .notBefore(now.minusSeconds(5))
            .expiresAt(expiration)
            .keyId("key-1")
            .header("tenant", "acme")
            .claim("role", "admin")
            .claim("nested", mapOf("level" to 7))
            .signWith(HS256, secret)
            .compact()

        assertEquals(3, token.split('.').size)
        assertFalse(token.contains('='), "compact JWS must use unpadded base64url")

        val jwt = Jwkt.parser(codec)
            .clock(fixedClock(now))
            .verifyWith(HS256, secret)
            .build()
            .parse(token)

        assertTrue(jwt.isVerified)
        assertEquals(token, jwt.token)
        assertEquals("HS256", jwt.header.algorithm)
        assertEquals("JWT", jwt.header.type)
        assertEquals("key-1", jwt.header.keyId)
        assertEquals("acme", jwt.header["tenant"])
        assertEquals("https://issuer.example", jwt.claims.issuer)
        assertEquals("user-42", jwt.claims.subject)
        assertEquals(listOf("api", "web"), jwt.claims.audience)
        assertEquals(expiration, jwt.claims.expiration)
        assertEquals(now, jwt.claims.issuedAt)
        assertEquals(now.minusSeconds(5), jwt.claims.notBefore)
        assertEquals("token-1", jwt.claims.jwtId)
        assertEquals("admin", jwt.claims["role"])
        assertEquals(mapOf("level" to 7), jwt.claims["nested"])
        assertTrue(jwt.claims.rawJson.contains("\"sub\":\"user-42\""))
        assertEquals(32, jwt.signature.size)
        val originalFirstByte = jwt.signature[0]
        jwt.signature[0] = 0
        assertEquals(originalFirstByte, jwt.signature[0], "signature getter must return a defensive copy")
    }

    @Test
    fun `interoperates with the RFC 7515 HS256 example`() {
        val token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val key = Base64.getUrlDecoder().decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75" +
                "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )

        val jwt = Jwkt.parser(codec)
            .clock(Clock.fixed(Instant.parse("2011-03-22T00:00:00Z"), ZoneOffset.UTC))
            .verifyWith(HS256, key)
            .build()
            .parse(token)

        assertEquals("joe", jwt.claims.issuer)
        assertEquals(true, jwt.claims["http://example.com/is_root"])
        assertEquals(Instant.ofEpochSecond(1_300_819_380), jwt.claims.expiration)
    }

    @Test
    fun `works with a codec that does not use JSON at all`() {
        val opaque = OpaqueCodec()
        val token = Jwkt.builder(opaque)
            .issuer("issuer")
            .subject("subject")
            .claim("admin", true)
            .expiresAt(now.plusSeconds(60))
            .signWith(HS256, secret)
            .compact()

        assertFalse(token.contains('{'), "the library must not assume JSON syntax")

        val jwt = Jwkt.parser(opaque)
            .clock(fixedClock(now))
            .verifyWith(HS256, secret)
            .build()
            .parse(token)

        assertEquals("issuer", jwt.claims.issuer)
        assertEquals("subject", jwt.claims.subject)
        assertEquals(true, jwt.claims["admin"])
        assertEquals(true, opaque.decode(jwt.claims.rawJson, Map::class.java) is Map<*, *>)
    }

    @Test
    fun `supports a user defined signature algorithm`() {
        val reversing = ReversingAlgorithm

        val token = Jwkt.builder(codec)
            .subject("custom")
            .signWith(reversing, "any key")
            .compact()

        val parsed = Jwkt.parser(codec)
            .verifyWith(reversing, "any key")
            .build()
            .parse(token)

        assertEquals("X-REV", parsed.header.algorithm)
        assertEquals("custom", parsed.claims.subject)
    }

    @Test
    fun `supports all HMAC variants`() {
        val algorithms = listOf(
            HS256 to 32,
            HS384 to 48,
            HS512 to 64,
        )
        for ((algorithm, keySize) in algorithms) {
            val key = ByteArray(keySize) { (it * 3 + 1).toByte() }
            val token = Jwkt.builder(codec)
                .subject(algorithm.name)
                .signWith(algorithm, key)
                .compact()
            val jwt = Jwkt.parser(codec)
                .verifyWith(algorithm, key)
                .build()
                .parse(token)
            assertEquals(algorithm.name, jwt.header.algorithm)
        }
    }

    @Test
    fun `accepts a SecretKey for HMAC`() {
        val key = SecretKeySpec(secret, "HmacSHA256")
        val token = Jwkt.builder(codec)
            .subject("secret-key")
            .signWith(HS256, key)
            .compact()

        val jwt = Jwkt.parser(codec)
            .verifyWith(HS256, key)
            .build()
            .parse(token)

        assertEquals("secret-key", jwt.claims.subject)
    }

    @Test
    fun `supports all RSA variants`() {
        val keyPair = generateRsaKeyPair()
        for (algorithm in listOf(RS256, RS384, RS512)) {
            val token = Jwkt.builder(codec)
                .subject(algorithm.name)
                .signWith(algorithm, keyPair.private)
                .compact()

            val jwt = Jwkt.parser(codec)
                .verifyWith(algorithm, keyPair.public)
                .build()
                .parse(token)

            assertEquals(algorithm.name, jwt.header.algorithm)
            assertEquals(256, jwt.signature.size)
        }
    }

    @Test
    fun `supports all ECDSA variants`() {
        val variants = listOf(
            Triple(ES256, "secp256r1", 64),
            Triple(ES384, "secp384r1", 96),
            Triple(ES512, "secp521r1", 132),
        )
        for ((algorithm, curve, signatureSize) in variants) {
            val keyPair = generateEcKeyPair(curve)
            val token = Jwkt.builder(codec)
                .subject(algorithm.name)
                .signWith(algorithm, keyPair.private)
                .compact()

            val jwt = Jwkt.parser(codec)
                .verifyWith(algorithm, keyPair.public)
                .build()
                .parse(token)

            assertEquals(algorithm.name, jwt.header.algorithm)
            assertEquals(signatureSize, jwt.signature.size)
        }
    }

    @Test
    fun `supports ECDSA P-256 signatures`() {
        val keyPair = generateEcKeyPair()
        val token = Jwkt.builder(codec)
            .subject("ecdsa")
            .signWith(ES256, keyPair.private)
            .compact()

        val jwt = Jwkt.parser(codec)
            .verifyWith(ES256, keyPair.public)
            .build()
            .parse(token)

        assertEquals("ecdsa", jwt.claims.subject)
        assertEquals(64, jwt.signature.size)
    }

    @Test
    fun `selects a verification key from an untrusted header`() {
        val oldKey = ByteArray(32) { 1 }
        val newKey = ByteArray(32) { 2 }
        val parser = Jwkt.parser(codec)
            .verifyWith { header ->
                when (header.keyId) {
                    "new" -> JwsVerificationKey(HS256, newKey)
                    "old" -> JwsVerificationKey(HS256, oldKey)
                    else -> null
                }
            }
            .build()

        val token = Jwkt.builder(codec)
            .keyId("new")
            .subject("rotated")
            .signWith(HS256, newKey)
            .compact()

        assertEquals("rotated", parser.parse(token).claims.subject)

        val unknown = Jwkt.builder(codec)
            .keyId("missing")
            .signWith(HS256, newKey)
            .compact()
        assertThrows(JwtException.UnsupportedAlgorithm::class.java) {
            parser.parse(unknown)
        }
    }

    @Test
    fun `rejects a resolver that returns a different algorithm`() {
        val token = Jwkt.builder(codec)
            .keyId("key")
            .signWith(HS256, secret)
            .compact()

        val parser = Jwkt.parser(codec)
            .verifyWith { JwsVerificationKey(HS512, secret) }
            .build()

        val exception = assertThrows(JwtException.AlgorithmMismatch::class.java) {
            parser.parse(token)
        }
        assertEquals("HS256", exception.headerAlgorithm)
        assertEquals("HS512", exception.configuredAlgorithm)
    }

    @Test
    fun `parseUnverified does not check the signature`() {
        val token = Jwkt.builder(codec)
            .subject("unverified")
            .signWith(HS256, secret)
            .compact()
        val parts = token.split('.')
        val tampered = "${parts[0]}.${parts[1]}.${if (parts[2].first() == 'A') 'B' else 'A'}${parts[2].drop(1)}"

        val jwt = Jwkt.parseUnverified(tampered, codec)

        assertFalse(jwt.isVerified)
        assertEquals("unverified", jwt.claims.subject)
    }

    @Test
    fun `asType decodes the original payload into an application model`() {
        val token = Jwkt.builder(codec)
            .subject("typed")
            .claim("admin", true)
            .signWith(HS256, secret)
            .compact()

        val jwt = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .build()
            .parse(token)

        val typed = jwt.claims.asType<TypedClaims>()
        assertEquals("typed", typed.sub)
        assertTrue(typed.admin)
    }

    @Test
    fun `validators run after verification and can see isVerified`() {
        var invoked = false
        val token = Jwkt.builder(codec)
            .subject("validated")
            .signWith(HS256, secret)
            .compact()

        val jwt = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .validateWith { parsed ->
                invoked = true
                assertTrue(parsed.isVerified)
                assertEquals("validated", parsed.claims.subject)
            }
            .build()
            .parse(token)

        assertTrue(invoked)
        assertTrue(jwt.isVerified)
    }

    @Test
    fun `a validator can reject a token`() {
        val token = Jwkt.builder(codec)
            .claim("role", "user")
            .signWith(HS256, secret)
            .compact()

        val parser = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .validateWith { jwt ->
                if (jwt.claims["role"] != "admin") {
                    throw JwtException.InvalidClaims("admin role required")
                }
            }
            .build()

        assertThrows(JwtException.InvalidClaims::class.java) {
            parser.parse(token)
        }
    }

    @Test
    fun `requires issuer subject audience and claims`() {
        val token = Jwkt.builder(codec)
            .issuer("issuer-a")
            .subject("subject-a")
            .audience(listOf("api", "web"))
            .claim("tenant", "acme")
            .claim("role", "admin")
            .signWith(HS256, secret)
            .compact()

        val parser = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireIssuer("issuer-a")
            .requireSubject("subject-a")
            .requireAudience("api")
            .requireAudience("web")
            .requireClaim("tenant")
            .requireClaim("role", "admin")
            .build()

        assertEquals("subject-a", parser.parse(token).claims.subject)

        val wrongIssuer = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireIssuer("issuer-b")
            .build()
        val issuerError = assertThrows(JwtException.ClaimMismatch::class.java) {
            wrongIssuer.parse(token)
        }
        assertEquals("iss", issuerError.claimName)
        assertEquals("issuer-b", issuerError.expected)
        assertEquals("issuer-a", issuerError.actual)

        val missingClaim = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireClaim("department")
            .build()
        val missing = assertThrows(JwtException.MissingClaim::class.java) {
            missingClaim.parse(token)
        }
        assertEquals("department", missing.claimName)

        val missingAudience = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireAudience("mobile")
            .build()
        assertThrows(JwtException.ClaimMismatch::class.java) {
            missingAudience.parse(token)
        }
    }

    @Test
    fun `requireClaim compares numbers numerically and instants as epoch seconds`() {
        val expiration = Instant.ofEpochSecond(Instant.now().epochSecond + 3_600)
        val token = Jwkt.builder(codec)
            .claim("count", 1)
            .claim("exp", expiration)
            .signWith(HS256, secret)
            .compact()

        val parsed = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireClaim("count", 1L)
            .requireClaim("exp", expiration)
            .build()
            .parse(token)

        assertEquals(1, parsed.claims["count"])
    }

    @Test
    fun `requires a null valued claim to be present`() {
        val token = Jwkt.builder(codec)
            .claim("present-but-null", null)
            .signWith(HS256, secret)
            .compact()

        val parser = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireClaim("present-but-null")
            .build()

        assertNull(parser.parse(token).claims["present-but-null"])
    }

    @Test
    fun `validates expiration with clock skew`() {
        val token = Jwkt.builder(codec)
            .expiresAt(now)
            .signWith(HS256, secret)
            .compact()

        val strict = Jwkt.parser(codec)
            .clock(fixedClock(now))
            .verifyWith(HS256, secret)
            .build()
        val expired = assertThrows(JwtException.ExpiredToken::class.java) {
            strict.parse(token)
        }
        assertEquals(now, expired.expiredAt)
        assertEquals(now, expired.now)

        val lenient = Jwkt.parser(codec)
            .clock(fixedClock(now))
            .clockSkew(Duration.ofSeconds(1))
            .verifyWith(HS256, secret)
            .build()
        assertEquals(now, lenient.parse(token).claims.expiration)
    }

    @Test
    fun `can require an expiration claim`() {
        val token = Jwkt.builder(codec)
            .subject("no-expiration")
            .signWith(HS256, secret)
            .compact()

        val defaultParser = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .build()
        assertEquals("no-expiration", defaultParser.parse(token).claims.subject)

        val strictParser = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .requireExpiration()
            .build()
        val missing = assertThrows(JwtException.MissingClaim::class.java) {
            strictParser.parse(token)
        }
        assertEquals("exp", missing.claimName)
    }

    @Test
    fun `validates not before with clock skew`() {
        val token = Jwkt.builder(codec)
            .notBefore(now.plusSeconds(10))
            .signWith(HS256, secret)
            .compact()

        val strict = Jwkt.parser(codec)
            .clock(fixedClock(now))
            .verifyWith(HS256, secret)
            .build()
        val notYetValid = assertThrows(JwtException.NotYetValidToken::class.java) {
            strict.parse(token)
        }
        assertEquals(now.plusSeconds(10), notYetValid.notBefore)
        assertEquals(now, notYetValid.now)

        val lenient = Jwkt.parser(codec)
            .clock(fixedClock(now))
            .clockSkew(Duration.ofSeconds(10))
            .verifyWith(HS256, secret)
            .build()
        assertNotNull(lenient.parse(token).claims.notBefore)
    }

    @Test
    fun `supports static and resolver based verification keys on separate parsers`() {
        val token = Jwkt.builder(codec)
            .subject("static")
            .signWith(HS256, secret)
            .compact()

        val resolverParser = Jwkt.parser(codec)
            .verifyWith { header ->
                if (header.algorithm == "HS256") JwsVerificationKey(HS256, secret) else null
            }
            .build()

        assertEquals("static", resolverParser.parse(token).claims.subject)
    }

    @Test
    fun `exposes header and claims as immutable values`() {
        val token = Jwkt.builder(codec)
            .header("x", "y")
            .claim("a", 1)
            .signWith(HS256, secret)
            .compact()

        val jwt = Jwkt.parser(codec)
            .verifyWith(HS256, secret)
            .build()
            .parse(token)
        val headerCopy = jwt.header.toMap()
        val claimsCopy = jwt.claims.values

        assertEquals("y", headerCopy["x"])
        assertEquals(1, claimsCopy["a"])
        val mutableHeader = headerCopy.toMutableMap()
        mutableHeader["x"] = "changed"
        assertEquals("y", jwt.header["x"])
    }

    private fun fixedClock(instant: Instant): Clock =
        Clock.fixed(instant, ZoneOffset.UTC)

    private fun generateRsaKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun generateEcKeyPair(curve: String = "secp256r1"): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec(curve))
        }.generateKeyPair()

    private class OpaqueCodec : JsonCodec {
        private val values = LinkedHashMap<String, Any?>()
        private val nextId = AtomicInteger()

        override fun encode(value: Any?): String {
            val id = "jwkt-${nextId.getAndIncrement()}"
            values[id] = value
            return id
        }

        override fun decode(json: String, type: Class<*>): Any? =
            values[json] ?: error("unknown encoded value: $json")
    }

    private object ReversingAlgorithm : JwsAlgorithm {
        override val name: String = "X-REV"

        override fun sign(input: ByteArray, key: Any): ByteArray = input.reversedArray()

        override fun verify(input: ByteArray, signature: ByteArray, key: Any): Boolean =
            MessageDigest.isEqual(input.reversedArray(), signature)
    }

    private class TypedClaims {
        @JvmField
        var sub: String? = null

        @JvmField
        var admin: Boolean = false
    }
}
