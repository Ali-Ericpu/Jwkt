package com.rainccup.jwkt.spring

import com.rainccup.jwkt.JwsAlgorithms
import com.rainccup.jwkt.JwtException
import com.rainccup.jwkt.Jwkt
import com.rainccup.jwkt.spring.internal.JwktDefaults
import com.rainccup.jwkt.spring.internal.JwktKeys
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.core.io.ByteArrayResource
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class JwktKeysTest {

    @Test
    fun `loads RSA PKCS8 and X509 PEM keys`() {
        val pair = rsaKeyPair(2048)
        val material = JwktKeys.create(
            JwktProperties().apply {
                algorithm = "RS256"
                privateKey = pemResource("PRIVATE KEY", pair.private.encoded)
                publicKey = pemResource("PUBLIC KEY", pair.public.encoded)
            },
            emptyList(),
        )

        assertThat(material.signingKey).isInstanceOf(RSAPrivateKey::class.java)
        assertThat(material.verificationKey).isInstanceOf(RSAPublicKey::class.java)
        assertThat(material.algorithm.name).isEqualTo("RS256")
    }

    @Test
    fun `supports a public key without a private key`() {
        val pair = rsaKeyPair(2048)
        val material = JwktKeys.create(
            JwktProperties().apply {
                algorithm = "RS256"
                publicKey = pemResource("PUBLIC KEY", pair.public.encoded)
            },
            emptyList(),
        )

        assertThat(material.signingKey).isNull()
        assertThat(material.verificationKey).isInstanceOf(RSAPublicKey::class.java)
    }

    @Test
    fun `accepts a base64url HMAC secret`() {
        val raw = ByteArray(32) { (it + 1).toByte() }
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        val material = JwktKeys.create(
            JwktProperties().apply {
                algorithm = "HS256"
                secretBase64 = encoded
            },
            emptyList(),
        )

        assertThat(material.signingKey).isEqualTo(raw)
        assertThat(material.verificationKey).isEqualTo(raw)
    }

    @Test
    fun `rejects mixed secret and PEM material`() {
        val pair = rsaKeyPair(2048)
        assertThatThrownBy {
            JwktKeys.create(
                JwktProperties().apply {
                    algorithm = "RS256"
                    secret = "0123456789abcdef0123456789abcdef"
                    publicKey = pemResource("PUBLIC KEY", pair.public.encoded)
                },
                emptyList(),
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("cannot be combined")
    }

    @Test
    fun `rejects RSA keys shorter than 2048 bits`() {
        val pair = rsaKeyPair(1024)
        assertThatThrownBy {
            JwktKeys.create(
                JwktProperties().apply {
                    algorithm = "RS256"
                    publicKey = pemResource("PUBLIC KEY", pair.public.encoded)
                },
                emptyList(),
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("at least 2048 bits")
    }

    @Test
    fun `rejects an EC curve that does not match the algorithm`() {
        val pair = ecKeyPair("secp384r1")
        assertThatThrownBy {
            JwktKeys.create(
                JwktProperties().apply {
                    algorithm = "ES256"
                    publicKey = pemResource("PUBLIC KEY", pair.public.encoded)
                },
                emptyList(),
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("256-bit")
    }

    @Test
    fun `rejects PKCS1 private keys with a conversion hint`() {
        val pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
        assertThatThrownBy {
            JwktKeys.create(
                JwktProperties().apply {
                    algorithm = "RS256"
                    privateKey = ByteArrayResource(pkcs1.toByteArray())
                },
                emptyList(),
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("PKCS#1")
    }

    @Test
    fun `rejects an RSA algorithm with an EC key`() {
        val pair = ecKeyPair("secp256r1")
        assertThatThrownBy {
            JwktKeys.create(
                JwktProperties().apply {
                    algorithm = "RS256"
                    keyAlgorithm = "EC"
                    privateKey = pemResource("PRIVATE KEY", pair.private.encoded)
                },
                emptyList(),
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("requires an RSA")
    }

    @Test
    fun `rejects an EC algorithm with an RSA key`() {
        val pair = rsaKeyPair(2048)
        assertThatThrownBy {
            JwktKeys.create(
                JwktProperties().apply {
                    algorithm = "ES256"
                    keyAlgorithm = "RSA"
                    publicKey = pemResource("PUBLIC KEY", pair.public.encoded)
                },
                emptyList(),
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("requires an EC")
    }

    @Test
    fun `rejects missing key material`() {
        assertThatThrownBy {
            JwktKeys.create(JwktProperties().apply { algorithm = "HS256" }, emptyList())
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("No key is configured")
    }

    @Test
    fun `public signer applies no lifetime by default`() {
        val codec = SerializationJsonCodec()
        val secret = ByteArray(32) { (it + 1).toByte() }
        val signer = JwktSigner(codec, JwsAlgorithms.HS256, secret)
        val parser = Jwkt.parser(codec)
            .verifyWith(JwsAlgorithms.HS256, secret)
            .build()

        val jwt = parser.parse(signer.issue(mapOf("role" to "admin")))
        assertThat(jwt.claims["role"]).isEqualTo("admin")
        assertThat(jwt.claims.expiration).isNull()
        assertThat(jwt.claims.issuedAt).isNull()
        assertThat(signer.algorithmName).isEqualTo("HS256")
    }

    @Test
    fun `rejects reserved header names case-insensitively`() {
        assertThatThrownBy {
            JwktDefaults.from(
                JwktProperties().apply {
                    headers["ALG"] = "none"
                },
            )
        }.isInstanceOf(JwtException.ConfigurationException::class.java)
            .hasMessageContaining("reserved header")
    }

    private fun rsaKeyPair(size: Int): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(size) }.generateKeyPair()

    private fun ecKeyPair(curve: String): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec(curve))
        }.generateKeyPair()

    private fun pemResource(label: String, encoded: ByteArray): ByteArrayResource {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(encoded)
        val pem = "-----BEGIN $label-----\n$body\n-----END $label-----\n"
        return ByteArrayResource(pem.toByteArray())
    }
}
