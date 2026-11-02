package com.rainccup.jwkt.spring.internal

import com.rainccup.jwkt.EcJwsAlgorithm
import com.rainccup.jwkt.HmacJwsAlgorithm
import com.rainccup.jwkt.JwsAlgorithm
import com.rainccup.jwkt.JwsAlgorithms
import com.rainccup.jwkt.JwtException
import com.rainccup.jwkt.RsaJwsAlgorithm
import com.rainccup.jwkt.spring.JwktProperties
import org.springframework.core.io.Resource
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64

/** The selected algorithm and the keys available for signing and/or verification. */
public class JwktKeyMaterial internal constructor(
    public val algorithm: JwsAlgorithm,
    public val signingKey: Any?,
    public val verificationKey: Any?,
) {
    init {
        if (signingKey == null && verificationKey == null) {
            throw JwtException.ConfigurationException("No signing or verification key is available")
        }
    }
}

internal object JwktKeys {

    private val standardBase64: Base64 = Base64.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)
    private val urlSafeBase64: Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)

    fun create(properties: JwktProperties, algorithms: List<JwsAlgorithm>): JwktKeyMaterial {
        val name = properties.algorithm.trim()
        if (name.isEmpty()) {
            throw JwtException.ConfigurationException("jwkt.algorithm must not be blank")
        }

        val matching = algorithms.filter { it.name == name }
        if (matching.size > 1) {
            throw JwtException.ConfigurationException(
                "Multiple JwsAlgorithm beans are named '$name'; keep exactly one",
            )
        }
        val algorithm = matching.firstOrNull()
            ?: JwsAlgorithms.find(name)
            ?: throw JwtException.ConfigurationException(
                "Unknown JWS algorithm '$name'. Configure a JwsAlgorithm bean with that name " +
                    "or use one of: ${listOf("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512").joinToString()}",
            )

        val hasRawSecret = properties.secret != null
        val hasBase64Secret = properties.secretBase64 != null
        val hasPrivateKey = properties.privateKey != null
        val hasPublicKey = properties.publicKey != null
        val hasSecret = hasRawSecret || hasBase64Secret
        val hasPem = hasPrivateKey || hasPublicKey

        if (hasRawSecret && hasBase64Secret) {
            throw JwtException.ConfigurationException(
                "Configure only one of jwkt.secret and jwkt.secret-base64",
            )
        }
        if (hasSecret && hasPem) {
            throw JwtException.ConfigurationException(
                "jwkt.secret and PEM keys cannot be combined; configure one key source",
            )
        }
        if (!hasSecret && !hasPem) {
            throw JwtException.ConfigurationException(
                "No key is configured. Set jwkt.secret, jwkt.secret-base64, " +
                    "jwkt.private-key, or jwkt.public-key",
            )
        }

        if (algorithm is HmacJwsAlgorithm && !hasSecret) {
            throw JwtException.ConfigurationException(
                "Algorithm $name requires an HMAC secret (jwkt.secret or jwkt.secret-base64)",
            )
        }
        if ((algorithm is RsaJwsAlgorithm || algorithm is EcJwsAlgorithm) && !hasPem) {
            throw JwtException.ConfigurationException(
                "Algorithm $name requires a PEM key (jwkt.private-key and/or jwkt.public-key)",
            )
        }

        if (hasSecret) {
            val secret = when {
                hasRawSecret -> properties.secret!!.toByteArray(Charsets.UTF_8)
                else -> decodeBase64(properties.secretBase64!!)
            }
            if (secret.isEmpty()) {
                throw JwtException.ConfigurationException("The configured HMAC secret is empty")
            }
            if (algorithm is HmacJwsAlgorithm &&
                secret.size < algorithm.minimumKeySizeBytes
            ) {
                throw JwtException.ConfigurationException(
                    "HMAC key for $name must be at least " +
                        "${algorithm.minimumKeySizeBytes} bytes (got ${secret.size})",
                )
            }
            val copy = secret.copyOf()
            return JwktKeyMaterial(algorithm, copy.copyOf(), copy)
        }

        val keyAlgorithm = resolveKeyAlgorithm(properties, algorithm)
        val privateKey = properties.privateKey?.let {
            PemKeys.readPrivateKey(it, keyAlgorithm, "jwkt.private-key")
        }
        val publicKey = properties.publicKey?.let {
            PemKeys.readPublicKey(it, keyAlgorithm, "jwkt.public-key")
        }

        privateKey?.let { validateKey(it, algorithm, signing = true) }
        publicKey?.let { validateKey(it, algorithm, signing = false) }

        return JwktKeyMaterial(
            algorithm = algorithm,
            signingKey = privateKey,
            verificationKey = publicKey,
        )
    }

    private fun resolveKeyAlgorithm(properties: JwktProperties, algorithm: JwsAlgorithm): String {
        val explicit = properties.keyAlgorithm?.trim()
        if (!explicit.isNullOrEmpty()) {
            return explicit
        }
        return when (algorithm) {
            is RsaJwsAlgorithm -> "RSA"
            is EcJwsAlgorithm -> "EC"
            else -> throw JwtException.ConfigurationException(
                "PEM keys with custom algorithm ${algorithm.name} require jwkt.key-algorithm " +
                    "(for example RSA, EC, or Ed25519)",
            )
        }
    }

    private fun validateKey(key: java.security.Key, algorithm: JwsAlgorithm, signing: Boolean) {
        val label = if (signing) "private" else "public"
        if (algorithm is RsaJwsAlgorithm && key !is RSAKey) {
            throw JwtException.ConfigurationException(
                "Algorithm ${algorithm.name} requires an RSA $label key, got ${key.algorithm}",
            )
        }
        if (algorithm is EcJwsAlgorithm && key !is ECKey) {
            throw JwtException.ConfigurationException(
                "Algorithm ${algorithm.name} requires an EC $label key, got ${key.algorithm}",
            )
        }

        when (key) {
            is RSAPrivateKey -> {
                if (key.modulus.bitLength() < 2048) {
                    throw JwtException.ConfigurationException(
                        "RSA $label key must be at least 2048 bits " +
                            "(got ${key.modulus.bitLength()})",
                    )
                }
            }
            is RSAPublicKey -> {
                if (key.modulus.bitLength() < 2048) {
                    throw JwtException.ConfigurationException(
                        "RSA $label key must be at least 2048 bits " +
                            "(got ${key.modulus.bitLength()})",
                    )
                }
            }
        }

        if (algorithm is EcJwsAlgorithm) {
            val ecKey = key as ECKey
            val actualSize = ecKey.params.curve.field.fieldSize
            if (actualSize != algorithm.curveSizeBits) {
                throw JwtException.ConfigurationException(
                    "Algorithm ${algorithm.name} requires a ${algorithm.curveSizeBits}-bit " +
                        "curve, got $actualSize bits",
                )
            }
        }
    }

    private fun decodeBase64(value: String): ByteArray {
        val compact = value.trim()
        if (compact.isEmpty()) {
            throw JwtException.ConfigurationException("jwkt.secret-base64 must not be blank")
        }
        return try {
            standardBase64.decode(compact)
        } catch (_: IllegalArgumentException) {
            try {
                urlSafeBase64.decode(compact)
            } catch (url: IllegalArgumentException) {
                throw JwtException.ConfigurationException(
                    "jwkt.secret-base64 is not valid standard or URL-safe Base64",
                    url,
                )
            }
        }
    }
}

internal object PemKeys {

    private val PEM_PATTERN =
        Regex("-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----")
    private val BASE64 = Base64.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)

    fun readPrivateKey(resource: Resource, keyAlgorithm: String, propertyName: String): PrivateKey {
        val label = "PRIVATE KEY"
        val encoded = readPem(resource, label, propertyName)
        return try {
            val spec = PKCS8EncodedKeySpec(encoded)
            KeyFactory.getInstance(keyAlgorithm).generatePrivate(spec)
        } catch (e: GeneralSecurityException) {
            throw JwtException.ConfigurationException(
                "Failed to read $propertyName as a PKCS#8 $keyAlgorithm private key. " +
                    "Convert it with: openssl pkcs8 -topk8 -nocrypt",
                e,
            )
        } catch (e: IllegalArgumentException) {
            throw JwtException.ConfigurationException(
                "$propertyName does not contain a valid PKCS#8 private key",
                e,
            )
        }
    }

    fun readPublicKey(resource: Resource, keyAlgorithm: String, propertyName: String): PublicKey {
        val label = "PUBLIC KEY"
        val encoded = readPem(resource, label, propertyName)
        return try {
            val spec = X509EncodedKeySpec(encoded)
            KeyFactory.getInstance(keyAlgorithm).generatePublic(spec)
        } catch (e: GeneralSecurityException) {
            throw JwtException.ConfigurationException(
                "Failed to read $propertyName as an X.509 $keyAlgorithm public key",
                e,
            )
        } catch (e: IllegalArgumentException) {
            throw JwtException.ConfigurationException(
                "$propertyName does not contain a valid X.509 public key",
                e,
            )
        }
    }

    private fun readPem(resource: Resource, expectedLabel: String, propertyName: String): ByteArray {
        val text = try {
            if (!resource.exists()) {
                throw JwtException.ConfigurationException("$propertyName does not exist: $resource")
            }
            resource.inputStream.use { it.readBytes().toString(Charsets.US_ASCII) }
        } catch (e: JwtException) {
            throw e
        } catch (e: Exception) {
            throw JwtException.ConfigurationException("Failed to read $propertyName: $resource", e)
        }

        if (text.contains("ENCRYPTED PRIVATE KEY")) {
            throw JwtException.ConfigurationException(
                "$propertyName is encrypted; decrypt it before configuring JWKT",
            )
        }
        if (text.contains("BEGIN RSA PRIVATE KEY") || text.contains("BEGIN EC PRIVATE KEY")) {
            throw JwtException.ConfigurationException(
                "$propertyName is PKCS#1; convert it with: " +
                    "openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem",
            )
        }

        val match = PEM_PATTERN.find(text)
            ?: throw JwtException.ConfigurationException(
                "$propertyName does not contain a PEM block",
            )
        val label = match.groupValues[1]
        if (label != expectedLabel) {
            val hint = when (label) {
                "ENCRYPTED PRIVATE KEY" -> " The key is encrypted; decrypt it first."
                "RSA PRIVATE KEY", "EC PRIVATE KEY" -> " Convert PKCS#1 to PKCS#8 first."
                "RSA PUBLIC KEY" -> " Convert PKCS#1 to X.509 first."
                else -> ""
            }
            throw JwtException.ConfigurationException(
                "$propertyName must contain a $expectedLabel PEM block, found '$label'.$hint",
            )
        }

        val body = match.groupValues[2].replace(Regex("\\s"), "")
        return try {
            BASE64.decode(body)
        } catch (e: IllegalArgumentException) {
            throw JwtException.ConfigurationException(
                "$propertyName contains invalid Base64 in its PEM body",
                e,
            )
        }
    }
}
