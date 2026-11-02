package com.rainccup.jwkt

import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC JWS algorithm (HS256, HS384, HS512, or a custom HMAC variant).
 *
 * Accepts a [ByteArray] or [SecretKey] as the key. For new code, prefer [HS256], [HS384],
 * and [HS512] from [JwsAlgorithms], which enforce the RFC 7518 minimum key sizes.
 *
 * HMAC signatures are compared in constant time.
 */
public class HmacJwsAlgorithm(
    public override val name: String,
    public val jcaName: String,
    public val minimumKeySizeBytes: Int,
) : JwsAlgorithm {

    init {
        require(name.isNotBlank()) { "Algorithm name must not be blank" }
        require(jcaName.isNotBlank()) { "JCA algorithm name must not be blank" }
        require(minimumKeySizeBytes >= 1) { "Minimum key size must be positive" }
    }

    override fun sign(input: ByteArray, key: Any): ByteArray {
        val secret = secretBytes(key)
        return try {
            val mac = Mac.getInstance(jcaName)
            mac.init(SecretKeySpec(secret, jcaName))
            mac.doFinal(input)
        } catch (e: InvalidKeyException) {
            throw JwtException.InvalidKeyException(
                "HMAC key is not valid for $name",
                e,
            )
        } catch (e: GeneralSecurityException) {
            throw JwtException.SigningException("HMAC signing failed for $name", e)
        }
    }

    override fun verify(input: ByteArray, signature: ByteArray, key: Any): Boolean {
        val expected = sign(input, key)
        return MessageDigest.isEqual(expected, signature)
    }

    private fun secretBytes(key: Any): ByteArray {
        val bytes = when (key) {
            is ByteArray -> key
            is SecretKey -> key.encoded
                ?: throw JwtException.InvalidKeyException("HMAC key has no encoded form")
            else -> throw JwtException.InvalidKeyException(
                "HMAC algorithms require a ByteArray or SecretKey, got " +
                    key.javaClass.name,
            )
        }

        if (bytes.size < minimumKeySizeBytes) {
            throw JwtException.InvalidKeyException(
                "HMAC key for $name must be at least $minimumKeySizeBytes bytes " +
                    "(got ${bytes.size})",
            )
        }
        return bytes
    }
}

/**
 * RSA PKCS#1 v1.5 JWS algorithm (RS256, RS384, RS512, or a custom JCA algorithm name).
 *
 * Signing accepts a [PrivateKey] or [KeyPair]; verification accepts a [PublicKey] or
 * [KeyPair]. Keys smaller than [minimumKeySizeBits] (2048 by default) are rejected.
 */
public class RsaJwsAlgorithm(
    public override val name: String,
    public val jcaName: String,
    public val minimumKeySizeBits: Int = 2048,
) : JwsAlgorithm {

    init {
        require(name.isNotBlank()) { "Algorithm name must not be blank" }
        require(jcaName.isNotBlank()) { "JCA algorithm name must not be blank" }
        require(minimumKeySizeBits >= 1) { "Minimum key size must be positive" }
    }

    override fun sign(input: ByteArray, key: Any): ByteArray {
        val privateKey = rsaPrivateKey(key)
        val signer = newSignature()
        try {
            signer.initSign(privateKey)
            signer.update(input)
            return signer.sign()
        } catch (e: InvalidKeyException) {
            throw JwtException.InvalidKeyException("Invalid RSA private key for $name", e)
        } catch (e: SignatureException) {
            throw JwtException.SigningException("RSA signing failed for $name", e)
        }
    }

    override fun verify(input: ByteArray, signature: ByteArray, key: Any): Boolean {
        val publicKey = rsaPublicKey(key)
        val verifier = newSignature()
        return try {
            verifier.initVerify(publicKey)
            verifier.update(input)
            verifier.verify(signature)
        } catch (e: InvalidKeyException) {
            throw JwtException.InvalidKeyException("Invalid RSA public key for $name", e)
        } catch (e: SignatureException) {
            false
        }
    }

    private fun newSignature(): Signature {
        return try {
            Signature.getInstance(jcaName)
        } catch (e: GeneralSecurityException) {
            throw JwtException.VerificationException(
                "JCA Signature '$jcaName' is not available",
                e,
            )
        }
    }

    private fun rsaPrivateKey(key: Any): PrivateKey {
        val result = when (key) {
            is KeyPair -> key.private
            is PrivateKey -> key
            else -> throw JwtException.InvalidKeyException(
                "RSA signing requires a PrivateKey or KeyPair, got ${key.javaClass.name}",
            )
        }
        if (!result.algorithm.equals("RSA", ignoreCase = true)) {
            throw JwtException.InvalidKeyException(
                "RSA signing requires an RSA key, got ${result.algorithm}",
            )
        }
        requireMinimumSize(result, "private")
        return result
    }

    private fun rsaPublicKey(key: Any): PublicKey {
        val result = when (key) {
            is KeyPair -> key.public
            is PublicKey -> key
            else -> throw JwtException.InvalidKeyException(
                "RSA verification requires a PublicKey or KeyPair, got ${key.javaClass.name}",
            )
        }
        if (!result.algorithm.equals("RSA", ignoreCase = true)) {
            throw JwtException.InvalidKeyException(
                "RSA verification requires an RSA key, got ${result.algorithm}",
            )
        }
        requireMinimumSize(result, "public")
        return result
    }

    private fun requireMinimumSize(key: java.security.Key, label: String) {
        val bits = (key as? RSAKey)?.modulus?.bitLength() ?: return
        if (bits < minimumKeySizeBits) {
            throw JwtException.InvalidKeyException(
                "RSA $label key for $name must be at least $minimumKeySizeBits bits (got $bits)",
            )
        }
    }
}

/**
 * ECDSA JWS algorithm using the JCA P1363 signature format (raw `R || S`).
 *
 * Signing accepts an EC [PrivateKey] or [KeyPair]; verification accepts an EC [PublicKey]
 * or [KeyPair]. When the key exposes its curve, the curve size is checked against
 * [curveSizeBits] to prevent using, for example, a P-384 key with ES256.
 *
 * [jcaName] must be a JCA algorithm that emits fixed-size P1363 signatures, such as
 * `SHA256withECDSAinP1363Format`.
 */
public class EcJwsAlgorithm(
    public override val name: String,
    public val jcaName: String,
    public val curveSizeBits: Int,
) : JwsAlgorithm {

    private val signatureLength: Int = 2 * ((curveSizeBits + 7) / 8)

    init {
        require(name.isNotBlank()) { "Algorithm name must not be blank" }
        require(jcaName.isNotBlank()) { "JCA algorithm name must not be blank" }
        require(curveSizeBits >= 1) { "Curve size must be positive" }
    }

    override fun sign(input: ByteArray, key: Any): ByteArray {
        val privateKey = ecPrivateKey(key)
        val signer = newSignature()
        try {
            signer.initSign(privateKey)
            signer.update(input)
            val signature = signer.sign()
            if (signature.size != signatureLength) {
                throw JwtException.SigningException(
                    "ECDSA provider returned ${signature.size} bytes for $name; " +
                        "expected $signatureLength. The JCA algorithm must use P1363 format.",
                )
            }
            return signature
        } catch (e: InvalidKeyException) {
            throw JwtException.InvalidKeyException("Invalid EC private key for $name", e)
        } catch (e: SignatureException) {
            throw JwtException.SigningException("ECDSA signing failed for $name", e)
        }
    }

    override fun verify(input: ByteArray, signature: ByteArray, key: Any): Boolean {
        if (signature.size != signatureLength) {
            return false
        }
        val publicKey = ecPublicKey(key)
        val verifier = newSignature()
        return try {
            verifier.initVerify(publicKey)
            verifier.update(input)
            verifier.verify(signature)
        } catch (e: InvalidKeyException) {
            throw JwtException.InvalidKeyException("Invalid EC public key for $name", e)
        } catch (e: SignatureException) {
            false
        }
    }

    private fun newSignature(): Signature {
        return try {
            Signature.getInstance(jcaName)
        } catch (e: GeneralSecurityException) {
            throw JwtException.VerificationException(
                "JCA Signature '$jcaName' is not available",
                e,
            )
        }
    }

    private fun ecPrivateKey(key: Any): PrivateKey {
        val result = when (key) {
            is KeyPair -> key.private
            is PrivateKey -> key
            else -> throw JwtException.InvalidKeyException(
                "ECDSA signing requires a PrivateKey or KeyPair, got ${key.javaClass.name}",
            )
        }
        checkEcKey(result)
        return result
    }

    private fun ecPublicKey(key: Any): PublicKey {
        val result = when (key) {
            is KeyPair -> key.public
            is PublicKey -> key
            else -> throw JwtException.InvalidKeyException(
                "ECDSA verification requires a PublicKey or KeyPair, got ${key.javaClass.name}",
            )
        }
        checkEcKey(result)
        return result
    }

    private fun checkEcKey(key: java.security.Key) {
        val algorithm = key.algorithm
        if (!algorithm.equals("EC", ignoreCase = true) &&
            !algorithm.equals("ECDSA", ignoreCase = true)
        ) {
            throw JwtException.InvalidKeyException(
                "ECDSA algorithms require an EC key, got $algorithm",
            )
        }
        if (key is ECKey) {
            val actualSize = key.params.curve.field.fieldSize
            if (actualSize != curveSizeBits) {
                throw JwtException.InvalidKeyException(
                    "ECDSA $name requires a $curveSizeBits-bit curve, got $actualSize bits",
                )
            }
        }
    }
}

/**
 * Built-in JWS algorithms.
 *
 * | Name | JCA algorithm | Key |
 * | --- | --- | --- |
 * | HS256 / HS384 / HS512 | HmacSHA256/384/512 | [ByteArray] or [SecretKey] |
 * | RS256 / RS384 / RS512 | SHA256/384/512withRSA | [PrivateKey] / [PublicKey] |
 * | ES256 / ES384 / ES512 | SHA256/384/512withECDSAinP1363Format | EC keys |
 */
public object JwsAlgorithms {

    /** HMAC using SHA-256. Requires a key of at least 32 bytes. */
    @JvmField
    public val HS256: JwsAlgorithm = HmacJwsAlgorithm("HS256", "HmacSHA256", 32)

    /** HMAC using SHA-384. Requires a key of at least 48 bytes. */
    @JvmField
    public val HS384: JwsAlgorithm = HmacJwsAlgorithm("HS384", "HmacSHA384", 48)

    /** HMAC using SHA-512. Requires a key of at least 64 bytes. */
    @JvmField
    public val HS512: JwsAlgorithm = HmacJwsAlgorithm("HS512", "HmacSHA512", 64)

    /** RSASSA-PKCS1-v1_5 using SHA-256. */
    @JvmField
    public val RS256: JwsAlgorithm = RsaJwsAlgorithm("RS256", "SHA256withRSA")

    /** RSASSA-PKCS1-v1_5 using SHA-384. */
    @JvmField
    public val RS384: JwsAlgorithm = RsaJwsAlgorithm("RS384", "SHA384withRSA")

    /** RSASSA-PKCS1-v1_5 using SHA-512. */
    @JvmField
    public val RS512: JwsAlgorithm = RsaJwsAlgorithm("RS512", "SHA512withRSA")

    /** ECDSA using P-256 and SHA-256. */
    @JvmField
    public val ES256: JwsAlgorithm =
        EcJwsAlgorithm("ES256", "SHA256withECDSAinP1363Format", 256)

    /** ECDSA using P-384 and SHA-384. */
    @JvmField
    public val ES384: JwsAlgorithm =
        EcJwsAlgorithm("ES384", "SHA384withECDSAinP1363Format", 384)

    /** ECDSA using P-521 and SHA-512. */
    @JvmField
    public val ES512: JwsAlgorithm =
        EcJwsAlgorithm("ES512", "SHA512withECDSAinP1363Format", 521)

    private val byName: Map<String, JwsAlgorithm> = listOf(
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512,
        ES256,
        ES384,
        ES512,
    ).associateBy { it.name }

    /** Returns the built-in algorithm with the exact JOSE [name], or `null`. */
    @JvmStatic
    public fun find(name: String): JwsAlgorithm? = byName[name]
}
