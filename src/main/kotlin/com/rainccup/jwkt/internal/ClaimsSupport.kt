package com.rainccup.jwkt.internal

import com.rainccup.jwkt.JwtException
import java.math.RoundingMode
import kotlin.time.Instant

internal const val CLAIM_ISSUER = "iss"
internal const val CLAIM_SUBJECT = "sub"
internal const val CLAIM_AUDIENCE = "aud"
internal const val CLAIM_EXPIRATION = "exp"
internal const val CLAIM_NOT_BEFORE = "nbf"
internal const val CLAIM_ISSUED_AT = "iat"
internal const val CLAIM_JWT_ID = "jti"

internal fun isNumericDateClaim(name: String): Boolean =
    name == CLAIM_EXPIRATION || name == CLAIM_NOT_BEFORE || name == CLAIM_ISSUED_AT

/**
 * Converts a JWT NumericDate to an [Instant].
 *
 * Fractional seconds are supported. The value is rounded down to whole nanoseconds, so
 * validation never becomes more permissive because of rounding.
 */
internal fun numericDate(name: String, value: Any?): Instant? {
    value ?: return null
    if (value !is Number) {
        throw JwtException.InvalidClaims("JWT claim '$name' must be a number")
    }
    val decimal = try {
        value.toString().toBigDecimal()
    } catch (e: NumberFormatException) {
        throw JwtException.InvalidClaims("JWT claim '$name' is not a finite number", e)
    }

    val seconds = try {
        decimal.setScale(0, RoundingMode.FLOOR).longValueExact()
    } catch (e: ArithmeticException) {
        throw JwtException.InvalidClaims("JWT claim '$name' is outside the supported range", e)
    }

    val fraction = decimal.subtract(seconds.toBigDecimal())
    val nanos = try {
        fraction.movePointRight(9)
            .setScale(0, RoundingMode.DOWN)
            .longValueExact()
    } catch (e: ArithmeticException) {
        throw JwtException.InvalidClaims("JWT claim '$name' has an invalid fractional value", e)
    }

    return try {
        Instant.fromEpochSeconds(seconds, nanos)
    } catch (e: IllegalArgumentException) {
        throw JwtException.InvalidClaims(
            "JWT claim '$name' is outside the supported Instant range",
            e,
        )
    } catch (e: ArithmeticException) {
        throw JwtException.InvalidClaims(
            "JWT claim '$name' is outside the supported Instant range",
            e,
        )
    }
}
