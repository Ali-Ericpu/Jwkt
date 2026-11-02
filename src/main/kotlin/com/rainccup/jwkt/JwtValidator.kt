package com.rainccup.jwkt

/**
 * Application-specific validation applied after signature verification and built-in claim
 * checks.
 *
 * Throw a [JwtException] (or another runtime exception) to reject the token. Validators are
 * called in registration order.
 */
public fun interface JwtValidator {
    public fun validate(jwt: Jwt)
}
