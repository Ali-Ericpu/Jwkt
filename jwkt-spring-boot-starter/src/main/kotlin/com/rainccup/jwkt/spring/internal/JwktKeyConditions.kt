package com.rainccup.jwkt.spring.internal

import org.springframework.boot.context.properties.bind.Binder
import org.springframework.context.annotation.Condition
import org.springframework.context.annotation.ConditionContext
import org.springframework.core.type.AnnotatedTypeMetadata

/** Matches when at least one key property is configured. */
internal class JwktAnyKeyCondition : Condition {
    override fun matches(context: ConditionContext, metadata: AnnotatedTypeMetadata): Boolean =
        JwktEnvironmentKeys.hasSecret(context) ||
            JwktEnvironmentKeys.hasPrivateKey(context) ||
            JwktEnvironmentKeys.hasPublicKey(context)
}

/** Matches when the configuration can produce a signature. */
internal class JwktSigningKeyCondition : Condition {
    override fun matches(context: ConditionContext, metadata: AnnotatedTypeMetadata): Boolean =
        JwktEnvironmentKeys.hasSecret(context) || JwktEnvironmentKeys.hasPrivateKey(context)
}

/** Matches when the configuration can verify a signature. */
internal class JwktVerificationKeyCondition : Condition {
    override fun matches(context: ConditionContext, metadata: AnnotatedTypeMetadata): Boolean =
        JwktEnvironmentKeys.hasSecret(context) || JwktEnvironmentKeys.hasPublicKey(context)
}

internal object JwktEnvironmentKeys {

    fun hasSecret(context: ConditionContext): Boolean =
        configured(context, "jwkt.secret") ||
            configured(context, "jwkt.secret-base64")

    fun hasPrivateKey(context: ConditionContext): Boolean =
        configured(context, "jwkt.private-key")

    fun hasPublicKey(context: ConditionContext): Boolean =
        configured(context, "jwkt.public-key")

    /**
     * Uses the Boot binder so relaxed forms such as `jwkt.secret_base64` are visible,
     * matching the binding used by [com.rainccup.jwkt.spring.JwktProperties].
     */
    private fun configured(context: ConditionContext, name: String): Boolean =
        Binder.get(context.environment)
            .bind(name, String::class.java)
            .orElse(null)
            ?.isNotBlank() == true
}
