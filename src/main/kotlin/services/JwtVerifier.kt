package com.bittokazi.ktor.auth.services

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor

class JwtVerifier(
    jwksProvider: JwksProvider
) {
    private val jwtProcessor: ConfigurableJWTProcessor<SecurityContext> = DefaultJWTProcessor()

    init {
        val jwkSource = ImmutableJWKSet<SecurityContext>(JWKSet(jwksProvider.rsaJwk.toPublicJWK()))
        val keySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource)
        jwtProcessor.jwsKeySelector = keySelector
    }

    fun verify(token: String): SignedJWT? {
        return try {
            val signedJWT = SignedJWT.parse(token)
            jwtProcessor.process(signedJWT, null)  // throws exception if invalid
            signedJWT
        } catch (e: Exception) {
            null
        }
    }
}
