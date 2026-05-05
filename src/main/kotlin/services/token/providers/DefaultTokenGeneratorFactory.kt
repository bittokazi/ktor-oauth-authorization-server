package com.bittokazi.ktor.auth.services.token.providers

import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.services.token.TokenGeneratorFactory

/**
 * Default implementation of TokenGeneratorFactory.
 * Creates appropriate token generators based on grant type.
 * Resolves providers from dependencies injected at initialization.
 */
class DefaultTokenGeneratorFactory(
    private val clientCredentialsTokenGenerator: TokenGenerator,
    private val authorizationCodeTokenGenerator: TokenGenerator,
    private val refreshTokenGenerator: TokenGenerator,
    private val deviceCodeTokenGenerator: TokenGenerator
) : TokenGeneratorFactory {

    /**
     * Get the appropriate token generator for the given grant type.
     */
    override fun getGenerator(grantType: String?): TokenGenerator? {
        return when (grantType) {
            "client_credentials" -> clientCredentialsTokenGenerator
            "authorization_code" -> authorizationCodeTokenGenerator
            "refresh_token" -> refreshTokenGenerator
            "urn:ietf:params:oauth:grant-type:device_code" -> deviceCodeTokenGenerator
            else -> null
        }
    }
}
