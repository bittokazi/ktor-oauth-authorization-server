package com.bittokazi.ktor.auth.services.token

/**
 * Factory interface for creating appropriate token generators based on grant type.
 */
interface TokenGeneratorFactory {
    /**
     * Get the appropriate token generator for the given grant type.
     */
    fun getGenerator(grantType: String?): TokenGenerator?
}
