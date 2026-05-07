package com.bittokazi.ktor.auth.services.token

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

/**
 * Base interface for token generators handling different OAuth grant types.
 */
interface TokenGenerator {
    /**
     * Generates tokens for the given grant type.
     * @return Map containing the token response fields
     */
    suspend fun generateTokens(
        params: Map<String, String?>,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>>
}
