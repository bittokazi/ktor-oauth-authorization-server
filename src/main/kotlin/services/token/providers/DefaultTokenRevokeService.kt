package com.bittokazi.ktor.auth.services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.token.TokenRevokeService
import io.ktor.server.application.ApplicationCall

/**
 * Default implementation of TokenRevokeService for revoking tokens
 */
class DefaultTokenRevokeService(
    private val oauthTokenService: OauthTokenService,
) : TokenRevokeService {
    override suspend fun revoke(
        token: String,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        val access = oauthTokenService.findByAccessToken(token, call)
        val refresh = oauthTokenService.findByRefreshToken(token, call)

        if (access != null) {
            oauthTokenService.revokeAccessToken(token, call)
        }

        if (refresh != null) {
            oauthTokenService.revokeRefreshToken(token, call)
        }

        return Result.Success(
            mapOf(
                "message" to "Token revoked successfully",
            ),
        )
    }
}
