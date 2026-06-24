package com.bittokazi.ktor.auth.services.token.providers

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.token.TokenIntrospectService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import java.time.Instant

/**
 * Default implementation of TokenIntrospectService for introspecting access tokens
 */
class DefaultTokenIntrospectService(
    private val oauthClientService: OauthClientService,
    private val oauthTokenService: OauthTokenService,
) : TokenIntrospectService {
    override suspend fun introspect(
        token: String,
        clientId: String,
        clientSecret: String,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        // Validate client
        val client =
            oauthClientService.findByClientId(clientId, call)
                ?: return Result.Failure(
                    mapOf(
                        "error" to "Invalid client_id",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        if (!BCrypt.verifyer().verify(clientSecret.toCharArray(), client.clientSecret).verified) {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        // Find and check token
        val accessToken =
            oauthTokenService.findByAccessToken(token, call)
                ?: return Result.Success(mapOf("active" to false))

        if (accessToken.revoked || accessToken.expiresAt.isBefore(Instant.now())) {
            return Result.Success(mapOf("active" to false))
        }

        return Result.Success(
            mapOf(
                "active" to true,
                "client_id" to accessToken.clientId.toString(),
                "exp" to accessToken.expiresAt.epochSecond,
                "scope" to accessToken.scopes.joinToString(" "),
            ),
        )
    }
}
