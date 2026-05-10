package com.bittokazi.ktor.auth.services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import java.time.Instant

/**
 * Default token generator for client_credentials grant type.
 */
class DefaultClientCredentialsTokenGenerator(
    private val oauthClientService: OauthClientService,
    private val oauthTokenService: OauthTokenService,
    private val jwksProvider: JwksProvider,
) : TokenGenerator {
    override suspend fun generateTokens(
        params: Map<String, String?>,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        val clientId =
            params["client_id"] ?: return Result.Failure(
                mapOf(
                    "error" to "Missing client_id",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )

        val clientSecret =
            params["client_secret"] ?: return Result.Failure(
                mapOf(
                    "error" to "Missing client_secret",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )

        val client =
            oauthClientService.findByClientId(clientId, call)
                ?: return Result.Failure(
                    mapOf(
                        "error" to "Invalid client_id",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        if (client.clientType != "confidential") {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        if (client.clientSecret != clientSecret) {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        if (!client.grantTypes.contains("client_credentials")) {
            return Result.Failure(
                mapOf(
                    "error" to "Grant type not permitted",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        // Generate access token as JWT
        val issuer = call.getBaseUrl()
        val scopes = client.scopes // optional: client-defined scopes

        val accessToken =
            jwksProvider.generateJwt(
                subject = clientId,
                audience = "",
                scopes = scopes,
                issuer = issuer,
                expiresInSeconds = client.accessTokenValidity,
                client = client,
                tokenType = TokenType.ACCESS_TOKEN,
                call = call,
            )

        val expiry = Instant.now().plusSeconds(client.accessTokenValidity)

        oauthTokenService.storeAccessToken(
            token = accessToken,
            clientId = client.id,
            userId = null,
            scopes = scopes,
            expiresAt = expiry,
            call,
        )

        return Result.Success(
            mapOf(
                "access_token" to accessToken,
                "token_type" to "Bearer",
                "expires_in" to client.accessTokenValidity,
                "scope" to scopes.joinToString(" "),
            ),
        )
    }
}
