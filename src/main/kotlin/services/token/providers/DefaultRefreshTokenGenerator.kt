package com.bittokazi.ktor.auth.services.token.providers

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import java.time.Instant

/**
 * Default token generator for refresh_token grant type.
 */
class DefaultRefreshTokenGenerator(
    private val oauthClientService: OauthClientService,
    private val oauthTokenService: OauthTokenService,
    private val oauthUserService: OauthUserService,
    private val jwksProvider: JwksProvider,
) : TokenGenerator {
    override suspend fun generateTokens(
        params: Map<String, String?>,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        val refreshToken =
            params["refresh_token"]
                ?: return Result.Failure(
                    mapOf(
                        "error" to "Missing refresh_token",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        val clientId =
            params["client_id"] ?: return Result.Failure(
                mapOf(
                    "error" to "Missing client_id",
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

        if (client.clientType == "confidential") {
            val clientSecret =
                params["client_secret"] ?: return Result.Failure(
                    mapOf(
                        "error" to "Missing client_secret",
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
        }

        if (!client.grantTypes.contains("refresh_token")) {
            return Result.Failure(
                mapOf(
                    "error" to "Grant type not permitted",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        val existing =
            oauthTokenService.findByRefreshToken(refreshToken, call)
                ?: return Result.Failure(
                    mapOf(
                        "error" to "Invalid refresh_token",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        if (client.id != existing.clientId) {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        if (existing.revoked || existing.expiresAt.isBefore(Instant.now())) {
            return Result.Failure(
                mapOf(
                    "error" to "Expired or revoked token",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        val userId = existing.userId.toString()
        val issuer = call.getBaseUrl()

        val newAccessToken =
            jwksProvider.generateJwt(
                subject = userId,
                audience = clientId,
                scopes = existing.scopes,
                issuer = issuer,
                expiresInSeconds = client.accessTokenValidity,
                client = client,
                userId = userId,
                tokenType = TokenType.ACCESS_TOKEN,
                call = call,
            )

        val idToken =
            if (existing.scopes.contains("openid")) {
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId,
                    scopes = existing.scopes,
                    issuer = issuer,
                    expiresInSeconds = client.accessTokenValidity,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = oauthUserService.findById(userId, call),
                    call = call,
                )
            } else {
                null
            }

        val newRefreshToken =
            jwksProvider.generateJwt(
                subject = userId,
                audience = clientId,
                scopes = existing.scopes,
                issuer = issuer,
                expiresInSeconds = client.refreshTokenValidity,
                client = client,
                userId = userId,
                tokenType = TokenType.REFRESH_TOKEN,
                call = call,
            )
        val newExpiry = Instant.now().plusSeconds(client.accessTokenValidity)
        val newRefreshExpiry = Instant.now().plusSeconds(client.refreshTokenValidity)

        oauthTokenService.storeAccessToken(
            newAccessToken,
            client.id,
            existing.userId,
            existing.scopes,
            newExpiry,
            call,
        )

        oauthTokenService.rotateRefreshToken(
            refreshToken,
            newRefreshToken,
            newRefreshExpiry,
            call,
        )

        val response =
            mutableMapOf(
                "access_token" to newAccessToken,
                "token_type" to "bearer",
                "expires_in" to client.accessTokenValidity,
                "refresh_token" to newRefreshToken,
                "scope" to existing.scopes.joinToString(" "),
            )

        if (idToken != null) {
            response["id_token"] = idToken
        }

        return Result.Success(response)
    }
}
