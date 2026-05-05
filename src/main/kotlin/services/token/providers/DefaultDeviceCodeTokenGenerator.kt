package com.bittokazi.ktor.auth.services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import java.time.Instant

/**
 * Default token generator for device_code (urn:ietf:params:oauth:grant-type:device_code) grant type.
 */
class DefaultDeviceCodeTokenGenerator(
    private val oauthClientService: OauthClientService,
    private val oauthDeviceCodeService: OauthDeviceCodeService,
    private val oauthTokenService: OauthTokenService,
    private val oauthUserService: OauthUserService,
    private val jwksProvider: JwksProvider
) : TokenGenerator {

    override suspend fun generateTokens(
        params: Map<String, String?>,
        call: ApplicationCall
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        val clientId = params["client_id"] ?: return Result.Failure(mapOf(
            "error" to "Missing client_id",
            "statusCode" to HttpStatusCode.BadRequest
        ))

        val clientSecret = params["client_secret"] ?: return Result.Failure(mapOf(
            "error" to "Missing client_secret",
            "statusCode" to HttpStatusCode.BadRequest
        ))

        val deviceCode = params["device_code"] ?: return Result.Failure(mapOf(
            "error" to "Missing device_code",
            "statusCode" to HttpStatusCode.BadRequest
        ))

        val client = oauthClientService.findByClientId(clientId, call)
            ?: return Result.Failure(mapOf(
                "error" to "Invalid client_id",
                "statusCode" to HttpStatusCode.BadRequest
            ))

        if (client.clientType == "confidential" && client.clientSecret != clientSecret) {
            return Result.Failure(mapOf(
                "error" to "Unauthorized",
                "statusCode" to HttpStatusCode.Unauthorized
            ))
        }

        if (!client.grantTypes.contains("urn:ietf:params:oauth:grant-type:device_code")) {
            return Result.Failure(mapOf(
                "error" to "Grant type not permitted",
                "statusCode" to HttpStatusCode.Unauthorized
            ))
        }

        var oauthDeviceCodeEntity = oauthDeviceCodeService.findByDeviceCode(deviceCode, false, false, call)

        if (oauthDeviceCodeEntity != null && client.id != oauthDeviceCodeEntity.clientId) {
            return Result.Failure(mapOf(
                "error" to "Unauthorized",
                "statusCode" to HttpStatusCode.Unauthorized
            ))
        }

        if (oauthDeviceCodeEntity != null && !oauthDeviceCodeEntity.isDeviceAuthorized && !oauthDeviceCodeEntity.consumed) {
            return Result.Failure(mapOf(
                "error" to "authorization_pending",
                "statusCode" to HttpStatusCode.BadRequest
            ))
        }

        oauthDeviceCodeEntity = oauthDeviceCodeService.findByDeviceCode(deviceCode, true, false, call)

        if (oauthDeviceCodeEntity != null && client.id != oauthDeviceCodeEntity.clientId) {
            return Result.Failure(mapOf(
                "error" to "Unauthorized",
                "statusCode" to HttpStatusCode.Unauthorized
            ))
        }

        if (oauthDeviceCodeEntity != null && oauthDeviceCodeEntity.expiresAt < Instant.now()) {
            return Result.Failure(mapOf(
                "error" to "expired_token",
                "statusCode" to HttpStatusCode.BadRequest
            ))
        }

        if (oauthDeviceCodeEntity != null) {
            oauthDeviceCodeService.consumeDeviceCode(oauthDeviceCodeEntity.deviceCode, call)

            val userId = oauthDeviceCodeEntity.userId
            val issuer = call.getBaseUrl()

            val accessToken = jwksProvider.generateJwt(
                subject = userId!!,
                audience = clientId,
                scopes = oauthDeviceCodeEntity.scopes,
                issuer = issuer,
                expiresInSeconds = client.accessTokenValidity,
                client = client,
                userId = userId,
                tokenType = TokenType.ACCESS_TOKEN,
                call = call
            )

            val idToken = if (oauthDeviceCodeEntity.scopes.contains("openid")) jwksProvider.generateJwt(
                subject = userId,
                audience = clientId,
                scopes = oauthDeviceCodeEntity.scopes,
                issuer = issuer,
                expiresInSeconds = client.accessTokenValidity,
                client = client,
                userId = userId,
                tokenType = TokenType.ID_TOKEN,
                user = oauthUserService.findById(userId, call),
                call = call
            ) else null

            val refreshToken = if (client.grantTypes.contains("refresh_token")) jwksProvider.generateJwt(
                subject = userId,
                audience = clientId,
                scopes = oauthDeviceCodeEntity.scopes,
                issuer = issuer,
                expiresInSeconds = client.refreshTokenValidity,
                client = client,
                userId = userId,
                tokenType = TokenType.REFRESH_TOKEN,
                call = call
            ) else null

            val now = Instant.now()
            val accessExpiry = now.plusSeconds(client.accessTokenValidity)
            val refreshExpiry = now.plusSeconds(client.refreshTokenValidity)

            oauthTokenService.storeAccessToken(
                accessToken,
                client.id,
                userId,
                client.scopes,
                accessExpiry,
                call
            )

            if (refreshToken != null) oauthTokenService.storeRefreshToken(
                refreshToken,
                client.id,
                userId,
                client.scopes,
                refreshExpiry,
                call
            )

            val response = mutableMapOf(
                "access_token" to accessToken,
                "token_type" to "bearer",
                "expires_in" to client.accessTokenValidity,
                "scope" to client.scopes.joinToString(" ")
            )

            if (refreshToken != null) {
                response["refresh_token"] = refreshToken
            }

            if (idToken != null) {
                response["id_token"] = idToken
            }

            return Result.Success(response)
        }

        return Result.Failure(mapOf(
            "error" to "Unauthorized",
            "statusCode" to HttpStatusCode.Unauthorized
        ))
    }
}
