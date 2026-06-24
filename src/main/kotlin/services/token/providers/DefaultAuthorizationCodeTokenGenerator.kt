package com.bittokazi.ktor.auth.services.token.providers

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.utils.Utils
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import java.time.Instant

/**
 * Default token generator for authorization_code grant type.
 */
class DefaultAuthorizationCodeTokenGenerator(
    private val oauthClientService: OauthClientService,
    private val oauthAuthorizationCodeService: OauthAuthorizationCodeService,
    private val oauthTokenService: OauthTokenService,
    private val oauthUserService: OauthUserService,
    private val jwksProvider: JwksProvider,
) : TokenGenerator {
    override suspend fun generateTokens(
        params: Map<String, String?>,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        val code =
            params["code"] ?: return Result.Failure(
                mapOf(
                    "error" to "Missing code",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )

        val redirectUri =
            params["redirect_uri"] ?: return Result.Failure(
                mapOf(
                    "error" to "Missing redirect_uri",
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

        if (!client.grantTypes.contains("authorization_code")) {
            return Result.Failure(
                mapOf(
                    "error" to "Grant type not permitted",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        val codeData =
            oauthAuthorizationCodeService.findByCode(code, call)
                ?: return Result.Failure(
                    mapOf(
                        "error" to "Invalid code",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        if (client.id != codeData.clientId) {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        // Validate client authentication
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
        } else if (client.clientType == "public") {
            val codeVerifier =
                params["code_verifier"] ?: return Result.Failure(
                    mapOf(
                        "error" to "Missing code_verifier",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

            if (codeData.codeChallenge == null) {
                return Result.Failure(
                    mapOf(
                        "error" to "Missing code_challenge",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )
            }

            if (codeData.codeChallengeMethod == "plain") {
                if (codeVerifier != codeData.codeChallenge) {
                    return Result.Failure(
                        mapOf(
                            "error" to "Invalid code challenge",
                            "statusCode" to HttpStatusCode.Unauthorized,
                        ),
                    )
                }
            } else if (codeData.codeChallengeMethod == "S256") {
                if (!Utils.verifyPkce(codeVerifier, codeData.codeChallenge)) {
                    return Result.Failure(
                        mapOf(
                            "error" to "Invalid code challenge",
                            "statusCode" to HttpStatusCode.Unauthorized,
                        ),
                    )
                }
            }
        }

        if (codeData.redirectUri != redirectUri) {
            return Result.Failure(
                mapOf(
                    "error" to "Invalid redirect_uri",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        if (codeData.consumed) {
            return Result.Failure(
                mapOf(
                    "error" to "Invalid or used code",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        oauthAuthorizationCodeService.consumeCode(code, call)

        val userId = codeData.userId
        val issuer = call.getBaseUrl()

        val accessToken =
            jwksProvider.generateJwt(
                subject = userId,
                audience = clientId,
                scopes = codeData.scopes,
                issuer = issuer,
                expiresInSeconds = client.accessTokenValidity,
                client = client,
                userId = userId,
                tokenType = TokenType.ACCESS_TOKEN,
                call = call,
            )

        val idToken =
            if (codeData.scopes.contains("openid")) {
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId,
                    scopes = codeData.scopes,
                    issuer = issuer,
                    expiresInSeconds = client.accessTokenValidity,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = oauthUserService.findById(codeData.userId, call),
                    call = call,
                )
            } else {
                null
            }

        val refreshToken =
            if (client.grantTypes.contains("refresh_token")) {
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId,
                    scopes = codeData.scopes,
                    issuer = issuer,
                    expiresInSeconds = client.refreshTokenValidity,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.REFRESH_TOKEN,
                    call = call,
                )
            } else {
                null
            }

        val now = Instant.now()
        val accessExpiry = now.plusSeconds(client.accessTokenValidity)
        val refreshExpiry = now.plusSeconds(client.refreshTokenValidity)

        oauthTokenService.storeAccessToken(
            accessToken,
            client.id,
            codeData.userId,
            codeData.scopes,
            accessExpiry,
            call,
        )

        if (refreshToken != null) {
            oauthTokenService.storeRefreshToken(
                refreshToken,
                client.id,
                codeData.userId,
                codeData.scopes,
                refreshExpiry,
                call,
            )
        }

        val response =
            mutableMapOf(
                "access_token" to accessToken,
                "token_type" to "bearer",
                "expires_in" to client.accessTokenValidity,
                "scope" to codeData.scopes.joinToString(" "),
            )

        if (refreshToken != null) {
            response["refresh_token"] = refreshToken
        }

        if (idToken != null) {
            response["id_token"] = idToken
        }

        return Result.Success(response)
    }
}
