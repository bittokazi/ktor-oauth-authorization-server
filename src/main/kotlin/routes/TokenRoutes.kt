package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import java.time.Instant

fun Application.tokenRoutes() {

    val oauthClientService: OauthClientService by dependencies
    val oauthAuthorizationCodeService: OauthAuthorizationCodeService by dependencies
    val oauthTokenService: OauthTokenService by dependencies
    val jwksProvider: JwksProvider by dependencies
    val oauthUserService: OauthUserService by dependencies

    routing {

        route("/oauth") {
            post("/token") {
                val params = call.receiveParameters()
                val grantType = params["grant_type"]

                when (grantType) {
                    "client_credentials" -> {
                        val clientId = params["client_id"] ?: return@post call.respond(HttpStatusCode.BadRequest,
                            mutableMapOf("error" to "Missing client_id"))

                        val clientSecret = params["client_secret"] ?: return@post call.respond(HttpStatusCode.BadRequest,
                            mutableMapOf("error" to "Missing client_secret"))

                        val client = oauthClientService.findByClientId(clientId, call)
                            ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid client_id"))

                        if (client.clientType == "confidential" && client.clientSecret != clientSecret) {
                            call.respond(HttpStatusCode.Unauthorized, mutableMapOf("error" to "Unauthorized"))
                            return@post
                        }

                        if (!client.grantTypes.contains("client_credentials")) {
                            call.respond(HttpStatusCode.Unauthorized, mutableMapOf("message" to "Grant type not permitted"))
                            return@post
                        }

                        // Generate access token as JWT
                        val issuer = call.getBaseUrl()
                        val scopes = client.scopes // optional: client-defined scopes

                        val accessToken = jwksProvider.generateJwt(
                            subject = client.id.toString(),  // no user
                            audience = "",      // or a specific resource server
                            scopes = scopes,
                            issuer = issuer,
                            expiresInSeconds = client.accessTokenValidity,
                            client = client,
                            tokenType = TokenType.ACCESS_TOKEN
                        )

                        val expiry = Instant.now().plusSeconds(client.accessTokenValidity)

                        oauthTokenService.storeAccessToken(
                            token = accessToken,
                            clientId = client.id,
                            userId = null,                // no user
                            scopes = scopes,
                            expiresAt = expiry,
                            call
                        )

                        call.respond(
                            mapOf(
                                "access_token" to accessToken,
                                "token_type" to "Bearer",
                                "expires_in" to client.accessTokenValidity,
                                "scope" to scopes.joinToString(" ")
                            )
                        )
                    }

                    "authorization_code" -> {
                        val code = params["code"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing code"))
                        val redirectUri = params["redirect_uri"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing redirect_uri"))
                        val clientId = params["client_id"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_id"))
                        val clientSecret = params["client_secret"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_secret"))

                        val client = oauthClientService.findByClientId(clientId, call)
                            ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid client_id"))

                        if (client.clientType == "confidential" && client.clientSecret != clientSecret) {
                            call.respond(HttpStatusCode.Unauthorized, mutableMapOf("error" to "Unauthorized"))
                            return@post
                        }

                        if (!client.grantTypes.contains("authorization_code")) {
                            call.respond(HttpStatusCode.Unauthorized, mutableMapOf("message" to "Grant type not permitted"))
                            return@post
                        }

                        val codeData = oauthAuthorizationCodeService.findByCode(code, call)
                            ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid code"))

                        if (codeData.redirectUri != redirectUri || codeData.consumed) {
                            call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid or used code"))
                            return@post
                        }

                        oauthAuthorizationCodeService.consumeCode(code, call)

                        val userId = codeData.userId
                        val issuer = call.getBaseUrl()

                        val accessToken = jwksProvider.generateJwt(
                            subject = userId,
                            audience = clientId,
                            scopes = codeData.scopes,
                            issuer = issuer,
                            expiresInSeconds = client.accessTokenValidity,
                            client = client,
                            userId = userId,
                            tokenType = TokenType.ACCESS_TOKEN
                        )

                        val idToken = if(codeData.scopes.contains("openid")) jwksProvider.generateJwt(
                            subject = userId,
                            audience = clientId,
                            scopes = codeData.scopes,
                            issuer = issuer,
                            expiresInSeconds = client.accessTokenValidity,
                            client = client,
                            userId = userId,
                            tokenType = TokenType.ID_TOKEN,
                            user = oauthUserService.findById(codeData.userId, call)
                        ) else null

                        val refreshToken = if (client.grantTypes.contains("refresh_token")) jwksProvider.generateJwt(
                            subject = userId,
                            audience = clientId,
                            scopes = codeData.scopes,
                            issuer = issuer,
                            expiresInSeconds = client.refreshTokenValidity,
                            client = client,
                            userId = userId,
                            tokenType = TokenType.REFRESH_TOKEN
                        ) else null


                        val now = Instant.now()
                        val accessExpiry = now.plusSeconds(client.accessTokenValidity)
                        val refreshExpiry = now.plusSeconds(client.refreshTokenValidity)

                        oauthTokenService.storeAccessToken(
                            accessToken,
                            client.id,
                            codeData.userId,
                            codeData.scopes,
                            accessExpiry,
                            call
                        )

                        if(refreshToken != null) oauthTokenService.storeRefreshToken(
                            refreshToken,
                            client.id,
                            codeData.userId,
                            codeData.scopes,
                            refreshExpiry,
                            call
                        )

                        val response = mutableMapOf(
                            "access_token" to accessToken,
                            "token_type" to "bearer",
                            "expires_in" to client.accessTokenValidity,
                            "id_token" to idToken,
                            "scope" to codeData.scopes.joinToString(" ")
                        )

                        if (refreshToken != null) {
                            response["refresh_token"] = refreshToken
                        }

                        if (idToken != null) {
                            response["id_token"] = idToken
                        }
                        call.respond(response)
                    }

                    "refresh_token" -> {
                        val refreshToken = params["refresh_token"]
                            ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing refresh_token"))

                        val clientId = params["client_id"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_id"))
                        val clientSecret = params["client_secret"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_secret"))

                        val client = oauthClientService.findByClientId(clientId, call)
                            ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid client_id"))

                        if (client.clientType == "confidential" && client.clientSecret != clientSecret) {
                            call.respond(HttpStatusCode.Unauthorized, mutableMapOf("error" to "Unauthorized"))
                            return@post
                        }

                        val existing = oauthTokenService.findByRefreshToken(refreshToken, call)
                            ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid refresh_token"))

                        if (existing.revoked || existing.expiresAt.isBefore(Instant.now())) {
                            call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Expired or revoked token"))
                            return@post
                        }

                        val userId = existing.userId.toString()
                        val issuer = call.getBaseUrl()

                        val newAccessToken = jwksProvider.generateJwt(
                            subject = userId,
                            audience = existing.clientId.toString(),
                            scopes = existing.scopes,
                            issuer = issuer,
                            expiresInSeconds = client.accessTokenValidity,
                            client = client,
                            userId = userId,
                            tokenType = TokenType.ACCESS_TOKEN
                        )

                        val idToken = if(existing.scopes.contains("openid")) jwksProvider.generateJwt(
                            subject = userId,
                            audience = existing.clientId.toString(),
                            scopes = existing.scopes,
                            issuer = issuer,
                            expiresInSeconds = client.accessTokenValidity,
                            client = client,
                            userId = userId,
                            tokenType = TokenType.ID_TOKEN,
                            user = oauthUserService.findById(userId, call)
                        ) else null

                        val newRefreshToken = jwksProvider.generateJwt(
                            subject = userId,
                            audience = existing.clientId.toString(),
                            scopes = existing.scopes,
                            issuer = issuer,
                            expiresInSeconds = client.refreshTokenValidity,
                            client = client,
                            userId = userId,
                            tokenType = TokenType.REFRESH_TOKEN
                        )
                        val newExpiry = Instant.now().plusSeconds(client.accessTokenValidity)
                        val newRefreshExpiry = Instant.now().plusSeconds(client.refreshTokenValidity)

                        oauthTokenService.storeAccessToken(
                            newAccessToken,
                            existing.clientId,
                            existing.userId,
                            existing.scopes,
                            newExpiry,
                            call
                        )

                        oauthTokenService.rotateRefreshToken(
                            refreshToken,
                            newRefreshToken,
                            newRefreshExpiry,
                            call
                        )

                        val response = mutableMapOf(
                            "access_token" to newAccessToken,
                            "token_type" to "bearer",
                            "expires_in" to client.accessTokenValidity,
                            "refresh_token" to newRefreshToken,
                            "scope" to existing.scopes.joinToString(" ")
                        )

                        if (idToken != null) {
                            response["id_token"] = idToken
                        }
                        call.respond(response)
                    }

                    else -> call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Unsupported grant type"))
                }
            }

            post("/introspect") {
                val params = call.receiveParameters()
                val token = params["token"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing token"))

                val clientId = params["client_id"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_id"))
                val clientSecret = params["client_secret"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_secret"))

                val client = oauthClientService.findByClientId(clientId, call)
                    ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Invalid client_id"))

                if (client.clientSecret != clientSecret) {
                    call.respond(HttpStatusCode.Unauthorized, mutableMapOf("error" to "Unauthorized"))
                    return@post
                }

                val accessToken = oauthTokenService.findByAccessToken(token, call)
                    ?: return@post call.respond(mapOf("active" to false))

                if (accessToken.revoked || accessToken.expiresAt.isBefore(Instant.now())) {
                    call.respond(mapOf("active" to false))
                } else {
                    call.respond(
                        mapOf(
                            "active" to true,
                            "client_id" to accessToken.clientId.toString(),
                            "exp" to accessToken.expiresAt.epochSecond,
                            "scope" to accessToken.scopes.joinToString(" ")
                        )
                    )
                }
            }

            post("/revoke") {
                val params = call.receiveParameters()
                val token = params["token"] ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing token"))

                val access = oauthTokenService.findByAccessToken(token, call)
                val refresh = oauthTokenService.findByRefreshToken(token, call)

                if (access != null) oauthTokenService.revokeAccessToken(token, call)
                if (refresh != null) oauthTokenService.revokeRefreshToken(token, call)

                call.respond(HttpStatusCode.OK, "{}")
            }
        }
    }
}
