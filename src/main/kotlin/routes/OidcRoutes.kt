package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.oidcRoutes() {
    val oauthUserService: OauthUserService by dependencies
    val jwksProvider: JwksProvider by dependencies
    val jwtVerifier: JwtVerifier by dependencies

    routing {

        authenticate {
            get("/oauth/userinfo") {
                val authHeader = call.request.headers["Authorization"] ?: return@get call.respond(
                    HttpStatusCode.Unauthorized, mapOf(
                        "error" to "No Authorization Provided"
                    )
                )
                if (!authHeader.startsWith("Bearer ")) return@get call.respond(
                    HttpStatusCode.Unauthorized, mapOf(
                        "error" to "Invalid authorization token"
                    )
                )

                val token = authHeader.removePrefix("Bearer ").trim()
                val signedJWT = jwtVerifier.verify(token) ?: return@get call.respond(
                    HttpStatusCode.Unauthorized, mapOf(
                        "error" to "Unauthorized"
                    )
                )

                if (signedJWT.jwtClaimsSet.getStringClaim("token_type") != TokenType.ACCESS_TOKEN.name) {
                    return@get call.respond(
                        HttpStatusCode.Unauthorized, mapOf(
                            "error" to "Unauthorized"
                        )
                    )
                }

                // Extract claims
                val claims = signedJWT.jwtClaimsSet
                val sub = claims.subject
                val scopes = claims.getStringClaim("scope")?.split(" ") ?: emptyList()

                // Optional: only return claims that the token scopes allow
                val response = mutableMapOf(
                    "sub" to sub
                )
                if ("openid" in scopes) {
                    val user = oauthUserService.findById(sub, call)
                        ?: return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "User not found"))
                    if ("email" in scopes) {
                        response["email"] = user.email as String
                    }
                    if ("profile" in scopes) {
                        response["name"] = "${user.firstName} ${user.lastName}"
                        response["preferred_username"] = user.username
                    }
                }

                call.respond(response)
            }
        }

        get("/.well-known/openid-configuration") {
            val issuer = call.getBaseUrl()
            val baseUrl = "${call.getBaseUrl()}/oauth"

            val metadata = mapOf(
                "issuer" to issuer,
                "authorization_endpoint" to "$baseUrl/authorize",
                "device_authorization_endpoint" to "$baseUrl/device_authorization",
                "token_endpoint" to "$baseUrl/token",
                "userinfo_endpoint" to "$baseUrl/userinfo",
                "revocation_endpoint" to "$baseUrl/revoke",
                "introspection_endpoint" to "$baseUrl/introspect",
                "jwks_uri" to "$issuer/.well-known/jwks.json",
                "response_types_supported" to listOf("code", "token", "id_token", "code id_token"),
                "grant_types_supported" to listOf(
                    "authorization_code",
                    "refresh_token"
                ),
                "subject_types_supported" to listOf("public"),
                "id_token_signing_alg_values_supported" to listOf("RS256"),
                "scopes_supported" to listOf("openid", "profile", "email"),
                "token_endpoint_auth_methods_supported" to listOf("client_secret_post"),
                "code_challenge_methods_supported" to listOf("S256", "plain")
            )

            call.respond(metadata)
        }

        get("/.well-known/jwks.json") {
            val jwkSet = mapOf(
                "keys" to listOf(jwksProvider.getPublicJwk())
            )
            call.respond(jwkSet)
        }
    }
}
