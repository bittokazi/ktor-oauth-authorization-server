package com.bittokazi.ktor.auth.services.oidc

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.ApplicationCall

class DefaultOidcService(
    private val oauthUserService: OauthUserService,
    private val jwksProvider: JwksProvider,
    private val jwtVerifier: JwtVerifier,
) : OidcService {
    override suspend fun getUserInfo(
        authHeader: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any>, String> {
        if (authHeader == null) {
            return Result.Failure("No Authorization Provided")
        }

        if (!authHeader.startsWith("Bearer ")) {
            return Result.Failure("Invalid authorization token")
        }

        val token = authHeader.removePrefix("Bearer ").trim()
        val signedJWT = jwtVerifier.verify(token) ?: return Result.Failure("Unauthorized")

        if (signedJWT.jwtClaimsSet.getStringClaim("token_type") != TokenType.ACCESS_TOKEN.name) {
            return Result.Failure("Unauthorized")
        }

        // Extract claims
        val claims = signedJWT.jwtClaimsSet
        val sub = claims.subject
        val scopes = claims.getStringClaim("scope")?.split(" ") ?: emptyList()

        // Optional: only return claims that the token scopes allow
        val response = mutableMapOf<String, Any>("sub" to sub)

        if ("openid" in scopes) {
            val user = oauthUserService.findById(sub, call) ?: return Result.Failure("User not found")

            if ("email" in scopes) {
                response["email"] = user.email as String
            }
            if ("profile" in scopes) {
                response["name"] = "${user.firstName} ${user.lastName}"
                response["preferred_username"] = user.username
            }
        }

        return Result.Success(response)
    }

    override fun getOpenIdConfiguration(
        baseUrl: String,
        issuer: String,
    ): Map<String, Any> {
        return mapOf(
            "issuer" to issuer,
            "authorization_endpoint" to "$baseUrl/authorize",
            "device_authorization_endpoint" to "$baseUrl/device_authorization",
            "token_endpoint" to "$baseUrl/token",
            "userinfo_endpoint" to "$baseUrl/userinfo",
            "revocation_endpoint" to "$baseUrl/revoke",
            "introspection_endpoint" to "$baseUrl/introspect",
            "jwks_uri" to "$issuer/.well-known/jwks.json",
            "response_types_supported" to listOf("code", "token", "id_token", "code id_token"),
            "grant_types_supported" to listOf("authorization_code", "refresh_token"),
            "subject_types_supported" to listOf("public"),
            "id_token_signing_alg_values_supported" to listOf("RS256"),
            "scopes_supported" to listOf("openid", "profile", "email"),
            "token_endpoint_auth_methods_supported" to listOf("client_secret_post"),
            "code_challenge_methods_supported" to listOf("S256", "plain"),
        )
    }

    override fun getJwksConfiguration(): Map<String, Any> {
        return mapOf(
            "keys" to listOf(jwksProvider.getPublicJwk()),
        )
    }
}
