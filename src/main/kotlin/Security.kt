package com.bittokazi.ktor.auth

import com.auth0.jwk.JwkProviderBuilder
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.*
import io.ktor.server.auth.AuthenticationConfig
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.sessions.*
import io.ktor.util.hex
import kotlinx.serialization.Serializable
import java.net.URL
import kotlin.random.Random

@Serializable
data class OauthUserSession(val userId: String, val username: String, val expiresAt: Long, val rememberMe: Boolean?)

fun Application.configureSecurity() {

    val sessionCustomizer: SessionCustomizer by dependencies

    var secretEncryptKey = hex(Random.nextBytes(16).joinToString("") { "%02x".format(it) }) // 16 bytes = AES128
    var secretSignKey = hex(Random.nextBytes(16).joinToString("") { "%02x".format(it) })   // 16 bytes

    if(sessionCustomizer.encryptionKey != null || sessionCustomizer.signingKey != null) {
       secretEncryptKey = hex(sessionCustomizer.encryptionKey!!)
       secretSignKey =  hex(sessionCustomizer.signingKey!!)
    }

    install(Sessions) {
        cookie<OauthUserSession>("OAUTH_USER_SESSION") {
            cookie.httpOnly = true
            cookie.secure = false // set true in production (HTTPS only)
            cookie.maxAgeInSeconds = 31536000
            transform(SessionTransportTransformerEncrypt(secretEncryptKey, secretSignKey))
        }
        cookie<String>("OAUTH_ORIGINAL_URL") {
            cookie.httpOnly = true
            cookie.secure = false // set true in production (HTTPS only)
        }
    }
}

fun AuthenticationConfig.oauthAuthenticationConfig(issuerUrl: String) {
    jwt {
        realm = "ktor-oauth-server"

        verifier(JwkProviderBuilder(URL("${issuerUrl}/.well-known/jwks.json")).build())

        validate { credential ->
            if (credential.payload.issuer != this.getBaseUrl()) {
                return@validate null
            }
            JWTPrincipal(credential.payload)
        }

        challenge { _, _ ->
            call.respond(
                HttpStatusCode.Unauthorized, mapOf(
                    "message" to "Unauthorized"
                )
            )
        }
    }
}
