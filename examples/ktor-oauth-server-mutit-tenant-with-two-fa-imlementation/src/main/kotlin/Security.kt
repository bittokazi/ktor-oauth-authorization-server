package com.bittokazi.example.ktor

import com.bittokazi.ktor.auth.oauthAuthenticationConfig
import com.bittokazi.ktor.auth.services.SessionExtender
import io.ktor.client.*
import io.ktor.client.engine.apache.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.plugins.di.annotations.Property
import io.ktor.server.sessions.SessionTransportTransformerEncrypt
import io.ktor.server.sessions.SessionsConfig
import io.ktor.server.sessions.cookie
import io.ktor.util.hex
import kotlinx.serialization.Serializable
import kotlin.random.Random

fun Application.configureSecurity() {
    authentication {
        oauth("ktor-oauth2") {
            urlProvider = { "http://localhost:8080/auth/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "ktor-auth-server",
                    authorizeUrl = "http://localhost:8080/oauth/authorize",
                    accessTokenUrl = "http://localhost:8080/oauth/token",
                    requestMethod = HttpMethod.Post,
                    clientId = "default-client",
                    clientSecret = "password",
                    defaultScopes = listOf("openid profile email")
                )
            }
            client = HttpClient(Apache)
        }

        oauthAuthenticationConfig("http://localhost:8080")
    }
}

class SessionExtenderImpl(
    @Property("oauth.session.encryption-key") val encryptionKey: String? = null,
    @Property("oauth.session.signing-key") val signingKey: String? = null,
): SessionExtender {

    override fun extent(sessionsConfig: SessionsConfig) {
        var secretEncryptKey = hex(Random.nextBytes(16).joinToString("") { "%02x".format(it) }) // 16 bytes = AES128
        var secretSignKey = hex(Random.nextBytes(16).joinToString("") { "%02x".format(it) })   // 16 bytes

        if(encryptionKey != null || signingKey != null) {
            secretEncryptKey = hex(encryptionKey!!)
            secretSignKey =  hex(signingKey!!)
        }

        sessionsConfig.cookie<UserTwoFaSession>("USER_TWO_FA_SESSION") {
            cookie.httpOnly = true
            cookie.secure = false
            cookie.maxAgeInSeconds = 315360000
            transform(SessionTransportTransformerEncrypt(secretEncryptKey, secretSignKey))
        }
    }
}

@Serializable
data class UserTwoFaSession(
    val userId: String,
    val username: String,
)
