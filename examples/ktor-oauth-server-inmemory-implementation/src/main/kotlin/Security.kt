package com.bittokazi.example.ktor

import com.bittokazi.ktor.auth.oauthAuthenticationConfig
import io.ktor.client.*
import io.ktor.client.engine.apache.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*

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
