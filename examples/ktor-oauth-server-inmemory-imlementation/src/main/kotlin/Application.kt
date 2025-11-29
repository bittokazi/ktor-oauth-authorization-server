package com.bittokazi.example.ktor

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.configureOauth2AuthorizationServer
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtTokenCustomizer
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.providers.inmemory.OauthAuthorizationCodeServiceInMemoryProvider
import com.bittokazi.ktor.auth.services.providers.inmemory.OauthClientServiceInMemoryProvider
import com.bittokazi.ktor.auth.services.providers.inmemory.OauthConsentServiceInMemoryProvider
import com.bittokazi.ktor.auth.services.providers.inmemory.OauthDeviceCodeServiceInMemoryProvider
import com.bittokazi.ktor.auth.services.providers.inmemory.OauthTokenServiceInMemoryProvider
import com.bittokazi.ktor.auth.services.providers.inmemory.OauthUserServiceInMemoryProvider
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.server.application.*
import io.ktor.server.plugins.di.dependencies
import java.util.UUID

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureSecurity()

    dependencies {
        provide<OauthUserService> {
            OauthUserServiceInMemoryProvider(
                mutableListOf(
                    OAuthUserDTO(
                        id = "1",
                        passwordHash = BCrypt.withDefaults().hashToString(12, "pass".toCharArray()),
                        username = "admin",
                        email = "admin@example.com",
                        firstName = "Jon",
                        lastName = "Doe",
                        isActive = true
                    )
                )
            )
        }
        provide<OauthClientService> {
            OauthClientServiceInMemoryProvider(
                mutableListOf(
                    OAuthClientDTO(
                        id = UUID.randomUUID(),
                        clientId = "default-client",
                        clientSecret = "password",
                        clientName = "backend",
                        clientType = "confidential",
                        scopes = listOf("openid", "profile", "email"),
                        redirectUris = listOf("http://localhost:8080/callback"),
                        grantTypes = listOf("authorization_code", "client_credentials", "refresh_token")
                    )
                )
            )
        }
        provide<OauthAuthorizationCodeService>(OauthAuthorizationCodeServiceInMemoryProvider::class)
        provide<OauthTokenService>(OauthTokenServiceInMemoryProvider::class)
        provide<OauthConsentService>(OauthConsentServiceInMemoryProvider::class)
        provide<OauthDeviceCodeService>(OauthDeviceCodeServiceInMemoryProvider::class)
        provide<JwtTokenCustomizer>(JwtCustomizerImpl::class)
        provide(JwksProvider::class)
        provide(JwtVerifier::class)
        provide(SessionCustomizer::class)
        provide<OauthLoginOptionService> {
            DefaultOauthLoginOptionService("/home")
        }
        provide<OauthLogoutActionService> {
            DefaultOauthLogoutActionService("/hoome")
        }
    }
    configureOauth2AuthorizationServer(
        configureSerialization = true,
        defaultLoginRoutes = true,
        defaultAuthorizeRoute = true,
        defaultOidcRoute = true,
        defaultTokenRoute = true,
        defaultConsentRoute = true,
        defaultDeviceAuthorizationRoute = true
    )

    configureRouting()
}

class JwtCustomizerImpl: JwtTokenCustomizer {
    override fun customize(
        user: String?,
        client: OAuthClientDTO?,
        claims: JWTClaimsSet.Builder,
        call: ApplicationCall?
    ): Map<String, String> {
        return mapOf(
            "extra-scope" to "test-value",
            "scope" to ("${claims.claims["scope"]} extraScope")
        )
    }
}
