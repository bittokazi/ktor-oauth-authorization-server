package com.bittokazi.example.ktor

import com.bittokazi.ktor.auth.configureOauth2AuthorizationServer
import com.bittokazi.ktor.auth.database.DefaultOauthDatabaseConfiguration
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtTokenCustomizer
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.providers.database.OauthAuthorizationCodeServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthClientServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthConsentServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthDeviceCodeServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthTokenServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthUserServiceDatabaseProvider
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.server.application.*
import io.ktor.server.plugins.di.dependencies

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureSecurity()

    dependencies {
        provide<OauthDatabaseConfiguration>(DefaultOauthDatabaseConfiguration::class)
        provide<OauthUserServiceDatabaseProvider>(OauthUserServiceDatabaseProvider::class)
        provide<OauthClientServiceDatabaseProvider>(OauthClientServiceDatabaseProvider::class)
    }

    val oauthUserServiceDatabaseProvider: OauthUserServiceDatabaseProvider by dependencies
    val oauthClientServiceDatabaseProvider: OauthClientServiceDatabaseProvider by dependencies

    dependencies {
        provide<OauthUserService> { oauthUserServiceDatabaseProvider }
        provide<OauthClientService> { oauthClientServiceDatabaseProvider }
        provide<OauthAuthorizationCodeService>(OauthAuthorizationCodeServiceDatabaseProvider::class)
        provide<OauthTokenService>(OauthTokenServiceDatabaseProvider::class)
        provide<OauthConsentService>(OauthConsentServiceDatabaseProvider::class)
        provide<OauthDeviceCodeService>(OauthDeviceCodeServiceDatabaseProvider::class)
        provide<JwtTokenCustomizer>(JwtCustomizerImpl::class)
        provide(JwksProvider::class)
        provide(JwtVerifier::class)
        provide(SessionCustomizer::class)
        provide<OauthLoginOptionService> {
            DefaultOauthLoginOptionService("/home")
        }
        provide<OauthLogoutActionService> {
            DefaultOauthLogoutActionService("/home")
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
    ): Map<String, Any> {
        return mapOf(
            "extra-scope" to "test-value",
            "scope" to ("${claims.claims["scope"]} extraScope")
        )
    }
}
