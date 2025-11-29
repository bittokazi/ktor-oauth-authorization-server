package com.bittokazi.example.ktor

import com.bittokazi.example.ktor.databse.MultiTenantDatabaseConfiguration
import com.bittokazi.example.ktor.interceptors.tenantInterceptorPlugin
import com.bittokazi.example.ktor.services.LoginService
import com.bittokazi.example.ktor.services.TwoFaService
import com.bittokazi.example.ktor.services.UserService
import com.bittokazi.example.ktor.tenant.TenantConfiguration
import com.bittokazi.ktor.auth.configureOauth2AuthorizationServer
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtTokenCustomizer
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.SessionExtender
import com.bittokazi.ktor.auth.services.TemplateCustomizer
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
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.plugins.di.provide
import io.ktor.util.AttributeKey
import kotlinx.serialization.json.Json

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

val TENANT_ATTRIBUTE_KEY = AttributeKey<String>("oauth_tenant")

val applicationHttpClient = HttpClient(CIO) {
    install(ContentNegotiation) {
        json(Json {
            ignoreUnknownKeys = true
        })
    }
}

fun Application.module() {
    configureSecurity()

    dependencies {
        provide(TenantConfiguration::class)

        provide<OauthDatabaseConfiguration>(MultiTenantDatabaseConfiguration::class)
        provide<UserService>(UserService::class)
        provide<OauthClientServiceDatabaseProvider>(OauthClientServiceDatabaseProvider::class)
    }

    val userService: UserService by dependencies
    val oauthClientServiceDatabaseProvider: OauthClientServiceDatabaseProvider by dependencies
    val tenantConfiguration: TenantConfiguration by dependencies
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration by dependencies

    dependencies {
        provide<OauthUserService> { userService }
        provide<OauthClientService> { oauthClientServiceDatabaseProvider }
        provide<OauthAuthorizationCodeService>(OauthAuthorizationCodeServiceDatabaseProvider::class)
        provide<OauthTokenService>(OauthTokenServiceDatabaseProvider::class)
        provide<OauthConsentService>(OauthConsentServiceDatabaseProvider::class)
        provide<OauthDeviceCodeService>(OauthDeviceCodeServiceDatabaseProvider::class)
        provide<JwtTokenCustomizer>(JwtCustomizerImpl::class)
        provide(JwksProvider::class)
        provide(JwtVerifier::class)
        provide(SessionCustomizer::class)
        provide<TemplateCustomizer>(TemplateCustomizerImpl::class)

        val loginService = LoginService(
            "/home",
            oauthDatabaseConfiguration
        )

        provide<OauthLoginOptionService> {
            loginService
        }
        provide<OauthLogoutActionService> {
            loginService
        }

        provide<SessionExtender>(SessionExtenderImpl::class)
        provide<TwoFaService>(TwoFaService::class)
    }

    install(tenantInterceptorPlugin(tenantConfiguration))

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

        return mapOf<String, Any>(
            "extra-claim" to "test-value",
            "scope" to ("${claims.claims["scope"]} extraScope")
        )
    }
}

class TemplateCustomizerImpl(
    val tenantConfiguration: TenantConfiguration
): TemplateCustomizer {

    override fun addExtraData(call: ApplicationCall): Map<String, Any> {
        val tenant = tenantConfiguration.tenants.find {
            it.databaseSchema == call.attributes[TENANT_ATTRIBUTE_KEY]
        }

        return mapOf(
            "tenant" to (tenant?.name ?: "")
        )
    }
}
