package com.bittokazi.ktor.auth

import com.bittokazi.ktor.auth.services.DefaultTemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.TemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.authorization.DefaultOauthAuthorizationProcessService
import com.bittokazi.ktor.auth.services.authorization.OauthAuthorizationProcessService
import com.bittokazi.ktor.auth.services.consent.ConsentProcessService
import com.bittokazi.ktor.auth.services.consent.DefaultConsentProcessService
import com.bittokazi.ktor.auth.services.device.code.DefaultDeviceCodeProcessService
import com.bittokazi.ktor.auth.services.device.code.DeviceCodeProcessService
import com.bittokazi.ktor.auth.services.oidc.DefaultOidcService
import com.bittokazi.ktor.auth.services.oidc.OidcService
import com.bittokazi.ktor.auth.services.session.DefaultSessionProvider
import com.bittokazi.ktor.auth.services.session.SessionProvider
import com.bittokazi.ktor.auth.services.token.TokenGeneratorFactory
import com.bittokazi.ktor.auth.services.token.TokenIntrospectService
import com.bittokazi.ktor.auth.services.token.TokenRevokeService
import com.bittokazi.ktor.auth.services.token.providers.DefaultAuthorizationCodeTokenGenerator
import com.bittokazi.ktor.auth.services.token.providers.DefaultClientCredentialsTokenGenerator
import com.bittokazi.ktor.auth.services.token.providers.DefaultDeviceCodeTokenGenerator
import com.bittokazi.ktor.auth.services.token.providers.DefaultRefreshTokenGenerator
import com.bittokazi.ktor.auth.services.token.providers.DefaultTokenGeneratorFactory
import com.bittokazi.ktor.auth.services.token.providers.DefaultTokenIntrospectService
import com.bittokazi.ktor.auth.services.token.providers.DefaultTokenRevokeService
import com.bittokazi.ktor.auth.utils.configureIssuerProvider
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies

fun Application.configureOauth2AuthorizationServer(
    configureSerialization: Boolean = false,
    defaultLoginRoutes: Boolean = true,
    defaultAuthorizeRoute: Boolean = true,
    defaultOidcRoute: Boolean = true,
    defaultTokenRoute: Boolean = true,
    defaultConsentRoute: Boolean = true,
    defaultDeviceAuthorizationRoute: Boolean = true,
    configureForwardHeaderAndDefaultHeadersPlugin: Boolean = true,
) {
    dependencies {
        provide<SessionProvider>(DefaultSessionProvider::class)
    }
    val oauthAuthorizationProcessService: OauthAuthorizationProcessService? by dependencies
    if (oauthAuthorizationProcessService == null) {
        dependencies {
            provide<OauthAuthorizationProcessService>(DefaultOauthAuthorizationProcessService::class)
        }
    }

    val tokenIntrospectService: TokenIntrospectService? by dependencies
    if (tokenIntrospectService == null) {
        dependencies {
            provide<TokenIntrospectService>(DefaultTokenIntrospectService::class)
        }
    }

    val oidcService: OidcService? by dependencies
    if (oidcService == null) {
        dependencies {
            provide<OidcService>(DefaultOidcService::class)
        }
    }

    val tokenRevokeService: TokenRevokeService? by dependencies
    if (tokenRevokeService == null) {
        dependencies {
            provide<TokenRevokeService>(DefaultTokenRevokeService::class)
        }
    }

    val consentProcessService: ConsentProcessService? by dependencies
    if (consentProcessService == null) {
        dependencies {
            provide<ConsentProcessService>(DefaultConsentProcessService::class)
        }
    }

    val deviceCodeProcessService: DeviceCodeProcessService? by dependencies
    if (deviceCodeProcessService == null) {
        dependencies {
            provide<DeviceCodeProcessService>(DefaultDeviceCodeProcessService::class)
        }
    }

    val templateCustomizerFactory: TemplateCustomizerFactory? by dependencies
    if (templateCustomizerFactory == null) {
        dependencies {
            provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
        }
    }

    dependencies {
        provide(DefaultClientCredentialsTokenGenerator::class)
        provide(DefaultAuthorizationCodeTokenGenerator::class)
        provide(DefaultRefreshTokenGenerator::class)
        provide(DefaultDeviceCodeTokenGenerator::class)
    }
    val defaultClientCredentialsTokenGenerator: DefaultClientCredentialsTokenGenerator by dependencies
    val defaultAuthorizationCodeTokenGenerator: DefaultAuthorizationCodeTokenGenerator by dependencies
    val defaultRefreshTokenGenerator: DefaultRefreshTokenGenerator by dependencies
    val defaultDeviceCodeTokenGenerator: DefaultDeviceCodeTokenGenerator by dependencies

    val tokenGeneratorFactory: TokenGeneratorFactory? by dependencies
    if (tokenGeneratorFactory == null) {
        dependencies {
            provide<TokenGeneratorFactory> {
                DefaultTokenGeneratorFactory(
                    clientCredentialsTokenGenerator = defaultClientCredentialsTokenGenerator,
                    authorizationCodeTokenGenerator = defaultAuthorizationCodeTokenGenerator,
                    refreshTokenGenerator = defaultRefreshTokenGenerator,
                    deviceCodeTokenGenerator = defaultDeviceCodeTokenGenerator,
                )
            }
        }
    }

    configureIssuerProvider()

    if (configureSerialization) {
        configureSerialization()
    }

    if (configureForwardHeaderAndDefaultHeadersPlugin) {
        configureHTTP()
    }
    configureSecurity()
    configureRouting(
        defaultLoginRoutes = defaultLoginRoutes,
        defaultAuthorizeRoute = defaultAuthorizeRoute,
        defaultOidcRoute = defaultOidcRoute,
        defaultTokenRoute = defaultTokenRoute,
        defaultConsentRoute = defaultConsentRoute,
        defaultDeviceAuthorizationRoute = defaultDeviceAuthorizationRoute,
    )
}
