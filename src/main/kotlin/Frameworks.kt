package com.bittokazi.ktor.auth

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.database.DefaultOauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtTokenCustomizer
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.*
import io.ktor.server.plugins.di.*

fun Application.configureFrameworks(
    configureDatabase: Boolean = false,
    oauthUserService: OauthUserService,
    oauthClientService: OauthClientService,
    oauthAuthorizationCodeService: OauthAuthorizationCodeService,
    oauthTokenService: OauthTokenService,
    jwtTokenCustomizer: JwtTokenCustomizer? = null
) {
    dependencies {
        if(configureDatabase) {
            provide<OauthDatabaseConfiguration>(DefaultOauthDatabaseConfiguration::class)
        }
        if (jwtTokenCustomizer != null) {
            provide<JwtTokenCustomizer> { jwtTokenCustomizer }
        }
        provide<OauthUserService> { oauthUserService }
        provide<OauthClientService> { oauthClientService }
        provide<OauthAuthorizationCodeService> { oauthAuthorizationCodeService }
        provide<OauthTokenService> { oauthTokenService }
        provide(JwksProvider::class)
        provide(JwtVerifier::class)
    }
}
