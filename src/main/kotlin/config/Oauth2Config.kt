package com.bittokazi.ktor.auth.config

import io.ktor.server.plugins.di.annotations.Property
import kotlinx.serialization.Serializable

@Serializable
data class Oauth2Config(
    @Property("oauth.default-logout-redirect-url") val afterLogoutRedirectUrl: String,
)
