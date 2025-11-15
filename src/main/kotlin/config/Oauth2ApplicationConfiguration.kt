package com.bittokazi.ktor.auth.config

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration

data class Oauth2ApplicationConfiguration(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
)
