package com.bittokazi.ktor.auth.services.authorization

import io.ktor.server.application.ApplicationCall

interface AuthorizationCodeRedirectUriCustomizer {
    fun customizeRedirectUri(
        redirectUri: String,
        call: ApplicationCall,
    ): String
}
