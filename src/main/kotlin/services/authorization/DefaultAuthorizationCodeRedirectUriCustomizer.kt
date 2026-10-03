package com.bittokazi.ktor.auth.services.authorization

class DefaultAuthorizationCodeRedirectUriCustomizer : AuthorizationCodeRedirectUriCustomizer {
    override fun customizeRedirectUri(
        redirectUri: String,
        call: io.ktor.server.application.ApplicationCall,
    ): String {
        // Default implementation does not modify the redirect URI
        return redirectUri
    }
}
