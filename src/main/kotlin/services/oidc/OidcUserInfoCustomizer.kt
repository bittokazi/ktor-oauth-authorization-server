package com.bittokazi.ktor.auth.services.oidc

import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.server.application.ApplicationCall

interface OidcUserInfoCustomizer {
    fun customize(
        userInfo: MutableMap<String, Any>,
        claims: JWTClaimsSet,
        call: ApplicationCall,
    ): MutableMap<String, Any>
}
