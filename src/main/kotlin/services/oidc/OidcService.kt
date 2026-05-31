package com.bittokazi.ktor.auth.services.oidc

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

interface OidcService {
    suspend fun getUserInfo(
        authHeader: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any>, String>

    fun getOpenIdConfiguration(
        baseUrl: String,
        issuer: String,
    ): Map<String, Any>

    fun getJwksConfiguration(): Map<String, Any>
}
