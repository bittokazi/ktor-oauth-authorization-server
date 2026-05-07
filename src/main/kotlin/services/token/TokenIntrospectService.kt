package com.bittokazi.ktor.auth.services.token

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

interface TokenIntrospectService {
    suspend fun introspect(
        token: String,
        clientId: String,
        clientSecret: String,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>>
}
