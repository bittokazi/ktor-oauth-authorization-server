package com.bittokazi.ktor.auth.services.token

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

interface TokenRevokeService {
    suspend fun revoke(
        token: String,
        call: ApplicationCall
    ): Result<Map<String, Any?>, Map<String, Any?>>
}
