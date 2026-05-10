package com.bittokazi.ktor.auth.services.authorization

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

interface OauthAuthorizationProcessService {
    suspend fun authorize(
        clientId: String,
        redirectUri: String,
        responseType: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>>
}
