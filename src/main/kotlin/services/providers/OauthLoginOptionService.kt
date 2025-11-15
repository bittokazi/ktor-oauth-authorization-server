package com.bittokazi.ktor.auth.services.providers

import com.bittokazi.ktor.auth.OauthUserSession
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.sessions.sessions

interface OauthLoginOptionService {
    val fallbackAfterLoginRedirectUrl: String
    suspend fun isAfterLoginCheckCompleted(oauthUserSession: OauthUserSession, call: ApplicationCall): Boolean

    suspend fun completeLogin(call: ApplicationCall) {
        val originalUrl = call.sessions.get("OAUTH_ORIGINAL_URL")
        if (originalUrl != null) {
            call.sessions.clear("OAUTH_ORIGINAL_URL")
            call.respondRedirect(originalUrl.toString())
        } else {
            call.respondRedirect(fallbackAfterLoginRedirectUrl) // fallback
        }
    }
}

class DefaultOauthLoginOptionService(
    override val fallbackAfterLoginRedirectUrl: String = "/"
) : OauthLoginOptionService {

    override suspend fun isAfterLoginCheckCompleted(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall
    ): Boolean = true
}
