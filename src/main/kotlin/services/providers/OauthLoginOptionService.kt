package com.bittokazi.ktor.auth.services.providers

import com.bittokazi.ktor.auth.OauthUserSession
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.sessions.sessions

interface AuthenticatedUserSession {
    val loginCompleted: Boolean
}

interface OauthLoginOptionService<T : AuthenticatedUserSession> {
    val fallbackAfterLoginRedirectUrl: String

    suspend fun isAfterLoginCheckCompleted(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall,
    ): T

    suspend fun onGoingLogin(
        oauthUserSession: OauthUserSession,
        payload: T,
        call: ApplicationCall,
    )

    suspend fun onSuccessfulLogin(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall,
    )

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

class AuthenticatedUserSessionImpl(
    override val loginCompleted: Boolean,
) : AuthenticatedUserSession

class DefaultOauthLoginOptionService(
    override val fallbackAfterLoginRedirectUrl: String = "/",
) : OauthLoginOptionService<AuthenticatedUserSession> {
    override suspend fun isAfterLoginCheckCompleted(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall,
    ): AuthenticatedUserSession = AuthenticatedUserSessionImpl(loginCompleted = true)

    override suspend fun onGoingLogin(
        oauthUserSession: OauthUserSession,
        payload: AuthenticatedUserSession,
        call: ApplicationCall,
    ) {}

    override suspend fun onSuccessfulLogin(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall,
    ) {}
}
