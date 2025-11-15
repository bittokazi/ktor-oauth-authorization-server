package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect

interface OauthLogoutActionService {
    suspend fun afterLogoutAction(userId: String?, call: ApplicationCall)
}

class DefaultOauthLogoutActionService(
    val afterLogoutRedirectUrl: String
): OauthLogoutActionService {

    override suspend fun afterLogoutAction(userId: String?, call: ApplicationCall) {
        call.respondRedirect(afterLogoutRedirectUrl)
    }
}
