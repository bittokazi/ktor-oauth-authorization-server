package com.bittokazi.ktor.auth.services.providers

import com.bittokazi.ktor.auth.config.Oauth2Config
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect

interface OauthLogoutActionService {
    suspend fun afterLogoutAction(
        userId: String?,
        clientId: String?,
        call: ApplicationCall,
    )
}

class DefaultOauthLogoutActionService(
    val oauth2Config: Oauth2Config,
    val oauthClientService: OauthClientService,
) : OauthLogoutActionService {
    override suspend fun afterLogoutAction(
        userId: String?,
        clientId: String?,
        call: ApplicationCall,
    ) {
        val client = clientId?.let { oauthClientService.findByClientId(it, call) }
        val redirectUrl = client?.postLogoutRedirectUri ?: oauth2Config.afterLogoutRedirectUrl
        call.respondRedirect(redirectUrl)
    }
}
