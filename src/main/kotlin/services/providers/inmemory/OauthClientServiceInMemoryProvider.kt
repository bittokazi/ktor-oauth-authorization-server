package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import io.ktor.server.application.ApplicationCall

class OauthClientServiceInMemoryProvider(
    val clients: MutableList<OAuthClientDTO>
): OauthClientService {

    init {
        if(clients.isEmpty()) {
            throw RuntimeException("You have to define atleast 1 client")
        } else {
            clients.forEachIndexed { index, client ->
                client.isDefault = index == 0
            }
        }
    }

    override fun findByClientId(clientId: String, call: ApplicationCall): OAuthClientDTO? {
        return clients.find { it.clientId == clientId }
    }

    override fun findDefaultClient(call: ApplicationCall): OAuthClientDTO? {
        return clients.find { it.isDefault }
    }
}
