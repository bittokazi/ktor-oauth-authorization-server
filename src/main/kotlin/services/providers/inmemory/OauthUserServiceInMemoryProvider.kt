package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.ApplicationCall

class OauthUserServiceInMemoryProvider(
    val users: MutableList<OAuthUserDTO>
): OauthUserService {

    override fun findByUsername(username: String, call: ApplicationCall): OAuthUserDTO? {
        return users.find { it.username == username }
    }

    override fun findById(id: String, call: ApplicationCall): OAuthUserDTO? {
        return users.find { it.id == id }
    }
}
