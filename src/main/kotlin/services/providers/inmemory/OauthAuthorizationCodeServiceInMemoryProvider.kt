package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.AuthorizationCodeDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import io.ktor.server.application.ApplicationCall
import java.time.Instant
import java.util.UUID

class OauthAuthorizationCodeServiceInMemoryProvider(): OauthAuthorizationCodeService {
    val codes: MutableList<AuthorizationCodeDTO> = mutableListOf()

    override fun createCode(
        code: String,
        clientId: UUID,
        userId: String,
        redirectUri: String,
        scopes: List<String>,
        expiresAt: Instant,
        challenge: String?,
        challengeMethod: String?,
        call: ApplicationCall
    ): Boolean {
        return codes.add(
            AuthorizationCodeDTO(
                code,
                clientId,
                userId,
                redirectUri,
                scopes,
                challenge,
                challengeMethod,
                expiresAt,
                false
            )
        )
    }

    override fun findByCode(code: String, call: ApplicationCall): AuthorizationCodeDTO? {
        return codes.find { it.code == code }
    }

    override fun consumeCode(code: String, call: ApplicationCall): Boolean {
        return codes.find { it.code == code }?.consumed ?: true
    }

    override fun logoutAction(userId: String, clientId: String?, call: ApplicationCall) {

    }
}
