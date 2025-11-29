package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall
import java.time.Instant
import java.util.UUID

data class AuthorizationCodeDTO(
    val code: String,
    val clientId: UUID,
    val userId: String,
    val redirectUri: String,
    val scopes: List<String>,
    val codeChallenge: String?,
    val codeChallengeMethod: String?,
    val expiresAt: Instant,
    val consumed: Boolean
)

interface OauthAuthorizationCodeService {
    fun createCode(
        code: String,
        clientId: UUID,
        userId: String,
        redirectUri: String,
        scopes: List<String>,
        expiresAt: Instant,
        challenge: String?,
        challengeMethod: String?,
        call: ApplicationCall
    ): Boolean

    fun findByCode(code: String, call: ApplicationCall): AuthorizationCodeDTO?

    fun consumeCode(code: String, call: ApplicationCall): Boolean

    fun logoutAction(userId: String, clientId: String?, call: ApplicationCall)
}
