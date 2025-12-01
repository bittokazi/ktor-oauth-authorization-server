package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.AccessTokenDTO
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.RefreshTokenDTO
import io.ktor.server.application.ApplicationCall
import java.time.Instant
import java.util.UUID

class OauthTokenServiceInMemoryProvider: OauthTokenService {
    val accessTokens: MutableList<AccessTokenDTO> = mutableListOf()
    val refreshTokens: MutableList<RefreshTokenDTO> = mutableListOf()

    override fun storeAccessToken(
        token: String,
        clientId: UUID,
        userId: String?,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall
    ): Boolean {
        return accessTokens.add(
            AccessTokenDTO(
                UUID.randomUUID(),
                token,
                clientId,
                userId,
                scopes,
                expiresAt,
                false
            )
        )
    }

    override fun revokeAccessToken(token: String, call: ApplicationCall): Boolean {
        accessTokens.find { it.token == token }?.revoked = true
        return true
    }

    override fun storeRefreshToken(
        token: String,
        clientId: UUID,
        userId: String?,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall
    ): UUID {
        val refreshTokenDTO = RefreshTokenDTO(
            UUID.randomUUID(),
            token,
            clientId,
            userId,
            scopes,
            expiresAt,
            false,
            null
        )
        refreshTokens.add(refreshTokenDTO)
        return refreshTokenDTO.id
    }

    override fun findByAccessToken(token: String, call: ApplicationCall): AccessTokenDTO? {
        return accessTokens.find { it.token == token }
    }

    override fun findByRefreshToken(token: String, call: ApplicationCall): RefreshTokenDTO? {
        return refreshTokens.find { it.token == token }
    }

    override fun revokeRefreshToken(token: String, call: ApplicationCall): Boolean {
        refreshTokens.find { it.token == token }?.revoked = true
        return true
    }

    override fun rotateRefreshToken(
        oldToken: String,
        newToken: String,
        expiresAt: Instant,
        call: ApplicationCall
    ): Boolean {
        val old = refreshTokens.find { it.token == oldToken }!!
        val refreshTokenDTO = RefreshTokenDTO(
            UUID.randomUUID(),
            newToken,
            old.clientId,
            old.userId,
            old.scopes,
            expiresAt,
            false,
            old.id
        )
        refreshTokens.add(refreshTokenDTO)
        refreshTokens.find { it.token == oldToken }?.revoked = true
        return true
    }

    override fun logoutAction(userId: String, clientId: String?, call: ApplicationCall) {

    }
}
