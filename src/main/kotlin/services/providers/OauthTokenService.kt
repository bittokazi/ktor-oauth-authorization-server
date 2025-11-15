package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall
import java.time.Instant
import java.util.UUID

data class AccessTokenDTO(
    val id: UUID,
    val token: String,
    val clientId: UUID,
    val userId: String?,
    val scopes: List<String>,
    val expiresAt: Instant,
    var revoked: Boolean
)

data class RefreshTokenDTO(
    val id: UUID,
    val token: String,
    val clientId: UUID,
    val userId: String?,
    val scopes: List<String>,
    val expiresAt: Instant,
    var revoked: Boolean,
    val rotatedTo: UUID?
)

interface OauthTokenService {
    fun storeAccessToken(token: String, clientId: UUID, userId: String?, scopes: List<String>, expiresAt: Instant, call: ApplicationCall): Boolean

    fun revokeAccessToken(token: String, call: ApplicationCall): Boolean

    fun storeRefreshToken(token: String, clientId: UUID, userId: String?, scopes: List<String>, expiresAt: Instant, call: ApplicationCall): UUID

    fun findByAccessToken(token: String, call: ApplicationCall): AccessTokenDTO?

    fun findByRefreshToken(token: String, call: ApplicationCall): RefreshTokenDTO?

    fun revokeRefreshToken(token: String, call: ApplicationCall): Boolean

    fun rotateRefreshToken(oldToken: String, newToken: String, expiresAt: Instant, call: ApplicationCall): Boolean

    fun logoutAction(userId: String, call: ApplicationCall)
}
