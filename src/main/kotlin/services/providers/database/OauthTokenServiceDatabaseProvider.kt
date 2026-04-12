package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.AccessTokenDTO
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.RefreshTokenDTO
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.javatime.timestamp
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.update
import java.time.Instant
import java.time.Instant.now
import java.util.*
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.toJavaUuid
import kotlin.uuid.toKotlinUuid

@OptIn(ExperimentalUuidApi::class)
object OAuthAccessTokens : Table("oauth_access_tokens") {
    @OptIn(ExperimentalUuidApi::class)
    val id = uuid("id")
    val token = text("token").uniqueIndex()
    val clientId = uuid("client_id")
    val userId = varchar("user_id", 255).nullable()
    val scopes = text("scopes")
    val issuedAt = timestamp("issued_at")
    val expiresAt = timestamp("expires_at")
    val revoked = bool("revoked").default(false)
}

@OptIn(ExperimentalUuidApi::class)
object OAuthRefreshTokens : Table("oauth_refresh_tokens") {
    val id = uuid("id")
    val token = text("token").uniqueIndex()
    val clientId = uuid("client_id")
    val userId = varchar("user_id", 255).nullable()
    val scopes = text("scopes")
    val expiresAt = timestamp("expires_at")
    val revoked = bool("revoked").default(false)
    val rotatedTo = (uuid("rotated_to") references this.id).nullable()
}

@OptIn(ExperimentalUuidApi::class)
class OauthTokenServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthTokenService {

    override fun storeAccessToken(
        token: String,
        clientId: UUID,
        userId: String?,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall
    ): Boolean =
        oauthDatabaseConfiguration.dbQuery(call) {
            OAuthAccessTokens.insert {
                it[OAuthAccessTokens.id] = UUID.randomUUID().toKotlinUuid()
                it[OAuthAccessTokens.token] = token
                it[OAuthAccessTokens.clientId] = clientId.toKotlinUuid()
                it[OAuthAccessTokens.userId] = userId
                it[OAuthAccessTokens.scopes] = scopes.joinToString(",")
                it[OAuthAccessTokens.issuedAt] = now()
                it[OAuthAccessTokens.expiresAt] = expiresAt
            }.insertedCount > 0
        }

    override fun revokeAccessToken(
        token: String,
        call: ApplicationCall
    ): Boolean = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthAccessTokens.update({ OAuthAccessTokens.token eq token }) {
            it[revoked] = true
        } > 0
    }

    override fun storeRefreshToken(
        token: String,
        clientId: UUID,
        userId: String?,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall
    ): UUID = oauthDatabaseConfiguration.dbQuery(call) {
        val id = UUID.randomUUID()
        OAuthRefreshTokens.insert {
            it[OAuthRefreshTokens.id] = id.toKotlinUuid()
            it[OAuthRefreshTokens.token] = token
            it[OAuthRefreshTokens.clientId] = clientId.toKotlinUuid()
            it[OAuthRefreshTokens.userId] = userId
            it[OAuthRefreshTokens.scopes] = scopes.joinToString(",")
            it[OAuthRefreshTokens.expiresAt] = expiresAt
            it[OAuthRefreshTokens.rotatedTo] = null
        }
        id
    }

    override fun findByAccessToken(
        token: String,
        call: ApplicationCall
    ): AccessTokenDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthAccessTokens
            .selectAll()
            .where { OAuthAccessTokens.token eq token }
            .map {
                AccessTokenDTO(
                    id = it[OAuthAccessTokens.id].toJavaUuid(),
                    token = it[OAuthAccessTokens.token],
                    clientId = it[OAuthAccessTokens.clientId].toJavaUuid(),
                    userId = it[OAuthAccessTokens.userId],
                    scopes = it[OAuthAccessTokens.scopes].split(","),
                    expiresAt = it[OAuthAccessTokens.expiresAt],
                    revoked = it[OAuthAccessTokens.revoked]
                )
            }.singleOrNull()
    }

    override fun findByRefreshToken(
        token: String,
        call: ApplicationCall
    ): RefreshTokenDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthRefreshTokens
            .selectAll()
            .where { OAuthRefreshTokens.token eq token }
            .map {
                RefreshTokenDTO(
                    id = it[OAuthRefreshTokens.id].toJavaUuid(),
                    token = it[OAuthRefreshTokens.token],
                    clientId = it[OAuthRefreshTokens.clientId].toJavaUuid(),
                    userId = it[OAuthRefreshTokens.userId],
                    scopes = it[OAuthRefreshTokens.scopes].split(","),
                    expiresAt = it[OAuthRefreshTokens.expiresAt],
                    revoked = it[OAuthRefreshTokens.revoked],
                    rotatedTo = it[OAuthRefreshTokens.rotatedTo]?.toJavaUuid()
                )
            }.singleOrNull()
    }

    override fun revokeRefreshToken(
        token: String,
        call: ApplicationCall
    ): Boolean = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthRefreshTokens.update({ OAuthRefreshTokens.token eq token }) {
            it[revoked] = true
        } > 0
    }

    override fun rotateRefreshToken(
        oldToken: String,
        newToken: String,
        expiresAt: Instant,
        call: ApplicationCall
    ): Boolean = oauthDatabaseConfiguration.dbQuery(call) {
        val old = OAuthRefreshTokens.selectAll().where { OAuthRefreshTokens.token eq oldToken }.singleOrNull()
            ?: return@dbQuery false

        val newId = UUID.randomUUID()
        val inserted = OAuthRefreshTokens.insert {
            it[id] = newId.toKotlinUuid()
            it[token] = newToken
            it[clientId] = old[OAuthRefreshTokens.clientId]
            it[userId] = old[OAuthRefreshTokens.userId]
            it[scopes] = old[OAuthRefreshTokens.scopes]
            it[OAuthRefreshTokens.expiresAt] = expiresAt
        }.insertedCount

        if (inserted > 0) {
            OAuthRefreshTokens.update({ OAuthRefreshTokens.token eq oldToken }) {
                it[revoked] = true
                it[rotatedTo] = newId.toKotlinUuid()
            }
        }
        inserted > 0
    }

    override fun logoutAction(userId: String, clientId: String?, call: ApplicationCall) {

    }
}
