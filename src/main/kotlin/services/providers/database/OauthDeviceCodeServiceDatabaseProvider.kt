package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeDTO
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.javatime.timestamp
import java.time.Instant
import java.util.*

object OAuthDeviceCodes : Table("oauth_device_codes") {
    val id = uuid("id")
    val clientId = uuid("client_id")
    val userId = varchar("user_id", 255).nullable()
    val scopes = text("scopes")
    val expiresAt = timestamp("expires_at")
    val consumed = bool("consumed").default(false)
    val isDeviceAuthorized = bool("is_device_authorized").default(false)
    val deviceCode = varchar("device_code", 128)
    val userCode = varchar("user_code", 128)
}

class OauthDeviceCodeServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthDeviceCodeService {

    override fun createCode(
        clientId: UUID,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall,
        deviceCode: String,
        userCode: String
    ): Boolean = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthDeviceCodes.insert {
            it[OAuthDeviceCodes.clientId] = clientId
            it[OAuthDeviceCodes.scopes] = scopes.joinToString(",")
            it[OAuthDeviceCodes.expiresAt] = expiresAt
            it[OAuthDeviceCodes.deviceCode] = deviceCode
            it[OAuthDeviceCodes.userCode] = userCode
        }.insertedCount > 0
    }

    override fun findByUserCode(
        code: String,
        call: ApplicationCall
    ): OauthDeviceCodeDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthDeviceCodes
            .selectAll()
            .where {
                (OAuthDeviceCodes.userCode eq code)
                    .and(OAuthDeviceCodes.isDeviceAuthorized eq false)
                    .and(OAuthDeviceCodes.consumed eq false)
            }
            .map {
                OauthDeviceCodeDTO(
                    id = it[OAuthDeviceCodes.id],
                    clientId = it[OAuthDeviceCodes.clientId],
                    userId = it[OAuthDeviceCodes.userId],
                    scopes = it[OAuthDeviceCodes.scopes].split(","),
                    expiresAt = it[OAuthDeviceCodes.expiresAt],
                    consumed = it[OAuthDeviceCodes.consumed],
                    isDeviceAuthorized = it[OAuthDeviceCodes.isDeviceAuthorized],
                    deviceCode = it[OAuthDeviceCodes.deviceCode],
                    userCode = it[OAuthDeviceCodes.userCode],
                )
            }.singleOrNull()
    }

    override fun findByDeviceCode(
        code: String,
        isAuthorized: Boolean,
        consumed: Boolean,
        call: ApplicationCall
    ): OauthDeviceCodeDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthDeviceCodes
            .selectAll()
            .where {
                (OAuthDeviceCodes.deviceCode eq code)
                    .and(OAuthDeviceCodes.isDeviceAuthorized eq isAuthorized)
                    .and(OAuthDeviceCodes.consumed eq consumed)
            }
            .map {
                OauthDeviceCodeDTO(
                    id = it[OAuthDeviceCodes.id],
                    clientId = it[OAuthDeviceCodes.clientId],
                    userId = it[OAuthDeviceCodes.userId],
                    scopes = it[OAuthDeviceCodes.scopes].split(","),
                    expiresAt = it[OAuthDeviceCodes.expiresAt],
                    consumed = it[OAuthDeviceCodes.consumed],
                    isDeviceAuthorized = it[OAuthDeviceCodes.isDeviceAuthorized],
                    deviceCode = it[OAuthDeviceCodes.deviceCode],
                    userCode = it[OAuthDeviceCodes.userCode],
                )
            }.singleOrNull()
    }

    override fun consumeDeviceCode(
        code: String,
        call: ApplicationCall
    ): Boolean = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthDeviceCodes.update({ OAuthDeviceCodes.deviceCode eq code }) {
            it[OAuthDeviceCodes.consumed] = true
        } > 0
    }

    override fun authorizeDevice(
        code: String,
        userId: String,
        call: ApplicationCall
    ): Boolean = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthDeviceCodes.update({ OAuthDeviceCodes.deviceCode eq code }) {
            it[OAuthDeviceCodes.isDeviceAuthorized] = true
            it[OAuthDeviceCodes.userId] = userId
        } > 0
    }

    override fun logoutAction(userId: String, clientId: String?, call: ApplicationCall) {

    }
}
