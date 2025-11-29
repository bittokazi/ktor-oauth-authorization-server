package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeDTO
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import io.ktor.server.application.ApplicationCall
import java.time.Instant
import java.util.UUID

class OauthDeviceCodeServiceInMemoryProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthDeviceCodeService {

    val codes: MutableList<OauthDeviceCodeDTO> = mutableListOf()

    override fun createCode(
        clientId: UUID,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall,
        deviceCode: String,
        userCode: String
    ): Boolean {
        codes.add(
            OauthDeviceCodeDTO(
                id = UUID.randomUUID(),
                clientId = clientId,
                scopes = scopes,
                expiresAt = expiresAt,
                deviceCode = deviceCode,
                userCode = userCode,
                consumed = false,
                isDeviceAuthorized = false,
                userId = null
            )
        )
        return true
    }

    override fun findByUserCode(
        code: String,
        call: ApplicationCall
    ): OauthDeviceCodeDTO? {
        return codes.find {
            it.userCode == code && !it.isDeviceAuthorized && !it.consumed
        }
    }

    override fun findByDeviceCode(
        code: String,
        isAuthorized: Boolean,
        consumed: Boolean,
        call: ApplicationCall
    ): OauthDeviceCodeDTO? {
        return codes.find {
            it.userCode == code && it.isDeviceAuthorized == isAuthorized && it.consumed == consumed
        }
    }

    override fun consumeDeviceCode(
        code: String,
        call: ApplicationCall
    ): Boolean {
        codes.find { it.deviceCode == code }?.consumed = true
        return true
    }

    override fun authorizeDevice(
        code: String,
        userId: String,
        call: ApplicationCall
    ): Boolean {
        codes.find { it.deviceCode == code }?.userId = userId
        codes.find { it.deviceCode == code }?.isDeviceAuthorized = true
        return true
    }

    override fun logoutAction(userId: String, clientId: String?, call: ApplicationCall) {
        clientId?.let {
            codes.removeIf { it.userId == userId && it.clientId == UUID.fromString(clientId) }
        } ?: run {
            codes.removeIf { it.userId == userId }
        }
    }
}
