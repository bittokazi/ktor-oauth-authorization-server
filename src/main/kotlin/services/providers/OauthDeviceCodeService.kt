package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall
import java.time.Instant
import java.util.UUID

data class OauthDeviceCodeDTO(
    val id: UUID,
    val clientId: UUID,
    var userId: String?,
    val scopes: List<String>,
    val expiresAt: Instant,
    var consumed: Boolean,
    var isDeviceAuthorized: Boolean,
    val deviceCode: String,
    val userCode: String
)

interface OauthDeviceCodeService {
    fun createCode(
        clientId: UUID,
        scopes: List<String>,
        expiresAt: Instant,
        call: ApplicationCall,
        deviceCode: String,
        userCode: String
    ): Boolean

    fun findByUserCode(code: String, call: ApplicationCall): OauthDeviceCodeDTO?

    fun findByDeviceCode(code: String, isAuthorized: Boolean, consumed: Boolean, call: ApplicationCall): OauthDeviceCodeDTO?

    fun consumeDeviceCode(code: String, call: ApplicationCall): Boolean

    fun authorizeDevice(code: String, userId: String, call: ApplicationCall): Boolean

    fun logoutAction(userId: String, clientId: String?, call: ApplicationCall)
}
