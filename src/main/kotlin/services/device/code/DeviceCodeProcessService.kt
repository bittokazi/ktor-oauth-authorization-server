package com.bittokazi.ktor.auth.services.device.code

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

interface DeviceCodeProcessService {
    suspend fun createDeviceAuthorization(
        clientId: String?,
        scope: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any>, Pair<Int, Any>>

    suspend fun getDeviceVerificationPage(call: ApplicationCall): Result<Map<String, Any>, VerificationFailure>

    suspend fun verifyDeviceCode(
        userCode: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any>, VerificationFailure>
}

sealed class VerificationFailure {
    data object LoginRequired : VerificationFailure()

    data class Template(
        val data: Map<String, Any?>,
    ) : VerificationFailure()
}
