package com.bittokazi.ktor.auth.services.consent

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall

interface ConsentProcessService {
    suspend fun getConsentPage(
        clientId: String?,
        call: ApplicationCall,
    ): Result<TemplateContent?, ConsentFailure>

    suspend fun processConsent(
        clientId: String?,
        action: String?,
        call: ApplicationCall,
    ): Result<TemplateContent?, ConsentFailure>
}

sealed class ConsentFailure {
    data object LoginRequired : ConsentFailure()

    data class Template(val data: Map<String, Any?>) : ConsentFailure()

    data object BadRequest : ConsentFailure()

    data object InvalidClient : ConsentFailure()

    data object InvalidAction : ConsentFailure()
}
