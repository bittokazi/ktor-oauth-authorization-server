package com.bittokazi.ktor.auth.services.consent

import com.bittokazi.ktor.auth.domains.rest.Result
import io.ktor.server.application.ApplicationCall
import io.ktor.server.mustache.MustacheContent

interface ConsentProcessService {
    suspend fun getConsentPage(
        clientId: String?,
        call: ApplicationCall,
    ): Result<MustacheContent?, ConsentFailure>

    suspend fun processConsent(
        clientId: String?,
        action: String?,
        call: ApplicationCall,
    ): Result<MustacheContent?, ConsentFailure>
}

sealed class ConsentFailure {
    data object LoginRequired : ConsentFailure()

    data class Template(val data: Map<String, Any?>) : ConsentFailure()

    data object BadRequest : ConsentFailure()

    data object InvalidClient : ConsentFailure()

    data object InvalidAction : ConsentFailure()
}
