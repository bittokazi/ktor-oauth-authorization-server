package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall
import java.util.UUID

interface OauthConsentService {
    fun grantConsent(userId: String, clientId: UUID, scopes: List<String>, call: ApplicationCall): Boolean
    fun getConsent(userId: String, clientId: UUID, call: ApplicationCall): List<String>?
}