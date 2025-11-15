package com.bittokazi.ktor.auth.services.providers

import java.util.UUID

interface OauthConsentService {
    fun grantConsent(userId: String, clientId: UUID, scopes: List<String>): Boolean
    fun getConsent(userId: String, clientId: UUID): List<String>?
}