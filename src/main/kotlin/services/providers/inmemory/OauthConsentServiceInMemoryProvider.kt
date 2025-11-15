package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import java.util.UUID

data class ConsentRecord(
    val userId: String,
    val clientId: UUID,
    val scopes: List<String>
)

class OauthConsentServiceInMemoryProvider : OauthConsentService {
    private val consents = mutableListOf<ConsentRecord>()

    override fun grantConsent(userId: String, clientId: UUID, scopes: List<String>): Boolean {
        consents.removeIf { it.userId == userId && it.clientId == clientId }
        consents.add(ConsentRecord(userId, clientId, scopes))
        return true
    }

    override fun getConsent(userId: String, clientId: UUID): List<String>? {
        return consents.find { it.userId == userId && it.clientId == clientId }?.scopes
    }
}
