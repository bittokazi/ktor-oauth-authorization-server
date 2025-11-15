package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall
import java.util.UUID

data class OAuthClientDTO(
    val id: UUID,
    var clientId: String,
    var clientName: String,
    var clientType: String,
    var redirectUris: List<String>,
    var scopes: List<String>,
    var grantTypes: List<String>,
    var clientSecret: String? = null,
    var accessTokenValidity: Long = 300,
    var refreshTokenValidity: Long = 7200,
    var isDefault: Boolean = false,
    var consentRequired: Boolean = true
)

interface OauthClientService {
    fun findByClientId(clientId: String, call: ApplicationCall): OAuthClientDTO?
    fun findDefaultClient(call: ApplicationCall): OAuthClientDTO?
}
