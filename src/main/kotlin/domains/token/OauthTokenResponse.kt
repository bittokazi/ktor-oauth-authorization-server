package com.bittokazi.ktor.auth.domains.token

import kotlinx.serialization.Serializable

@Serializable
data class OauthTokenResponse(
    val access_token: String? = null,
    val token_type: String? = null,
    val expires_in: Long? = null,
    val refresh_token: String? = null,
    val id_token: String? = null,
    val scope: String? = null,
)
