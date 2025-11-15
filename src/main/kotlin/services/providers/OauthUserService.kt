package com.bittokazi.ktor.auth.services.providers

import io.ktor.server.application.ApplicationCall

data class OAuthUserDTO(
    val id: String,
    var username: String,
    var email: String?,
    var firstName: String?,
    var lastName: String?,
    var isActive: Boolean,
    var passwordHash: String? = null
)

interface OauthUserService {
    fun findByUsername(username: String, call: ApplicationCall): OAuthUserDTO?
    fun findById(id: String, call: ApplicationCall): OAuthUserDTO?
}
