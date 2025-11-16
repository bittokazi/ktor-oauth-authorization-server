package com.bittokazi.ktor.auth.services

import io.ktor.server.plugins.di.annotations.Property
import io.ktor.server.sessions.SessionsConfig

class SessionCustomizer(
    @Property("oauth.session.encryption-key") val encryptionKey: String? = null,
    @Property("oauth.session.signing-key") val signingKey: String? = null,
    @Property("oauth.session.timeout") val timeout: Long? = 3600,
)

interface SessionExtender {
    fun extent(sessionsConfig: SessionsConfig)
}
