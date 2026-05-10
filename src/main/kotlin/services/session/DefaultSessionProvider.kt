package com.bittokazi.ktor.auth.services.session

import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.CurrentSession
import io.ktor.server.sessions.sessions

class DefaultSessionProvider : SessionProvider {
    override fun getSession(call: ApplicationCall): CurrentSession {
        return call.sessions
    }
}
