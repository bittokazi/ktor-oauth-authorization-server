package com.bittokazi.ktor.auth.services.session

import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.CurrentSession

interface SessionProvider {
    fun getSession(call: ApplicationCall): CurrentSession
}
