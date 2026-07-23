package com.bittokazi.ktor.auth.services

import com.bittokazi.ktor.auth.OauthUserSession
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions

suspend fun userSessionCheck(
    call: ApplicationCall,
    chain: suspend (call: ApplicationCall) -> Unit,
) {
    if (!isValidUserSession(call)) {
        call.respondRedirect("/oauth/login")
        return
    }
    return chain(call)
}

fun isValidUserSession(call: ApplicationCall): Boolean {
    val session = call.sessions.get<OauthUserSession>()
    return !(session == null || session.expiresAt < System.currentTimeMillis())
}
