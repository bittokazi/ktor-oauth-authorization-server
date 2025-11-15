package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.mustache.MustacheContent
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions

fun Application.consentRoute() {

    val oauthClientService: OauthClientService by dependencies
    val oauthConsentService: OauthConsentService by dependencies
    val oauthLoginOptionService: OauthLoginOptionService by dependencies

    routing {
        get("/oauth/consent") {
            val clientId = call.request.queryParameters["client_id"]

            // Check user session
            val session = call.sessions.get<OauthUserSession>()
            if (session == null || session.expiresAt < System.currentTimeMillis()) {
                // No session/expired: save original request so we can come back later
                call.sessions.clear("OAUTH_USER_SESSION")
                call.respondRedirect("/oauth/login")
                return@get
            }

            if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
                return@get
            }

            // Validate request
            if (clientId == null) {
                call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid request"))
                return@get
            }

            val client = oauthClientService.findByClientId(clientId, call)
                ?: return@get call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid client_id"))

            if (client.consentRequired) {
                when (val consents = oauthConsentService.getConsent(userId = session.userId, clientId = client.id)) {
                    null -> {
                        call.respond(MustacheContent("consent.hbs", mapOf(
                            "clientName" to client.clientName,
                            "scopes" to client.scopes,
                            "clientId" to client.clientId
                        )))
                        return@get
                    }
                    else -> {
                        if (!consents.containsAll(client.scopes)) {
                            call.respond(MustacheContent("consent.hbs", mapOf(
                                "clientName" to client.clientName,
                                "scopes" to client.scopes,
                                "clientId" to client.clientId
                            )))
                            return@get
                        }
                        // Retrieve saved original request URL
                        oauthLoginOptionService.completeLogin(call)
                    }
                }
            } else {
                // Retrieve saved original request URL
                oauthLoginOptionService.completeLogin(call)
            }
        }

        post("/oauth/consent") {

            val session = call.sessions.get<OauthUserSession>()
            if (session == null || session.expiresAt < System.currentTimeMillis()) {
                call.sessions.clear("OAUTH_USER_SESSION")
                call.respondRedirect("/oauth/login")
                return@post
            }

            val params = call.receiveParameters()

            val clientIdParam = call.request.queryParameters["client_id"]
                ?: params["client_id"]

            val action = params["action"]

            if (clientIdParam == null || action == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Invalid request"))
                return@post
            }

            val client = oauthClientService.findByClientId(clientIdParam, call)
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Invalid client_id"))

            when (action) {
                "approve" -> {
                    oauthConsentService.grantConsent(
                        userId = session.userId,
                        clientId = client.id,
                        scopes = client.scopes
                    )

                    // Redirect back to original URL (authorization endpoint)
                    oauthLoginOptionService.completeLogin(call)
                }
                "deny" -> {
                    call.sessions.clear("OAUTH_ORIGINAL_URL")

                    call.respond(
                        HttpStatusCode.Forbidden,
                        MustacheContent(
                            "consent_denied.hbs",
                            mapOf(
                                "error" to "access_denied",
                                "error_description" to "You have denied access to the application."
                            )
                        )
                    )
                }
                else -> {
                    call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Invalid action"))
                }
            }
        }
    }
}
