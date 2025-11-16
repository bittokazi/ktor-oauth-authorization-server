package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import java.time.Instant
import java.util.UUID

fun Application.authorizeRoute() {

    val oauthClientService: OauthClientService by dependencies
    val oauthUserService: OauthUserService by dependencies
    val oauthAuthorizationCodeService: OauthAuthorizationCodeService by dependencies
    val sessionCustomizer: SessionCustomizer by dependencies
    val oauthConsentService: OauthConsentService by dependencies
    val oauthLoginOptionService: OauthLoginOptionService by dependencies

    routing {
        get("/oauth/authorize") {
            val clientId = call.request.queryParameters["client_id"]
            val redirectUri = call.request.queryParameters["redirect_uri"]
            val responseType = call.request.queryParameters["response_type"]
            val scope = call.request.queryParameters["scope"]
            val state = call.request.queryParameters["state"]
            val codeChallenge = call.request.queryParameters["code_challenge"]
            val codeChallengeMethod = call.request.queryParameters["code_challenge_method"]

            // Validate request
            if (clientId == null || redirectUri == null || responseType != "code") {
                call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid request"))
                return@get
            }

            val client = oauthClientService.findByClientId(clientId, call)
                ?: return@get call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid client_id"))

            if (!client.isDefault && !client.redirectUris.contains(redirectUri)) {
                return@get call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid redirect_uri"))
            }

            if (client.isDefault && call.getBaseUrl()
                .replace("http://", "").replace("https//", "").replace("www.", "") != redirectUri
                    .replace("http://", "").replace("https//", "").replace("www.", "")
                    .split("/").firstOrNull()) {
                return@get call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid redirect_uri"))
            }

            if (!client.scopes.containsAll(scope?.split(" ")?.toList() ?: emptyList())) {
                return@get call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid scopes"))
            }

            // Check user session
            val session = call.sessions.get<OauthUserSession>()
            if (session == null || session.expiresAt < System.currentTimeMillis()) {
                // No session/expired: save original request so we can come back later
                call.sessions.clear("OAUTH_USER_SESSION")
                val authRequestUrl = call.request.uri
                call.sessions.set("OAUTH_ORIGINAL_URL", authRequestUrl)
                call.respondRedirect("/oauth/login")
                return@get
            }

            val authRequestUrl = call.request.uri
            call.sessions.set("OAUTH_ORIGINAL_URL", authRequestUrl)
            if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
                return@get
            } else {
                call.sessions.clear("OAUTH_ORIGINAL_URL")
            }

            if (client.consentRequired) {
                when (val consents = oauthConsentService.getConsent(userId = session.userId, clientId = client.id, call)) {
                   null -> {
                       val authRequestUrl = call.request.uri
                       call.sessions.set("OAUTH_ORIGINAL_URL", authRequestUrl)
                       call.respondRedirect("/oauth/consent?client_id=${client.clientId}")
                       return@get
                   }
                   else -> {
                       if (!consents.containsAll(client.scopes)) {
                           val authRequestUrl = call.request.uri
                           call.sessions.set("OAUTH_ORIGINAL_URL", authRequestUrl)
                           call.respondRedirect("/oauth/consent?client_id=${client.clientId}")
                           return@get
                       }
                   }
               }
            }

            // User is logged in → issue authorization code
            val user = oauthUserService.findByUsername(session.username, call)
                ?: return@get call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "User not found"))

            if (session.expiresAt > System.currentTimeMillis()) {
                val ttlSeconds = when (session.rememberMe) {
                    true -> 31536000
                    else -> sessionCustomizer.timeout ?: 3200
                }
                val expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000)
                    call.sessions.set(OauthUserSession(session.userId, session.username, expiresAt, session.rememberMe))
            }

            val code = UUID.randomUUID().toString()
            val expiresAt = Instant.now().plusSeconds(300)

            oauthAuthorizationCodeService.createCode(
                code,
                client.id,
                user.id,
                redirectUri,
                scope?.split(" ") ?: emptyList(),
                expiresAt,
                codeChallenge,
                codeChallengeMethod,
                call
            )

            val redirectUrl = "$redirectUri?code=$code${if (state != null) "&state=$state" else ""}"
            call.respondRedirect(redirectUrl)
        }
    }
}
