package com.bittokazi.ktor.auth.routes

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.Application
import io.ktor.server.mustache.MustacheContent
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set

fun Application.loginRoutes() {

    val oauthUserService: OauthUserService by dependencies
    val oauthAuthorizationCodeService: OauthAuthorizationCodeService by dependencies
    val oauthTokenService: OauthTokenService by dependencies
    val oauthLogoutActionService: OauthLogoutActionService? by dependencies
    val sessionCustomizer: SessionCustomizer by dependencies
    val oauthLoginOptionService: OauthLoginOptionService by dependencies
    val oauthDeviceCodeService: OauthDeviceCodeService by dependencies
    val templateCustomizer: TemplateCustomizer? by dependencies

    routing {
        route("/oauth") {
            get("/login") {
                val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

                val session = call.sessions.get<OauthUserSession>()
                if (session == null) {
                    call.respond(MustacheContent("oauth_templates/login.hbs", templateData))
                    return@get
                }

                if (session.expiresAt > System.currentTimeMillis()) {
                    val ttlSeconds = when (session.rememberMe) {
                        true -> 31536000
                        else -> sessionCustomizer.timeout ?: 3200
                    }
                    val expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000)
                    call.sessions.set(OauthUserSession(session.userId, session.username, expiresAt, session.rememberMe))
                }

                // Retrieve saved original request URL
                if (oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
                    oauthLoginOptionService.completeLogin(call)
                } else {
                    return@get
                }
            }

            post("/login") {
                val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

                val params = call.receiveParameters()
                val username = params["username"] ?: ""
                val password = params["password"] ?: ""
                val rememberMe = params["rememberMe"]?.toBoolean() ?: false

                val user = oauthUserService.findByUsername(username, call)

                if (user == null || !BCrypt.verifyer().verify(password.toCharArray(), user.passwordHash).verified) {
                    // Invalid login
                    call.respond(MustacheContent("oauth_templates/login.hbs", mutableMapOf<String, Any>(
                        "error" to "invalidLogin",
                        "errorMessage" to "Login credentials do not match"
                    ).plus(templateData)))
                    return@post
                }

                // Create session
                val ttlSeconds = when (rememberMe) {
                    true -> 31536000
                    else -> sessionCustomizer.timeout ?: 3200
                }
                val expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000)
                val userSession = OauthUserSession(user.id, user.username, expiresAt, rememberMe)
                call.sessions.set(userSession)

                // Retrieve saved original request URL
                oauthLoginOptionService.onSuccessfulLogin(userSession, call)
                if (oauthLoginOptionService.isAfterLoginCheckCompleted(userSession, call)) {
                    oauthLoginOptionService.completeLogin(call)
                } else {
                    return@post
                }
            }

            get("/logout") {
                val session = call.sessions.get<OauthUserSession>()

                if (session != null) {
                    val userId = session.userId
                    val clientId = call.request.queryParameters["client_id"]

                    oauthAuthorizationCodeService.logoutAction(userId, clientId, call)
                    oauthTokenService.logoutAction(userId, clientId, call)
                    oauthDeviceCodeService.logoutAction(userId, clientId, call)
                    call.sessions.clear("OAUTH_USER_SESSION")
                    call.sessions.clear("OAUTH_ORIGINAL_URL")

                    oauthLogoutActionService?.afterLogoutAction(userId, call)
                }
            }
        }
    }
}
