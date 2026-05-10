package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.authorization.OauthAuthorizationProcessService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.sessions.sessions

fun Application.authorizeRoute() {
    val oauthAuthorizationProcessService: OauthAuthorizationProcessService by dependencies

    routing {
        get("/oauth/authorize") {
            val clientId = call.request.queryParameters["client_id"]
            val redirectUri = call.request.queryParameters["redirect_uri"]
            val responseType = call.request.queryParameters["response_type"]
            val scope = call.request.queryParameters["scope"]
            val state = call.request.queryParameters["state"]
            val codeChallenge = call.request.queryParameters["code_challenge"]
            val codeChallengeMethod = call.request.queryParameters["code_challenge_method"]

            // Validate that required parameters are present
            if (clientId == null || redirectUri == null) {
                call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid request"))
                return@get
            }

            // Call the authorization service
            val result =
                oauthAuthorizationProcessService
                    .authorize(
                        clientId = clientId,
                        redirectUri = redirectUri,
                        responseType = responseType ?: "",
                        scope = scope,
                        state = state,
                        codeChallenge = codeChallenge,
                        codeChallengeMethod = codeChallengeMethod,
                        call = call,
                    )

            when (result) {
                is Result.Success -> {
                    // Check for special cases
                    val authorizationCode = result.outcome
                    val code = authorizationCode["code"] as String
                    val resultState = authorizationCode["state"]

                    val redirectUrl = "$redirectUri?code=$code${if (resultState != null) "&state=$resultState" else ""}"
                    call.respondRedirect(redirectUrl)
                }

                is Result.Failure -> {
                    val errorBody = result.errorBody
                    val statusCode = (errorBody["statusCode"] as? HttpStatusCode) ?: HttpStatusCode.BadRequest
                    val requiresLogin = errorBody["requiresLogin"] as? Boolean ?: false
                    val requiresConsent = errorBody["requiresConsent"] as? Boolean ?: false

                    when {
                        requiresLogin -> {
                            // Save original URL and redirect to login
                            call.sessions.clear("OAUTH_USER_SESSION")
                            call.sessions.set("OAUTH_ORIGINAL_URL", call.request.uri)
                            call.respondRedirect("/oauth/login")
                        }

                        requiresConsent -> {
                            // Redirect to consent screen
                            val clientIdForConsent = errorBody["clientId"] as String
                            call.sessions.set("OAUTH_ORIGINAL_URL", call.request.uri)
                            call.respondRedirect("/oauth/consent?client_id=$clientIdForConsent")
                        }

                        else -> {
                            // Return error response
                            call.respond(statusCode, errorBody)
                        }
                    }
                }
            }
        }
    }
}
