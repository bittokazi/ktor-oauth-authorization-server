package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.oidc.OidcService
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.oidcRoutes() {
    val oidcService: OidcService by dependencies

    routing {
        authenticate {
            get("/oauth/userinfo") {
                val authHeader = call.request.headers["Authorization"]

                when (val result = oidcService.getUserInfo(authHeader, call)) {
                    is Result.Success -> call.respond(result.outcome)
                    is Result.Failure -> {
                        val statusCode =
                            when (result.errorBody) {
                                "No Authorization Provided" -> HttpStatusCode.Unauthorized
                                "Invalid authorization token" -> HttpStatusCode.Unauthorized
                                "Unauthorized" -> HttpStatusCode.Unauthorized
                                "User not found" -> HttpStatusCode.NotFound
                                else -> HttpStatusCode.BadRequest
                            }
                        call.respond(statusCode, mapOf("error" to result.errorBody))
                    }
                }
            }
        }

        get("/.well-known/openid-configuration") {
            val issuer = call.getBaseUrl()
            val baseUrl = "${call.getBaseUrl()}/oauth"

            val configuration = oidcService.getOpenIdConfiguration(baseUrl, issuer)
            call.respond(configuration)
        }

        get("/.well-known/jwks.json") {
            val jwks = oidcService.getJwksConfiguration()
            call.respond(jwks)
        }
    }
}
