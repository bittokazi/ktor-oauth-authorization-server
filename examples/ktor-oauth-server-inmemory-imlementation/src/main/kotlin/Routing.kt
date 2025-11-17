package com.bittokazi.example.ktor

import com.bittokazi.example.ktor.routes.clientRoutes
import com.bittokazi.example.ktor.routes.userRoutes
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Application.configureRouting() {

    routing {
        authenticate("ktor-oauth2") {
            get("/login") {
                // Redirects to 'authorizeUrl' automatically
            }

            get("/auth/callback") {
                val currentPrincipal: OAuthAccessTokenResponse.OAuth2? = call.principal()
                // redirects home if the url is not found before authorization
                currentPrincipal?.let { principal ->
                    principal.state?.let { state ->
                        //call.sessions.set(UserSession(state, principal.accessToken))
                        return@get call.respond(currentPrincipal)
                    }
                }
                call.respondRedirect("/home")
            }
        }
    }

    userRoutes()
    clientRoutes()
}
