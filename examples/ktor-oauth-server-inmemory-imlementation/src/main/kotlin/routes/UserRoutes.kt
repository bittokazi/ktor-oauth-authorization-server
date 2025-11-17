package com.bittokazi.example.ktor.routes

import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.userRoutes() {
    val oauthUserService: OauthUserService by dependencies

    routing {
        authenticate {
            get("/api/users/whoami") {
                call.principal<JWTPrincipal>()?.let { principal ->
                    call.respond(
                        oauthUserService
                            .findById(principal.subject!!, call).also { it?.passwordHash = "" } as Any
                    )
                }
            }
        }
    }
}
