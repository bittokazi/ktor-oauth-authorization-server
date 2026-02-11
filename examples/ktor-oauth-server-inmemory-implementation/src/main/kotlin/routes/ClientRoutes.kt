package com.bittokazi.example.ktor.routes

import com.bittokazi.ktor.auth.services.providers.OauthClientService
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.clientRoutes() {
    val oauthClientService: OauthClientService by dependencies

    routing {
        authenticate {
            get("/api/oauth-clients/{id}") {

                call.respond(
                    message = oauthClientService.findByClientId(call.parameters["id"]!!, call) as Any
                )
            }
        }
    }
}
