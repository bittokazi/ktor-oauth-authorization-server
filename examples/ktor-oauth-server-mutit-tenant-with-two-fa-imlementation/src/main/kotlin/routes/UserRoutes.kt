package com.bittokazi.example.ktor.routes

import com.bittokazi.example.ktor.services.TwoFaService
import com.bittokazi.example.ktor.services.UserService
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing

fun Application.userRoutes() {
    val userService: UserService by dependencies
    val twoFaService: TwoFaService by dependencies

    routing {
        authenticate {
            get("/api/users/whoami") {
                call.principal<JWTPrincipal>()?.let { principal ->
                    call.respond(
                        userService
                            .getUserById(principal.subject!!, call).also {
                                it?.password = ""
                                it?.twoFaSecret = ""
                            } as Any
                    )
                }
            }

            get("/api/users/two-fa/code") {
                twoFaService.generateSecret(call)
            }

            post("/api/users/two-fa/enable") {
                val params = call.receiveParameters()
                twoFaService.enable2FA(params["code"]?.toInt()!!, params["secret"]!!, call)
            }

            get("/api/users/two-fa/disable") {
                twoFaService.disable(call)
            }
        }
    }
}
