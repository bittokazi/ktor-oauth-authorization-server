package com.bittokazi.example.ktor.routes

import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.database.OAuthUsers
import com.bittokazi.ktor.auth.services.providers.database.OauthUserServiceDatabaseProvider
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import org.jetbrains.exposed.sql.selectAll

fun Application.userRoutes() {
    val oauthUserServiceDatabaseProvider: OauthUserServiceDatabaseProvider by dependencies

    routing {
        authenticate {
            get("/api/users/whoami") {
                call.principal<JWTPrincipal>()?.let { principal ->
                    call.respond(
                        oauthUserServiceDatabaseProvider
                            .findById(principal.subject!!, call).also { it?.passwordHash = "" } as Any
                    )
                }
            }

            get("/api/users") {
                call.respond(
                    oauthUserServiceDatabaseProvider.runQuery(call) { users ->
                        users.selectAll().map {
                            OAuthUserDTO(
                                it[OAuthUsers.id],
                                it[OAuthUsers.username],
                                it[OAuthUsers.email],
                                it[OAuthUsers.firstName],
                                it[OAuthUsers.lastName],
                                it[OAuthUsers.isActive]
                            )
                        }
                    }
                )
            }
        }
    }
}
