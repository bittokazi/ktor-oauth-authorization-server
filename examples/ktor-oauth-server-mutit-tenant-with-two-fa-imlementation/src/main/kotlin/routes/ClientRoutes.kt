package com.bittokazi.example.ktor.routes

import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.database.OAuthClients
import com.bittokazi.ktor.auth.services.providers.database.OauthClientServiceDatabaseProvider
import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import org.jetbrains.exposed.sql.selectAll

fun Application.clientRoutes() {
    val oauthClientServiceDatabaseProvider: OauthClientServiceDatabaseProvider by dependencies

    routing {
        authenticate {
            get("/api/oauth-clients") {
                call.respond(
                    oauthClientServiceDatabaseProvider.runQuery(call) { clients ->
                        clients.selectAll().map {
                            OAuthClientDTO(
                                it[OAuthClients.id],
                                it[OAuthClients.clientId],
                                it[OAuthClients.clientName],
                                it[OAuthClients.clientType],
                                it[OAuthClients.redirectUris].split(","),
                                it[OAuthClients.scopes].split(","),
                                it[OAuthClients.grantTypes].split(","),
                                accessTokenValidity = it[OAuthClients.accessTokenValidity],
                                refreshTokenValidity = it[OAuthClients.refreshTokenValidity]
                            )
                        }
                    }
                )
            }
        }
    }
}
