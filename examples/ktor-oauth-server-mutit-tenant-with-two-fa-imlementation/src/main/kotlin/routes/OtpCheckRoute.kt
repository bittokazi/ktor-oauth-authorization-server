package com.bittokazi.example.ktor.routes

import com.bittokazi.example.ktor.UserTwoFaSession
import com.bittokazi.example.ktor.models.UserData
import com.bittokazi.example.ktor.models.Users
import com.bittokazi.example.ktor.services.TwoFaService
import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.userSessionCheck
import io.ktor.server.application.Application
import io.ktor.server.mustache.MustacheContent
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import org.jetbrains.exposed.sql.selectAll

fun Application.otpCheckRoute() {

    val oauthDatabaseConfiguration: OauthDatabaseConfiguration by dependencies
    val twoFaService: TwoFaService by dependencies

    routing {

        get("/otp-check") {
            userSessionCheck(call) {
                val session = call.sessions.get<UserTwoFaSession>()
                val oauthUserSession = call.sessions.get<OauthUserSession>()

                when (session) {
                    null -> {
                        val user = oauthDatabaseConfiguration.dbQuery(call) {
                            Users.selectAll()
                                .where { Users.id eq oauthUserSession!!.userId.toLong() }
                                .map {
                                    UserData(
                                        twoFaEnabled = it[Users.twoFaEnabled]
                                    )
                                }.singleOrNull()
                        }

                        when (user?.twoFaEnabled) {
                            true -> {
                                call.respond(MustacheContent("otp-check.hbs", mapOf<String, Any>()))
                            }
                            else -> {
                                val session = UserTwoFaSession(user?.id.toString(), user!!.email)
                                call.sessions.set(session)
                            }
                        }
                    }
                    else -> {
                        when (session.userId == oauthUserSession!!.userId) {
                            true -> call.respondRedirect("/login")
                            else -> call.respond(MustacheContent("otp-check.hbs", mapOf<String, Any>()))
                        }

                    }
                }
            }
        }

        post("/otp-check") {
            userSessionCheck(call) {
                val params = call.receiveParameters()

                val code = params["otp"]

                twoFaService.verify(code?.toInt()!!, call)
            }
        }
    }
}
