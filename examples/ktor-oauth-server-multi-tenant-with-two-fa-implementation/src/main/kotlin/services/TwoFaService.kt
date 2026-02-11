package com.bittokazi.example.ktor.services

import com.bittokazi.example.ktor.UserTwoFaSession
import com.bittokazi.example.ktor.models.UserData
import com.bittokazi.example.ktor.models.Users
import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.warrenstrange.googleauth.GoogleAuthenticator
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.principal
import io.ktor.server.response.respond
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.update

class TwoFaService(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration,
    val oauthLoginOptionService: OauthLoginOptionService
) {

    suspend fun generateSecret(call: ApplicationCall) {
        call.principal<JWTPrincipal>()?.let { principal ->
            val user = oauthDatabaseConfiguration.dbQuery(call) {
                Users.selectAll()
                    .where { Users.id eq principal.subject!!.toLong() }
                    .map {
                        UserData(
                            id = it[Users.id].value,
                            email = it[Users.email],
                            firstName = it[Users.firstName],
                            lastName = it[Users.lastName],
                            password = it[Users.hashedPassword],
                            twoFaEnabled = it[Users.twoFaEnabled],
                            twoFaSecret = it[Users.twoFaSecret]
                        )
                    }.singleOrNull()
            }

            when (user) {
                null -> call.respond(HttpStatusCode.NotFound, mapOf("error" to "User not found"))
                else -> {
                    when (user.twoFaEnabled) {
                        false -> {
                            val gAuth = GoogleAuthenticator()
                            val key = gAuth.createCredentials()

                            call.respond(
                                HttpStatusCode.OK,
                                mapOf(
                                    "secret" to key.key
                                )
                            )
                        }
                        else -> call.respond(HttpStatusCode.UnprocessableEntity, mapOf("error" to "2FA already enabled"))
                    }
                }
            }
        }
    }

    suspend fun enable2FA(
        code: Int,
        secret: String,
        call: ApplicationCall
    ) {
        call.principal<JWTPrincipal>()?.let { principal ->
            val user = oauthDatabaseConfiguration.dbQuery(call) {
                Users.selectAll()
                    .where { Users.id eq principal.subject!!.toLong() }
                    .map {
                        UserData(
                            id = it[Users.id].value,
                            email = it[Users.email],
                            firstName = it[Users.firstName],
                            lastName = it[Users.lastName],
                            password = it[Users.hashedPassword],
                            twoFaEnabled = it[Users.twoFaEnabled],
                            twoFaSecret = it[Users.twoFaSecret]
                        )
                    }.singleOrNull()
            }

            when (user) {
                null -> call.respond(HttpStatusCode.NotFound, mapOf("error" to "User not found"))
                else -> {
                    when (user.twoFaEnabled) {
                        false -> {
                            when (validate2FA(code, secret)) {
                                true -> {
                                    oauthDatabaseConfiguration.dbQuery(call) {
                                        Users.update({ Users.id eq user.id }) {
                                            it[Users.twoFaEnabled] = true
                                            it[Users.twoFaSecret] = secret
                                        }
                                    }

                                    call.respond(
                                        status = HttpStatusCode.OK,
                                        message = oauthDatabaseConfiguration.dbQuery(call) {
                                            Users.selectAll()
                                                .where { Users.id eq principal.subject!!.toLong() }
                                                .map {
                                                    UserData(
                                                        id = it[Users.id].value,
                                                        email = it[Users.email],
                                                        firstName = it[Users.firstName],
                                                        lastName = it[Users.lastName],
                                                        password = it[Users.hashedPassword],
                                                        twoFaEnabled = it[Users.twoFaEnabled]
                                                    )
                                                }.singleOrNull()
                                        } as Any
                                    )
                                }
                                else -> call.respond(HttpStatusCode.UnprocessableEntity, mapOf("error" to "Invalid code or secret"))
                            }

                        }
                        else -> call.respond(HttpStatusCode.UnprocessableEntity, mapOf("error" to "2FA already enabled"))
                    }
                }
            }
        }
    }

    suspend fun disable(call: ApplicationCall) {
        call.principal<JWTPrincipal>()?.let { principal ->
            val user = oauthDatabaseConfiguration.dbQuery(call) {
                Users.selectAll()
                    .where { Users.id eq principal.subject!!.toLong() }
                    .map {
                        UserData(
                            id = it[Users.id].value,
                            email = it[Users.email],
                            firstName = it[Users.firstName],
                            lastName = it[Users.lastName],
                            password = it[Users.hashedPassword],
                            twoFaEnabled = it[Users.twoFaEnabled],
                            twoFaSecret = it[Users.twoFaSecret]
                        )
                    }.singleOrNull()
            }

            when (user) {
                null -> call.respond(HttpStatusCode.NotFound, mapOf("error" to "User not found"))
                else -> {
                    when (user.twoFaEnabled) {
                        false -> {
                            call.respond(HttpStatusCode.UnprocessableEntity, mapOf("error" to "2FA not enabled"))
                        }
                        true -> {
                            oauthDatabaseConfiguration.dbQuery(call) {
                                Users.update({ Users.id eq user.id }) {
                                    it[Users.twoFaEnabled] = false
                                    it[Users.twoFaSecret] = ""
                                }
                            }

                            call.respond(
                                status = HttpStatusCode.OK,
                                message = oauthDatabaseConfiguration.dbQuery(call) {
                                    Users.selectAll()
                                        .where { Users.id eq principal.subject!!.toLong() }
                                        .map {
                                            UserData(
                                                id = it[Users.id].value,
                                                email = it[Users.email],
                                                firstName = it[Users.firstName],
                                                lastName = it[Users.lastName],
                                                password = it[Users.hashedPassword],
                                                twoFaEnabled = it[Users.twoFaEnabled]
                                            )
                                        }.singleOrNull()
                                } as Any
                            )
                        }
                    }
                }
            }
        }
    }

    suspend fun verify(code: Int, call: ApplicationCall) {
        val user = oauthDatabaseConfiguration.dbQuery(call) {
            Users.selectAll()
                .where { Users.id eq call.sessions.get<OauthUserSession>()!!.userId.toLong() }
                .map {
                    UserData(
                        id = it[Users.id].value,
                        email = it[Users.email],
                        firstName = it[Users.firstName],
                        lastName = it[Users.lastName],
                        password = it[Users.hashedPassword],
                        twoFaEnabled = it[Users.twoFaEnabled],
                        twoFaSecret = it[Users.twoFaSecret]
                    )
                }.singleOrNull()
        }

        when (user) {
            null -> call.respond(HttpStatusCode.NotFound, mapOf("error" to "User not found"))
            else -> {
                when (user.twoFaEnabled) {
                    true -> {
                        when (validate2FA(code, user.twoFaSecret)) {
                            true -> {
                                val session = UserTwoFaSession(user.id.toString(), user.email)
                                call.sessions.set(session)
                                oauthLoginOptionService.completeLogin(call)
                            }
                            else -> call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Invalid 2FA code"))
                        }
                    }
                    else -> call.respond(HttpStatusCode.UnprocessableEntity, mapOf("error" to "2FA is not enabled"))
                }
            }
        }
    }

    fun validate2FA(code: Int, secret: String?): Boolean {
        val gAuth = GoogleAuthenticator()
        return gAuth.authorize(secret, code)
    }
}
