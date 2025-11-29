package com.bittokazi.example.ktor.services

import com.bittokazi.example.ktor.UserTwoFaSession
import com.bittokazi.example.ktor.models.UserData
import com.bittokazi.example.ktor.models.Users
import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLogoutActionService
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import org.jetbrains.exposed.sql.selectAll

class LoginService(
    override val fallbackAfterLoginRedirectUrl: String,
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
) : OauthLoginOptionService, OauthLogoutActionService {

    override suspend fun isAfterLoginCheckCompleted(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall
    ): Boolean {
        val session = call.sessions.get<UserTwoFaSession>()

        return when (session) {
            null -> {
                val user = oauthDatabaseConfiguration.dbQuery(call) {
                    Users.selectAll()
                        .where { Users.id eq oauthUserSession.userId.toLong() }
                        .map {
                            UserData(
                                id = it[Users.id].value,
                                email = it[Users.email],
                                twoFaEnabled = it[Users.twoFaEnabled]
                            )
                        }.singleOrNull()
                }

                when (user?.twoFaEnabled) {
                    true -> {
                        call.respondRedirect("/otp-check")
                        return false
                    }
                    else -> {
                        val session = UserTwoFaSession(user?.id.toString(), user!!.email)
                        call.sessions.set(session)
                        return true
                    }
                }
            }
            else -> {
                when (session.userId == oauthUserSession.userId) {
                    true -> true
                    else -> {
                        call.sessions.clear("USER_TWO_FA_SESSION")
                        call.respondRedirect("/otp-check")
                        return false
                    }
                }
            }
        }
    }

    override suspend fun onSuccessfulLogin(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall
    ) {
        call.sessions.clear("USER_TWO_FA_SESSION")
    }

    override suspend fun afterLogoutAction(userId: String?, call: ApplicationCall) {
        call.sessions.clear("USER_TWO_FA_SESSION")
        call.respondRedirect("/home")
    }
}
