package com.bittokazi.example.ktor.services

import com.bittokazi.example.ktor.UserTwoFaSession
import com.bittokazi.example.ktor.models.UserData
import com.bittokazi.example.ktor.models.Users
import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.AuthenticatedUserSession
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLogoutActionService
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respondRedirect
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.selectAll

data class AuthenticatedUserSessionImpl(
    override val loginCompleted: Boolean,
    val action: suspend () -> Unit
) : AuthenticatedUserSession

class LoginService(
    override val fallbackAfterLoginRedirectUrl: String,
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
) : OauthLoginOptionService<AuthenticatedUserSessionImpl>, OauthLogoutActionService {

    override suspend fun isAfterLoginCheckCompleted(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall
    ): AuthenticatedUserSessionImpl {
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
                        AuthenticatedUserSessionImpl(
                            false
                        ) {
                            call.respondRedirect("/otp-check")
                        }
                    }
                    else -> {
                        AuthenticatedUserSessionImpl(true) {
                            val session = UserTwoFaSession(user?.id.toString(), user!!.email)
                            call.sessions.set(session)
                        }
                    }
                }
            }
            else -> {
                when (session.userId == oauthUserSession.userId) {
                    true -> AuthenticatedUserSessionImpl(true) {  }
                    else -> {
                        AuthenticatedUserSessionImpl(false) {
                            call.sessions.clear("USER_TWO_FA_SESSION")
                            call.respondRedirect("/otp-check")
                        }
                    }
                }
            }
        }
    }

    override suspend fun onGoingLogin(
        oauthUserSession: OauthUserSession,
        payload: AuthenticatedUserSessionImpl,
        call: ApplicationCall
    ) {
        payload.action()
    }

    override suspend fun onSuccessfulLogin(
        oauthUserSession: OauthUserSession,
        call: ApplicationCall
    ) {
        call.sessions.clear("USER_TWO_FA_SESSION")
    }

    override suspend fun afterLogoutAction(userId: String?, clientId: String?, call: ApplicationCall) {
        call.sessions.clear("USER_TWO_FA_SESSION")
        call.respondRedirect("/home")
    }
}
