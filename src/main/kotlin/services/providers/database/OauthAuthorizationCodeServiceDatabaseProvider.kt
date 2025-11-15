package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.AuthorizationCodeDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.javatime.timestamp
import java.time.Instant
import java.util.*

object OAuthAuthorizationCodes : Table("oauth_authorization_codes") {
    val code = varchar("code", 255)
    val clientId = uuid("client_id") references OAuthClients.id
    val userId = varchar("user_id", 255) references OAuthUsers.id
    val redirectUri = text("redirect_uri")
    val scopes = text("scopes")
    val codeChallenge = varchar("code_challenge", 255).nullable()
    val codeChallengeMethod = varchar("code_challenge_method", 10).nullable()
    val expiresAt = timestamp("expires_at")
    val consumed = bool("consumed").default(false)
}

class OauthAuthorizationCodeServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthAuthorizationCodeService {

    override fun createCode(
        code: String,
        clientId: UUID,
        userId: String,
        redirectUri: String,
        scopes: List<String>,
        expiresAt: Instant,
        challenge: String?,
        challengeMethod: String?,
        call: ApplicationCall
    ): Boolean = oauthDatabaseConfiguration.dbQuery {
        OAuthAuthorizationCodes.insert {
            it[OAuthAuthorizationCodes.code] = code
            it[OAuthAuthorizationCodes.clientId] = clientId
            it[OAuthAuthorizationCodes.userId] = userId
            it[OAuthAuthorizationCodes.redirectUri] = redirectUri
            it[OAuthAuthorizationCodes.scopes] = scopes.joinToString(",")
            it[OAuthAuthorizationCodes.codeChallenge] = challenge
            it[OAuthAuthorizationCodes.codeChallengeMethod] = challengeMethod
            it[OAuthAuthorizationCodes.expiresAt] = expiresAt
        }.insertedCount > 0
    }

    override fun findByCode(code: String, call: ApplicationCall): AuthorizationCodeDTO? = oauthDatabaseConfiguration.dbQuery {
        OAuthAuthorizationCodes
            .selectAll()
            .where { OAuthAuthorizationCodes.code eq code }
            .map {
                AuthorizationCodeDTO(
                    code = it[OAuthAuthorizationCodes.code],
                    clientId = it[OAuthAuthorizationCodes.clientId],
                    userId = it[OAuthAuthorizationCodes.userId],
                    redirectUri = it[OAuthAuthorizationCodes.redirectUri],
                    scopes = it[OAuthAuthorizationCodes.scopes].split(","),
                    codeChallenge = it[OAuthAuthorizationCodes.codeChallenge],
                    codeChallengeMethod = it[OAuthAuthorizationCodes.codeChallengeMethod],
                    expiresAt = it[OAuthAuthorizationCodes.expiresAt],
                    consumed = it[OAuthAuthorizationCodes.consumed]
                )
            }.singleOrNull()
    }

    override fun consumeCode(code: String, call: ApplicationCall): Boolean = oauthDatabaseConfiguration.dbQuery {
        OAuthAuthorizationCodes.update({ OAuthAuthorizationCodes.code eq code }) {
            it[consumed] = true
        } > 0
    }

    override fun logoutAction(userId: String, call: ApplicationCall) {
        oauthDatabaseConfiguration.dbQuery {
            OAuthAuthorizationCodes.deleteWhere { OAuthAuthorizationCodes.userId eq userId }
        }
    }
}
