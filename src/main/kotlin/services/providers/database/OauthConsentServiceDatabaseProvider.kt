package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import java.util.*

object OAuthConsents : Table("oauth_consents") {
    val id = uuid("id")
    val userId = varchar("user_id", 255) references OAuthUsers.id
    val clientId = uuid("client_id") references OAuthClients.id
    val scopes = text("scopes")
}

class OauthConsentServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthConsentService {

    override fun grantConsent(userId: String, clientId: UUID, scopes: List<String>) = oauthDatabaseConfiguration.dbQuery {
        OAuthConsents.deleteWhere { (OAuthConsents.userId eq userId).and(OAuthConsents.clientId eq clientId) }
        OAuthConsents.insert {
            it[OAuthConsents.id] = UUID.randomUUID()
            it[OAuthConsents.userId] = userId
            it[OAuthConsents.clientId] = clientId
            it[OAuthConsents.scopes] = scopes.joinToString(",")
        }
        return@dbQuery true
    }

    override fun getConsent(userId: String, clientId: UUID): List<String>? = oauthDatabaseConfiguration.dbQuery {
        OAuthConsents.selectAll().where { (OAuthConsents.userId eq userId) and (OAuthConsents.clientId eq clientId) }
            .map { it[OAuthConsents.scopes].split(",").map(String::trim) }
            .singleOrNull()
    }
}
