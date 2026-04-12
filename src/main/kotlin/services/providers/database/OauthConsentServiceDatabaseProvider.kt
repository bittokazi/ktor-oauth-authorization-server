package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import java.util.*
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.toKotlinUuid

@OptIn(ExperimentalUuidApi::class)
object OAuthConsents : Table("oauth_consents") {
    val id = uuid("id")
    val userId = varchar("user_id", 255)
    val clientId = uuid("client_id")
    val scopes = text("scopes")
}

@OptIn(ExperimentalUuidApi::class)
class OauthConsentServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthConsentService {

    override fun grantConsent(
        userId: String,
        clientId: UUID,
        scopes: List<String>,
        call: ApplicationCall
    ) = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthConsents.deleteWhere {
            (OAuthConsents.userId eq userId)
                .and(OAuthConsents.clientId eq clientId.toKotlinUuid())
        }

        OAuthConsents.insert {
            it[OAuthConsents.id] = UUID.randomUUID().toKotlinUuid()
            it[OAuthConsents.userId] = userId
            it[OAuthConsents.clientId] = clientId.toKotlinUuid()
            it[OAuthConsents.scopes] = scopes.joinToString(",")
        }
        return@dbQuery true
    }

    override fun getConsent(
        userId: String,
        clientId: UUID,
        call: ApplicationCall
    ): List<String>? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthConsents
            .selectAll()
            .where { (OAuthConsents.userId eq userId) and (OAuthConsents.clientId eq clientId.toKotlinUuid()) }
            .map { it[OAuthConsents.scopes].split(",").map(String::trim) }
            .singleOrNull()
    }
}
