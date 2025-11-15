package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.javatime.timestamp
import java.util.*

object OAuthClients : Table("oauth_clients") {
    val id = uuid("id")
    val clientId = varchar("client_id", 100).uniqueIndex()
    val clientSecret = varchar("client_secret", 255).nullable()
    val clientName = varchar("client_name", 255)
    val clientType = varchar("client_type", 50)
    val redirectUris = text("redirect_uris") // comma-separated
    val scopes = text("scopes")
    val grantTypes = text("grant_types")
    val tokenEndpointAuthMethod = varchar("token_endpoint_auth_method", 100)
    val createdAt = timestamp("created_at")
    val accessTokenValidity = long("access_token_validity")
    val refreshTokenValidity = long("refresh_token_validity")
    val isDefault = bool("is_default")
    val consentRequired = bool("consent_required")
}

class OauthClientServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthClientService {

    fun createClient(
        clientId: String,
        clientSecret: String?,
        name: String,
        type: String,
        redirectUris: List<String>,
        scopes: List<String>,
        grantTypes: List<String>,
        accessTokenValidity: Long = 300,
        refreshTokenValidity: Long = 7200,
        consentRequired: Boolean = true
    ): OAuthClientDTO = oauthDatabaseConfiguration.dbQuery {
        val id = UUID.randomUUID()
        OAuthClients.insert {
            it[OAuthClients.id] = id
            it[OAuthClients.clientId] = clientId
            it[OAuthClients.clientSecret] = clientSecret
            it[OAuthClients.clientName] = name
            it[OAuthClients.clientType] = type
            it[OAuthClients.redirectUris] = redirectUris.joinToString(",")
            it[OAuthClients.scopes] = scopes.joinToString(",")
            it[OAuthClients.grantTypes] = grantTypes.joinToString(",")
            it[OAuthClients.tokenEndpointAuthMethod] = "client_secret_post"
            it[OAuthClients.accessTokenValidity] = accessTokenValidity
            it[OAuthClients.refreshTokenValidity] = refreshTokenValidity
            it[OAuthClients.isDefault] = false
            it[OAuthClients.consentRequired] = consentRequired
        }
        OAuthClientDTO(id, clientId, name, type, redirectUris, scopes, grantTypes)
    }

    override fun findByClientId(clientId: String, call: ApplicationCall): OAuthClientDTO? = oauthDatabaseConfiguration.dbQuery {
        OAuthClients.selectAll().where { OAuthClients.clientId eq clientId }
            .map {
                OAuthClientDTO(
                    it[OAuthClients.id],
                    it[OAuthClients.clientId],
                    it[OAuthClients.clientName],
                    it[OAuthClients.clientType],
                    it[OAuthClients.redirectUris].split(","),
                    it[OAuthClients.scopes].split(","),
                    it[OAuthClients.grantTypes].split(","),
                    it[OAuthClients.clientSecret],
                    accessTokenValidity = it[OAuthClients.accessTokenValidity],
                    refreshTokenValidity = it[OAuthClients.refreshTokenValidity],
                    isDefault = it[OAuthClients.isDefault],
                    consentRequired = it[OAuthClients.consentRequired]
                )
            }.singleOrNull()
    }

    override fun findDefaultClient(call: ApplicationCall): OAuthClientDTO?  = oauthDatabaseConfiguration.dbQuery {
        OAuthClients.selectAll().where { OAuthClients.isDefault eq true }
            .map {
                OAuthClientDTO(
                    it[OAuthClients.id],
                    it[OAuthClients.clientId],
                    it[OAuthClients.clientName],
                    it[OAuthClients.clientType],
                    it[OAuthClients.redirectUris].split(","),
                    it[OAuthClients.scopes].split(","),
                    it[OAuthClients.grantTypes].split(","),
                    it[OAuthClients.clientSecret],
                    accessTokenValidity = it[OAuthClients.accessTokenValidity],
                    refreshTokenValidity = it[OAuthClients.refreshTokenValidity],
                    isDefault = it[OAuthClients.isDefault],
                    consentRequired = it[OAuthClients.consentRequired]
                )
            }.singleOrNull()
    }

    fun updateClient(
        clientId: String,
        name: String,
        type: String,
        redirectUris: List<String>,
        scopes: List<String>,
        grantTypes: List<String>,
        accessTokenValidity: Long = 300,
        refreshTokenValidity: Long = 7200,
        consentRequired: Boolean = true
    ): Boolean = oauthDatabaseConfiguration.dbQuery {
        OAuthClients.update({ OAuthClients.clientId eq clientId }) {
            it[OAuthClients.clientName] = name
            it[OAuthClients.clientType] = type
            it[OAuthClients.redirectUris] = redirectUris.joinToString(",")
            it[OAuthClients.scopes] = scopes.joinToString(",")
            it[OAuthClients.grantTypes] = grantTypes.joinToString(",")
            it[tokenEndpointAuthMethod] = "client_secret_post"
            it[OAuthClients.accessTokenValidity] = accessTokenValidity
            it[OAuthClients.refreshTokenValidity] = refreshTokenValidity
            it[OAuthClients.consentRequired] = consentRequired
        } > 0
    }

    fun updateClientSecret(
        clientId: String,
        clientSecret: String?,
    ): Boolean = oauthDatabaseConfiguration.dbQuery {
        OAuthClients.update({ OAuthClients.clientId eq clientId }) {
            it[OAuthClients.clientSecret] = clientSecret
        } > 0
    }

    fun <T> runQuery(query: (OAuthClients) -> T): T {
        return oauthDatabaseConfiguration.dbQuery {
            query(OAuthClients)
        }
    }
}
