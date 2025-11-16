package com.bittokazi.ktor.auth.services.providers.database

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.javatime.timestamp
import java.util.*

object OAuthUsers : Table("oauth_users") {
    val id = varchar("id", 255)
    val username = varchar("username", 150)
    val passwordHash = varchar("password_hash", 255)
    val email = varchar("email", 255).nullable()
    val firstName = varchar("first_name", 255).nullable()
    val lastName = varchar("last_name", 255).nullable()
    val isActive = bool("is_active").default(true)
    val createdAt = timestamp("created_at")
    val updatedAt = timestamp("updated_at")
}

class OauthUserServiceDatabaseProvider(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthUserService {

    fun createUser(username: String, password: String, email: String?, firstName: String?, lastName: String?, call: ApplicationCall): OAuthUserDTO =
        oauthDatabaseConfiguration.dbQuery(call) {
            val id = UUID.randomUUID().toString()
            OAuthUsers.insert {
                it[OAuthUsers.id] = id
                it[OAuthUsers.username] = username
                it[OAuthUsers.passwordHash] = BCrypt.withDefaults().hashToString(12, password.toCharArray())
                it[OAuthUsers.email] = email
                it[OAuthUsers.firstName] = firstName
                it[OAuthUsers.lastName] = lastName
            }
            OAuthUserDTO(id, username, email, firstName, lastName, true)
        }

    override fun findByUsername(username: String, call: ApplicationCall): OAuthUserDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthUsers.selectAll().where { OAuthUsers.username eq username }
            .map {
                OAuthUserDTO(
                    it[OAuthUsers.id],
                    it[OAuthUsers.username],
                    it[OAuthUsers.email],
                    it[OAuthUsers.firstName],
                    it[OAuthUsers.lastName],
                    it[OAuthUsers.isActive],
                    it[OAuthUsers.passwordHash]
                )
            }.singleOrNull()
    }

    override fun findById(id: String, call: ApplicationCall): OAuthUserDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        OAuthUsers.selectAll().where { OAuthUsers.id eq id }
            .map {
                OAuthUserDTO(
                    it[OAuthUsers.id],
                    it[OAuthUsers.username],
                    it[OAuthUsers.email],
                    it[OAuthUsers.firstName],
                    it[OAuthUsers.lastName],
                    it[OAuthUsers.isActive],
                    it[OAuthUsers.passwordHash]
                )
            }.singleOrNull()
    }

    fun updateUser(userId: String, username: String, email: String?, firstName: String?, lastName: String?, call: ApplicationCall): Boolean =
        oauthDatabaseConfiguration.dbQuery(call) {
            OAuthUsers.update({ OAuthUsers.id eq userId }) {
                it[OAuthUsers.username] = username
                it[OAuthUsers.email] = email
                it[OAuthUsers.firstName] = firstName
                it[OAuthUsers.lastName] = lastName
            } > 0
        }

    fun updateUserPassword(userId: String, password: String, call: ApplicationCall): Boolean =
        oauthDatabaseConfiguration.dbQuery(call) {
            OAuthUsers.update({ OAuthUsers.id eq userId }) {
                it[OAuthUsers.passwordHash] = BCrypt.withDefaults().hashToString(12, password.toCharArray())
            } > 0
        }

    fun <T> runQuery(call: ApplicationCall, query: (OAuthUsers) -> T): T {
        return oauthDatabaseConfiguration.dbQuery(call) {
            query(OAuthUsers)
        }
    }
}
