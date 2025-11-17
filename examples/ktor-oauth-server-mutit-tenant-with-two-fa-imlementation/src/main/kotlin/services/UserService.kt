package com.bittokazi.example.ktor.services

import com.bittokazi.example.ktor.models.UserData
import com.bittokazi.example.ktor.models.Users
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.sql.selectAll

class UserService(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthUserService {

    override fun findByUsername(
        username: String,
        call: ApplicationCall
    ): OAuthUserDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        Users.selectAll()
            .where { Users.email eq username }
            .map {
                OAuthUserDTO(
                    id = it[Users.id].toString(),
                    username = it[Users.email],
                    email = it[Users.email],
                    firstName = it[Users.firstName],
                    lastName = it[Users.lastName],
                    isActive = true,
                    passwordHash = it[Users.hashedPassword]
                )
            }.singleOrNull()
    }

    override fun findById(
        id: String,
        call: ApplicationCall
    ): OAuthUserDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        Users.selectAll()
            .where { Users.id eq id.toLong() }
            .map {
                OAuthUserDTO(
                    id = it[Users.id].toString(),
                    username = it[Users.email],
                    email = it[Users.email],
                    firstName = it[Users.firstName],
                    lastName = it[Users.lastName],
                    isActive = true,
                    passwordHash = it[Users.hashedPassword]
                )
            }.singleOrNull()
    }

    fun getUserById(id: String, call: ApplicationCall) = oauthDatabaseConfiguration.dbQuery(call) {
        Users.selectAll()
            .where { Users.id eq id.toLong() }
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
}
