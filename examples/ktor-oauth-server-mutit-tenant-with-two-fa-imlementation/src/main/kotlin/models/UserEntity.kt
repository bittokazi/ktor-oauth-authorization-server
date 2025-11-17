package com.bittokazi.example.ktor.models

import kotlinx.serialization.Serializable
import org.jetbrains.exposed.dao.LongEntity
import org.jetbrains.exposed.dao.id.EntityID
import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Column

@Serializable
data class UserData (
    val id: Long? = null,
    val firstName: String = "",
    val lastName: String = "",
    val email: String = "",
    var password: String? = "",
    var twoFaEnabled: Boolean,
    var twoFaSecret: String = "",
)

class User(id: EntityID<Long>): LongEntity(id) {
    var firstName by Users.firstName
    var lastName by Users.lastName
    var email by Users.email
    var password: String? = ""
    var hashedPassword by Users.hashedPassword
    var twoFaEnabled by Users.twoFaEnabled
    var twoFaSecret by Users.twoFaSecret

    fun toData(addPassword: Boolean = false): UserData {
        return UserData(id.value, firstName, lastName, email, if(addPassword) hashedPassword else "", twoFaEnabled, twoFaSecret)
    }
}

object Users : LongIdTable("users") {
    val firstName: Column<String> = varchar("first_name", length = 255)
    val lastName: Column<String> = varchar("last_name", length = 255)
    val email: Column<String> = varchar("email", length = 255)
    val hashedPassword: Column<String> = varchar("password", length = 255)
    val twoFaEnabled: Column<Boolean> = bool("two_fa_enabled")
    val twoFaSecret: Column<String> = varchar("two_fa_secret", length = 255)
}
