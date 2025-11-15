package com.bittokazi.ktor.auth.database

import io.ktor.server.application.ApplicationCall

interface OauthDatabaseConfiguration {
    fun <T> dbQuery(call: ApplicationCall? = null, block: () -> T): T
}
