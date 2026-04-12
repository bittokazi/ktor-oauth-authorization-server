package com.bittokazi.ktor.auth.config

import com.bittokazi.ktor.auth.database.DefaultOauthDatabaseConfiguration
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import io.ktor.server.application.ApplicationCall
import org.jetbrains.exposed.sql.transactions.transaction
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName

class TestOauthDatabaseConfiguration : OauthDatabaseConfiguration {

    private val postgresContainer: PostgreSQLContainer<*> = PostgreSQLContainer(DockerImageName.parse("postgres:15-alpine"))
        .withDatabaseName("test_oauth")
        .withUsername("test")
        .withPassword("test")

    private var oauthDatabaseConfiguration: OauthDatabaseConfiguration

    init {
        postgresContainer.start()

        // Use DefaultOauthDatabaseConfiguration with PostgreSQL container
        oauthDatabaseConfiguration = DefaultOauthDatabaseConfiguration(
            url = postgresContainer.jdbcUrl,
            username = postgresContainer.username,
            password = postgresContainer.password,
            driver = postgresContainer.driverClassName,
            schema = "public"
        )
    }

    fun stop() {
        postgresContainer.stop()
    }

    override fun <T> dbQuery(call: ApplicationCall?, block: () -> T): T {
        return oauthDatabaseConfiguration.dbQuery(call) { block() }
    }
}
