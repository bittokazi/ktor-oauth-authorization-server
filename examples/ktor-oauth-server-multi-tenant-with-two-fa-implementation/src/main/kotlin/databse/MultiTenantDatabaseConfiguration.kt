package com.bittokazi.example.ktor.databse

import com.bittokazi.example.ktor.TENANT_ATTRIBUTE_KEY
import com.bittokazi.example.ktor.tenant.TenantConfiguration
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.di.annotations.Property
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.transactions.transaction
import javax.sql.DataSource
import kotlin.collections.set

class MultiTenantDatabaseConfiguration(
    @Property("database.url") val url: String,
    @Property("database.username") val username: String,
    @Property("database.password") val password: String,
    @Property("database.driver") val driver: String,
    tenantConfiguration: TenantConfiguration
): OauthDatabaseConfiguration {

    private val dataSources: MutableMap<String, HikariDataSource> = mutableMapOf()

    var databases: MutableMap<String, Database> = mutableMapOf()

    init {
        tenantConfiguration.tenants.forEach {
            dataSources[it.databaseSchema] = init(url, username, password, it.databaseSchema, driver)
            databases[it.databaseSchema] = Database.connect(dataSources[it.databaseSchema]!!)
            setUpDatabase(dataSources[it.databaseSchema]!!, it.databaseSchema)
        }
    }

    private fun init(
        url: String,
        username: String,
        password: String,
        schema: String,
        driver: String
    ): HikariDataSource {
        val config: HikariConfig = hikariConfigGenerator(url, username, password, schema, driver)
        return HikariDataSource(config)
    }

    private fun hikariConfigGenerator(
        url: String,
        username: String,
        password: String,
        schema: String,
        driver: String
    ): HikariConfig {
        val config = HikariConfig()
        config.jdbcUrl = url
        config.username = username
        config.password = password
        config.schema = schema
        config.driverClassName = driver
        config.addDataSourceProperty("cachePrepStmts", "true")
        config.addDataSourceProperty("prepStmtCacheSize", "250")
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048")
        return config
    }

    fun setUpDatabase(dataSource: DataSource, schema: String) {
        Flyway.configure().dataSource(dataSource).defaultSchema(schema)
            .locations("classpath:oauth_db", "classpath:db")
            .load()
            .migrate()
    }

    override fun <T> dbQuery(call: ApplicationCall?, block: () -> T): T {
        return transaction(databases[call!!.attributes[TENANT_ATTRIBUTE_KEY]]) { block() }
    }
}
