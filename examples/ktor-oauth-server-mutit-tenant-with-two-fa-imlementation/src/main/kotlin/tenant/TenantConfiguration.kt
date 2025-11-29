package com.bittokazi.example.ktor.tenant

import io.ktor.server.plugins.di.annotations.Property
import kotlinx.serialization.Serializable

@Serializable
data class TenantConfiguration(
    @Property("tenants") val tenants: List<Tenant>,
)

@Serializable
data class Tenant(
    val name: String,
    val domain: String,
    val databaseSchema: String
)
