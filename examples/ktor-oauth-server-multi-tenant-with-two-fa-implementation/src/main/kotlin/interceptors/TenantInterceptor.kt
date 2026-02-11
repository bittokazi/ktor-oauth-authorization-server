package com.bittokazi.example.ktor.interceptors

import com.bittokazi.example.ktor.TENANT_ATTRIBUTE_KEY
import com.bittokazi.example.ktor.tenant.TenantConfiguration
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*

fun tenantInterceptorPlugin(tenantConfiguration: TenantConfiguration): ApplicationPlugin<Unit> {

    return createApplicationPlugin(name = "tenantInterceptorPlugin") {

        onCall { call ->

            tenantConfiguration.tenants
                .find { it.domain == call.getBaseUrl().replace("http://", "").replace("https://", "") }?.let {
                    call.attributes.put(TENANT_ATTRIBUTE_KEY, it.databaseSchema)
                } ?: run {
                    call.respond(HttpStatusCode.NotFound, mapOf("message" to "No Tenant"))
                }
        }
    }
}
