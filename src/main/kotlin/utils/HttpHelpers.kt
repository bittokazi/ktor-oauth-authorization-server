package com.bittokazi.ktor.auth.utils

import com.bittokazi.ktor.auth.services.issuer.DefaultIssuerProvider
import com.bittokazi.ktor.auth.services.issuer.IssuerProvider
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.di.dependencies

var issuerProvider: IssuerProvider? = null

fun Application.configureIssuerProvider() {
    val issuerProviderObject: IssuerProvider? by dependencies
    issuerProvider =
        if (issuerProviderObject == null) {
            DefaultIssuerProvider()
        } else {
            issuerProviderObject
        }
}

fun ApplicationCall.getBaseUrl(): String =
    issuerProvider?.getIssuer(this)
        ?: run {
            issuerProvider = DefaultIssuerProvider()
            issuerProvider!!.getIssuer(this)
        }
