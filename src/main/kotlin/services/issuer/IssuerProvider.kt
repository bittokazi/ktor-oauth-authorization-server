package com.bittokazi.ktor.auth.services.issuer

import io.ktor.server.application.ApplicationCall

interface IssuerProvider {
    fun getIssuer(call: ApplicationCall): String
}
