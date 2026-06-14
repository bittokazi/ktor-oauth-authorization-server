package com.bittokazi.ktor.auth.services.issuer

import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin

class DefaultIssuerProvider : IssuerProvider {
    override fun getIssuer(call: ApplicationCall): String {
        val origin = call.request.origin
        val portPart =
            when {
                (origin.scheme == "http" && origin.serverPort == 80) -> ""
                (origin.scheme == "https" && origin.serverPort == 443) -> ""
                else -> ":${origin.serverPort}"
            }
        return "${origin.scheme}://${origin.serverHost}$portPart"
    }
}
