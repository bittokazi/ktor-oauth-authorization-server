package com.bittokazi.ktor.auth.utils

import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin

fun ApplicationCall.getBaseUrl(): String {
    val origin = request.origin
    val portPart = when {
        (origin.scheme == "http" && origin.serverPort == 80) -> ""
        (origin.scheme == "https" && origin.serverPort == 443) -> ""
        else -> ":${origin.serverPort}"
    }
    return "${origin.scheme}://${origin.serverHost}$portPart"
}
