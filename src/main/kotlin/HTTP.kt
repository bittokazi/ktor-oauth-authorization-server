package com.bittokazi.ktor.auth

import io.ktor.server.application.*
import io.ktor.server.plugins.forwardedheaders.*

fun Application.configureHTTP() {
    install(ForwardedHeaders)
    install(XForwardedHeaders)
}
