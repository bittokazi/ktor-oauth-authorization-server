package com.bittokazi.ktor.auth

import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.forwardedheaders.ForwardedHeaders
import io.ktor.server.plugins.forwardedheaders.XForwardedHeaders

fun Application.configureHTTP() {
    install(ForwardedHeaders)
    install(XForwardedHeaders)
}
