package com.bittokazi.ktor.auth

import io.ktor.server.application.*

fun Application.configureOauth2AuthorizationServer(
    configureSerialization: Boolean = false,
    defaultLoginRoutes: Boolean = true,
    defaultAuthorizeRoute: Boolean = true,
    defaultOidcRoute: Boolean = true,
    defaultTokenRoute: Boolean = true,
    defaultConsentRoute: Boolean = true
) {
    if (configureSerialization) {
        configureSerialization()
    }
    configureTemplating()
    configureSecurity()
    configureRouting(
        defaultLoginRoutes = defaultLoginRoutes,
        defaultAuthorizeRoute = defaultAuthorizeRoute,
        defaultOidcRoute = defaultOidcRoute,
        defaultTokenRoute = defaultTokenRoute,
        defaultConsentRoute = defaultConsentRoute
    )

}
