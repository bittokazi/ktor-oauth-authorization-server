package com.bittokazi.ktor.auth

import com.bittokazi.ktor.auth.routes.authorizeRoute
import com.bittokazi.ktor.auth.routes.consentRoute
import com.bittokazi.ktor.auth.routes.loginRoutes
import com.bittokazi.ktor.auth.routes.oidcRoutes
import com.bittokazi.ktor.auth.routes.tokenRoutes
import io.ktor.server.application.*

fun Application.configureRouting(
    defaultLoginRoutes: Boolean = true,
    defaultAuthorizeRoute: Boolean = true,
    defaultOidcRoute: Boolean = true,
    defaultTokenRoute: Boolean = true,
    defaultConsentRoute: Boolean = true
) {
    if (defaultAuthorizeRoute) authorizeRoute()
    if (defaultLoginRoutes) loginRoutes()
    if (defaultOidcRoute) oidcRoutes()
    if (defaultTokenRoute) tokenRoutes()
    if (defaultConsentRoute) consentRoute()
}
