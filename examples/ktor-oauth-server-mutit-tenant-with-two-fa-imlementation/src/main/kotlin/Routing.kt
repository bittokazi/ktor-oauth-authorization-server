package com.bittokazi.example.ktor

import com.bittokazi.example.ktor.routes.clientRoutes
import com.bittokazi.example.ktor.routes.loginRoutes
import com.bittokazi.example.ktor.routes.otpCheckRoute
import com.bittokazi.example.ktor.routes.userRoutes
import io.ktor.server.application.*

fun Application.configureRouting() {

    loginRoutes()
    userRoutes()
    clientRoutes()
    otpCheckRoute()
}
