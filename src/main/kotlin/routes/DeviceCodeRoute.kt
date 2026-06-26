package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.TemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.device.code.DeviceCodeProcessService
import com.bittokazi.ktor.auth.services.device.code.VerificationFailure
import com.bittokazi.ktor.auth.utils.respondMustache
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing

fun Application.deviceCodeRoute() {
    val deviceCodeProcessService: DeviceCodeProcessService by dependencies
    val templateCustomizerFactory: TemplateCustomizerFactory by dependencies

    routing {
        post("/oauth/device_authorization") {
            val params = call.receiveParameters()

            when (
                val result =
                    deviceCodeProcessService.createDeviceAuthorization(
                        clientId = params["client_id"],
                        scope = params["scope"],
                        call = call,
                    )
            ) {
                is Result.Success -> {
                    call.respond(
                        HttpStatusCode.OK,
                        result.outcome,
                    )
                }

                is Result.Failure -> {
                    call.respond(
                        HttpStatusCode.fromValue(result.errorBody.first),
                        result.errorBody.second,
                    )
                }
            }
        }

        get("/oauth/device-verification") {
            when (
                val result =
                    deviceCodeProcessService.getDeviceVerificationPage(call)
            ) {
                is Result.Success -> {
                    call.respondMustache(
                        templateCustomizerFactory,
                        "oauth_templates/device_verification.hbs",
                        result.outcome,
                    )
                }

                is Result.Failure -> {
                    when (val failure = result.errorBody) {
                        VerificationFailure.LoginRequired -> {
                            call.respondRedirect("/oauth/login")
                        }

                        is VerificationFailure.Template -> {
                            call.respondMustache(
                                templateCustomizerFactory,
                                "oauth_templates/device_verification.hbs",
                                failure.data,
                            )
                        }
                    }
                }
            }
        }

        post("/oauth/device-verification") {
            val params = call.receiveParameters()

            when (
                val result =
                    deviceCodeProcessService.verifyDeviceCode(
                        userCode = params["user_code"],
                        call = call,
                    )
            ) {
                is Result.Success -> {
                    call.respondMustache(
                        templateCustomizerFactory,
                        "oauth_templates/device_verification.hbs",
                        result.outcome,
                    )
                }

                is Result.Failure -> {
                    when (val failure = result.errorBody) {
                        VerificationFailure.LoginRequired -> {
                            call.respondRedirect("/oauth/login")
                        }

                        is VerificationFailure.Template -> {
                            call.respondMustache(
                                templateCustomizerFactory,
                                "oauth_templates/device_verification.hbs",
                                failure.data,
                            )
                        }
                    }
                }
            }
        }
    }
}
