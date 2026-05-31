package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.consent.ConsentFailure
import com.bittokazi.ktor.auth.services.consent.ConsentProcessService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.mustache.MustacheContent
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing

fun Application.consentRoute() {
    val consentProcessService: ConsentProcessService by dependencies
    val oauthLoginOptionService: OauthLoginOptionService by dependencies

    routing {
        get("/oauth/consent") {
            val clientId = call.request.queryParameters["client_id"]

            when (
                val result =
                    consentProcessService.getConsentPage(
                        clientId,
                        call,
                    )
            ) {
                is Result.Success -> {
                    when (val outcome = result.outcome) {
                        is MustacheContent -> call.respond(outcome)
                        else -> oauthLoginOptionService.completeLogin(call)
                    }
                }

                is Result.Failure -> {
                    when (result.errorBody) {
                        ConsentFailure.LoginRequired -> call.respondRedirect("/oauth/login")
                        ConsentFailure.BadRequest -> call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid request"))
                        ConsentFailure.InvalidAction -> call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Invalid action"))
                        ConsentFailure.InvalidClient ->
                            call.respond(
                                HttpStatusCode.BadRequest,
                                mutableMapOf("message" to "Invalid client_id"),
                            )
                        is ConsentFailure.Template -> call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Template not found"))
                    }
                }
            }
        }

        post("/oauth/consent") {
            val params = call.receiveParameters()

            val clientId =
                call.request.queryParameters["client_id"] ?: params["client_id"]

            val action = params["action"]

            when (
                val result =
                    consentProcessService.processConsent(
                        clientId,
                        action,
                        call,
                    )
            ) {
                is Result.Success -> {
                    when (val outcome = result.outcome) {
                        is MustacheContent -> call.respond(outcome)
                        else -> oauthLoginOptionService.completeLogin(call)
                    }
                }

                is Result.Failure -> {
                    when (result.errorBody) {
                        ConsentFailure.LoginRequired -> call.respondRedirect("/oauth/login")
                        ConsentFailure.BadRequest -> call.respond(HttpStatusCode.BadRequest, mutableMapOf("message" to "Invalid request"))
                        ConsentFailure.InvalidAction -> call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Invalid action"))
                        ConsentFailure.InvalidClient ->
                            call.respond(
                                HttpStatusCode.BadRequest,
                                mutableMapOf("message" to "Invalid client_id"),
                            )
                        is ConsentFailure.Template -> call.respond(HttpStatusCode.BadRequest, mapOf("message" to "Template not found"))
                    }
                }
            }
        }
    }
}
