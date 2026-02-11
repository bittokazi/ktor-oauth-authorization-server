package com.bittokazi.example.ktor.routes

import com.bittokazi.example.ktor.applicationHttpClient
import com.bittokazi.ktor.auth.domains.token.OauthTokenResponse
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.client.call.body
import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

fun Application.loginRoutes() {

    val oauthClientService: OauthClientService by dependencies

    routing {

        get("/login") {
            val client = oauthClientService.findDefaultClient(call)
            call.respondRedirect("/oauth/authorize?client_id=${client?.clientId}&response_type=code&scope=${client?.scopes?.joinToString("+")}&redirect_uri=${call.getBaseUrl()}/oauth/callback")
        }

        get("/oauth/callback") {

            val code = call.parameters["code"]
            if (code == null) {
                call.respond(HttpStatusCode.BadRequest, mutableMapOf(
                    "error" to "Missing code"
                ))
                return@get
            }

            val client = oauthClientService.findDefaultClient(call)

            val tokenResponse: HttpResponse = applicationHttpClient.submitForm(
                url = "${call.getBaseUrl()}/oauth/token",
                formParameters = Parameters.build {
                    append("grant_type", "authorization_code")
                    append("code", code)
                    append("redirect_uri", "${call.getBaseUrl()}/oauth/callback")
                    append("client_id", client?.clientId ?: "")
                    append("client_secret", client?.clientSecret ?: "")
                }
            )

            if (tokenResponse.status == HttpStatusCode.OK) {
                call.respond(status = tokenResponse.status, tokenResponse.body<OauthTokenResponse>())
            } else {
                call.respond(status = tokenResponse.status, tokenResponse.body<String>())
            }
        }
    }
}
