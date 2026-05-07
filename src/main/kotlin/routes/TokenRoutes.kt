package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.token.TokenGeneratorFactory
import com.bittokazi.ktor.auth.services.token.TokenIntrospectService
import com.bittokazi.ktor.auth.services.token.TokenRevokeService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.util.toMap

fun Application.tokenRoutes() {
    val tokenGeneratorFactory: TokenGeneratorFactory by dependencies
    val tokenIntrospectService: TokenIntrospectService by dependencies
    val tokenRevokeService: TokenRevokeService by dependencies

    routing {
        route("/oauth") {
            post("/token") {
                val params = call.receiveParameters()
                val grantType = params["grant_type"]

                val generator =
                    tokenGeneratorFactory.getGenerator(grantType)
                        ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Unsupported grant type"))

                val paramsMap = params.toMap().mapValues { it.value.firstOrNull() }

                // Check if there's an error with a custom status code
                when (val result = generator.generateTokens(paramsMap, call)) {
                    is Result.Success<*, *> ->
                        call.respond(
                            HttpStatusCode.OK,
                            result.outcome as Map<*, *>,
                        )

                    is Result.Failure<*, *> -> {
                        val statusCode =
                            (result.errorBody as? Map<*, *>)?.get("statusCode") as? HttpStatusCode
                                ?: HttpStatusCode.InternalServerError
                        val responseMap = (result.errorBody as? Map<*, *>)?.filterKeys { it != "statusCode" }

                        call.respond(statusCode, responseMap as Map<*, *>)
                    }
                }
            }

            post("/introspect") {
                val params = call.receiveParameters()
                val token =
                    params["token"]
                        ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing token"))

                val clientId =
                    params["client_id"]
                        ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_id"))

                val clientSecret =
                    params["client_secret"]
                        ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing client_secret"))

                when (val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)) {
                    is Result.Success<*, *> ->
                        call.respond(
                            HttpStatusCode.OK,
                            result.outcome as Map<*, *>,
                        )

                    is Result.Failure<*, *> -> {
                        val statusCode =
                            (result.errorBody as? Map<*, *>)?.get("statusCode") as? HttpStatusCode
                                ?: HttpStatusCode.InternalServerError
                        val responseMap = (result.errorBody as? Map<*, *>)?.filterKeys { it != "statusCode" }

                        call.respond(statusCode, responseMap as Map<*, *>)
                    }
                }
            }

            post("/revoke") {
                val params = call.receiveParameters()
                val token =
                    params["token"]
                        ?: return@post call.respond(HttpStatusCode.BadRequest, mutableMapOf("error" to "Missing token"))

                when (val result = tokenRevokeService.revoke(token, call)) {
                    is Result.Success<*, *> ->
                        call.respond(
                            HttpStatusCode.OK,
                            result.outcome as Map<*, *>,
                        )

                    is Result.Failure<*, *> -> {
                        val statusCode =
                            (result.errorBody as? Map<*, *>)?.get("statusCode") as? HttpStatusCode
                                ?: HttpStatusCode.InternalServerError
                        val responseMap = (result.errorBody as? Map<*, *>)?.filterKeys { it != "statusCode" }

                        call.respond(statusCode, responseMap as Map<*, *>)
                    }
                }
            }
        }
    }
}
