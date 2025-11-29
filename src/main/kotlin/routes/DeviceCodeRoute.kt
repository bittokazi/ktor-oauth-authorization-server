package com.bittokazi.ktor.auth.routes

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.utils.Utils
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.mustache.MustacheContent
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.request.receiveParameters
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.get
import io.ktor.server.sessions.sessions
import java.time.Instant
import java.util.UUID

fun Application.deviceCodeRoute() {

    val oauthClientService: OauthClientService by dependencies
    val oauthLoginOptionService: OauthLoginOptionService by dependencies
    val oauthDeviceCodeService: OauthDeviceCodeService by dependencies
    val templateCustomizer: TemplateCustomizer? by dependencies

    routing {
        post("/oauth/device_authorization") {
            val params = call.receiveParameters()
            val clientId = params["client_id"]
                ?: return@post call.respond(
                    HttpStatusCode.BadRequest,
                    mutableMapOf("error" to "Missing client_id")
                )

            val scope = params["scope"]
                ?: return@post call.respond(
                    HttpStatusCode.BadRequest,
                    mutableMapOf("error" to "Missing scope")
                )

            val client = oauthClientService.findByClientId(clientId, call)
                ?: return@post call.respond(
                    HttpStatusCode.BadRequest,
                    mutableMapOf("message" to "Invalid client_id")
                )

            if (!client.scopes.containsAll(scope.split(" ").toList())) {
                return@post call.respond(
                    HttpStatusCode.BadRequest,
                    mutableMapOf("message" to "Invalid scopes")
                )
            }

            val userCode = Utils.generateUserCode()
            val deviceCode = UUID.randomUUID().toString()
            val expiresAt = Instant.now().plusSeconds(1200)

            oauthDeviceCodeService.createCode(
                client.id,
                scope.split(" "),
                expiresAt,
                call,
                deviceCode,
                userCode
            )

            call.respond(
                status = HttpStatusCode.OK,
                message = mapOf(
                    "device_code" to deviceCode,
                    "user_code" to userCode,
                    "verification_uri" to "${call.getBaseUrl()}/oauth/device-verification",
                    "verification_uri_complete" to "${call.getBaseUrl()}/oauth/device-verification?user_code=${userCode}",
                    "expires_in" to 1200,
                    "interval" to 5
                )
            )
        }

        get("/oauth/device-verification") {
            val userCode = call.request.queryParameters["user_code"]

            // Check user session
            val session = call.sessions.get<OauthUserSession>()
            if (session == null || session.expiresAt < System.currentTimeMillis()) {
                // No session/expired: save original request so we can come back later
                call.sessions.clear("OAUTH_USER_SESSION")
                val authRequestUrl = call.request.uri
                call.sessions.set("OAUTH_ORIGINAL_URL", authRequestUrl)
                call.respondRedirect("/oauth/login")
                return@get
            }

            if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
                return@get
            }

            val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()
            call.respond(MustacheContent("oauth_templates/device_verification.hbs", mapOf(
                "result" to false,
                "userCode" to userCode
            ).plus(templateData)))
        }

        post("/oauth/device-verification") {
            val params = call.receiveParameters()

            // Check user session
            val session = call.sessions.get<OauthUserSession>()
            if (session == null || session.expiresAt < System.currentTimeMillis()) {
                // No session/expired: save original request so we can come back later
                call.sessions.clear("OAUTH_USER_SESSION")
                val authRequestUrl = call.request.uri
                call.sessions.set("OAUTH_ORIGINAL_URL", authRequestUrl)
                call.respondRedirect("/oauth/login")
                return@post
            }

            if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
                return@post
            }

            val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

            val userCode = params["user_code"]
                ?: return@post call.respond(MustacheContent("oauth_templates/device_verification.hbs", mapOf(
                    "result" to true,
                    "isInvalid" to true
                ).plus(templateData)))

            val oauthDeviceCodeEntity =
                oauthDeviceCodeService.findByUserCode(userCode, call) ?: return@post call.respond(
                    MustacheContent(
                        "oauth_templates/device_verification.hbs", mapOf(
                            "result" to true,
                            "isInvalid" to true
                        ).plus(templateData)
                    )
                )

            oauthDeviceCodeService.authorizeDevice(oauthDeviceCodeEntity.deviceCode, session.userId, call)

            return@post call.respond(MustacheContent("oauth_templates/device_verification.hbs", mapOf(
                "result" to true,
                "isSuccess" to true
            ).plus(templateData)))
        }
    }
}
