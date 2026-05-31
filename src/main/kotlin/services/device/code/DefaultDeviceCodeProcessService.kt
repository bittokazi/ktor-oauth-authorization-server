package com.bittokazi.ktor.auth.services.device.code

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.session.SessionProvider
import com.bittokazi.ktor.auth.utils.Utils
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.uri
import io.ktor.server.sessions.get
import java.time.Instant
import java.util.UUID

class DefaultDeviceCodeProcessService(
    private val oauthClientService: OauthClientService,
    private val oauthLoginOptionService: OauthLoginOptionService,
    private val oauthDeviceCodeService: OauthDeviceCodeService,
    private val templateCustomizer: TemplateCustomizer?,
    private val sessionProvider: SessionProvider,
) : DeviceCodeProcessService {
    override suspend fun createDeviceAuthorization(
        clientId: String?,
        scope: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any>, Pair<Int, Any>> {
        if (clientId == null) {
            return Result.Failure(
                Pair(
                    400,
                    mutableMapOf("error" to "Missing client_id"),
                ),
            )
        }

        if (scope == null) {
            return Result.Failure(
                Pair(
                    400,
                    mutableMapOf("error" to "Missing scope"),
                ),
            )
        }

        val client =
            oauthClientService.findByClientId(clientId, call)
                ?: return Result.Failure(
                    Pair(
                        400,
                        mutableMapOf("message" to "Invalid client_id"),
                    ),
                )

        if (!client.scopes.containsAll(scope.split(" ").toList())) {
            return Result.Failure(
                Pair(
                    400,
                    mutableMapOf("message" to "Invalid scopes"),
                ),
            )
        }

        if (!client.grantTypes.contains("urn:ietf:params:oauth:grant-type:device_code")) {
            return Result.Failure(
                Pair(
                    401,
                    mutableMapOf("message" to "Client is not authorized for device code"),
                ),
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
            userCode,
        )

        return Result.Success(
            mapOf(
                "device_code" to deviceCode,
                "user_code" to userCode,
                "verification_uri" to "${call.getBaseUrl()}/oauth/device-verification",
                "verification_uri_complete" to "${call.getBaseUrl()}/oauth/device-verification?user_code=$userCode",
                "expires_in" to 1200,
                "interval" to 5,
            ),
        )
    }

    override suspend fun getDeviceVerificationPage(call: ApplicationCall): Result<Map<String, Any?>, VerificationFailure> {
        val userCode = call.request.queryParameters["user_code"]

        val session = sessionProvider.getSession(call).get<OauthUserSession>()

        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            sessionProvider.getSession(call).clear("OAUTH_USER_SESSION")

            val authRequestUrl = call.request.uri
            sessionProvider.getSession(call).set("OAUTH_ORIGINAL_URL", authRequestUrl)

            return Result.Failure(VerificationFailure.LoginRequired)
        }

        if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
            return Result.Failure(
                VerificationFailure.Template(emptyMap()),
            )
        }

        val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

        return Result.Success(
            mapOf(
                "result" to false,
                "userCode" to userCode,
            ).plus(templateData),
        )
    }

    override suspend fun verifyDeviceCode(
        userCode: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any>, VerificationFailure> {
        val session = sessionProvider.getSession(call).get<OauthUserSession>()

        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            sessionProvider.getSession(call).clear("OAUTH_USER_SESSION")

            val authRequestUrl = call.request.uri
            sessionProvider.getSession(call).set("OAUTH_ORIGINAL_URL", authRequestUrl)

            return Result.Failure(VerificationFailure.LoginRequired)
        }

        if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
            return Result.Failure(
                VerificationFailure.Template(emptyMap()),
            )
        }

        val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

        if (userCode == null) {
            return Result.Failure(
                VerificationFailure.Template(
                    mapOf(
                        "result" to true,
                        "isInvalid" to true,
                    ).plus(templateData),
                ),
            )
        }

        val oauthDeviceCodeEntity =
            oauthDeviceCodeService.findByUserCode(userCode, call)
                ?: return Result.Failure(
                    VerificationFailure.Template(
                        mapOf(
                            "result" to true,
                            "isInvalid" to true,
                        ).plus(templateData),
                    ),
                )

        oauthDeviceCodeService.authorizeDevice(
            oauthDeviceCodeEntity.deviceCode,
            session.userId,
            call,
        )

        return Result.Success(
            mapOf(
                "result" to true,
                "isSuccess" to true,
            ).plus(templateData),
        )
    }
}
