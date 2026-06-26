package com.bittokazi.ktor.auth.services.consent

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.session.SessionProvider
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.get

class DefaultConsentProcessService(
    private val oauthClientService: OauthClientService,
    private val oauthConsentService: OauthConsentService,
    private val oauthLoginOptionService: OauthLoginOptionService,
    private val templateCustomizer: TemplateCustomizer?,
    private val sessionProvider: SessionProvider,
) : ConsentProcessService {
    override suspend fun getConsentPage(
        clientId: String?,
        call: ApplicationCall,
    ): Result<TemplateContent?, ConsentFailure> {
        val session = sessionProvider.getSession(call).get<OauthUserSession>()

        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            sessionProvider.getSession(call).clear("OAUTH_USER_SESSION")
            return Result.Failure(ConsentFailure.LoginRequired)
        }

        if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
            return Result.Failure(ConsentFailure.BadRequest)
        }

        if (clientId == null) {
            return Result.Failure(ConsentFailure.BadRequest)
        }

        val client =
            oauthClientService.findByClientId(clientId, call)
                ?: return Result.Failure(ConsentFailure.InvalidClient)

        if (!client.consentRequired) {
            oauthLoginOptionService.completeLogin(call)
            return Result.Success(null)
        }

        val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

        val consents =
            oauthConsentService.getConsent(
                userId = session.userId,
                clientId = client.id,
                call,
            )

        return if (consents == null || !consents.containsAll(client.scopes)) {
            Result.Success(
                TemplateContent(
                    "oauth_templates/consent.hbs",
                    mapOf(
                        "clientName" to client.clientName,
                        "scopes" to client.scopes,
                        "clientId" to client.clientId,
                    ).plus(templateData),
                ),
            )
        } else {
            oauthLoginOptionService.completeLogin(call)
            Result.Success(null)
        }
    }

    override suspend fun processConsent(
        clientId: String?,
        action: String?,
        call: ApplicationCall,
    ): Result<TemplateContent?, ConsentFailure> {
        val session = sessionProvider.getSession(call).get<OauthUserSession>()

        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            sessionProvider.getSession(call).clear("OAUTH_USER_SESSION")
            return Result.Failure(ConsentFailure.LoginRequired)
        }

        if (clientId == null || action == null) {
            return Result.Failure(ConsentFailure.BadRequest)
        }

        val client =
            oauthClientService.findByClientId(clientId, call)
                ?: return Result.Failure(ConsentFailure.InvalidClient)

        val templateData = templateCustomizer?.addExtraData(call) ?: mapOf()

        when (action) {
            "approve" -> {
                oauthConsentService.grantConsent(
                    userId = session.userId,
                    clientId = client.id,
                    scopes = client.scopes,
                    call,
                )
                oauthLoginOptionService.completeLogin(call)
                return Result.Success(null)
            }

            "deny" -> {
                sessionProvider.getSession(call).clear("OAUTH_ORIGINAL_URL")

                return Result.Success(
                    TemplateContent(
                        "oauth_templates/consent_denied.hbs",
                        mapOf(
                            "error" to "access_denied",
                            "error_description" to "You have denied access to the application.",
                        ).plus(templateData),
                    ),
                )
            }

            else -> {
                return Result.Failure(ConsentFailure.InvalidAction)
            }
        }
    }
}

data class TemplateContent(val template: String, val additionalData: Map<String, Any>)
