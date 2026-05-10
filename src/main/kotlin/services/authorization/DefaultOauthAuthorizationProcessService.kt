package com.bittokazi.ktor.auth.services.authorization

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.session.SessionProvider
import com.bittokazi.ktor.auth.utils.getBaseUrl
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.get
import io.ktor.server.sessions.set
import java.time.Instant
import java.util.UUID

/**
 * Default implementation of OauthAuthorizationService
 * Handles the OAuth 2.0 Authorization Code flow
 */
class DefaultOauthAuthorizationProcessService(
    private val oauthClientService: OauthClientService,
    private val oauthUserService: OauthUserService,
    private val oauthAuthorizationCodeService: OauthAuthorizationCodeService,
    private val sessionCustomizer: SessionCustomizer,
    private val oauthConsentService: OauthConsentService,
    private val oauthLoginOptionService: OauthLoginOptionService,
    private val sessionProvider: SessionProvider,
) : OauthAuthorizationProcessService {
    override suspend fun authorize(
        clientId: String,
        redirectUri: String,
        responseType: String,
        scope: String?,
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        call: ApplicationCall,
    ): Result<Map<String, Any?>, Map<String, Any?>> {
        // Validate request parameters
        if (responseType != "code") {
            return Result.Failure(
                mapOf(
                    "error" to "Invalid request",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        // Validate and get client
        val client =
            oauthClientService.findByClientId(
                clientId,
                call,
            )
                ?: return Result.Failure(
                    mapOf(
                        "error" to "Invalid client_id",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        // Validate redirect URI
        if (!client.isDefault && !client.redirectUris.contains(redirectUri)) {
            return Result.Failure(
                mapOf(
                    "error" to "Invalid redirect_uri",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        if (client.isDefault && call.getBaseUrl()
                .replace("http://", "").replace("https://", "").replace("www.", "") !=
            redirectUri
                .replace("http://", "").replace("https://", "").replace("www.", "")
                .split("/").firstOrNull()
        ) {
            return Result.Failure(
                mapOf(
                    "error" to "Invalid redirect_uri",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        // Validate scopes
        if (!client.scopes.containsAll(scope?.split(" ")?.toList() ?: emptyList())) {
            return Result.Failure(
                mapOf(
                    "error" to "Invalid scopes",
                    "statusCode" to HttpStatusCode.BadRequest,
                ),
            )
        }

        // Val595473e0-3ec0-453d-a0f7-18e559cc9f68idate grant type
        if (!client.grantTypes.contains("authorization_code")) {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        // Validate PKCE for public clients
        if (client.clientType == "public") {
            if (codeChallenge == null || codeChallengeMethod == null) {
                return Result.Failure(
                    mapOf(
                        "error" to "Missing code challenge properties",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )
            }
            if (!listOf("S256", "plain").contains(codeChallengeMethod)) {
                return Result.Failure(
                    mapOf(
                        "error" to "Invalid code challenge method",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )
            }
        }

        // Check user session
        val session = sessionProvider.getSession(call).get<OauthUserSession>()
        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            return Result.Failure(
                mapOf(
                    "error" to "Unauthorized - No active session",
                    "statusCode" to HttpStatusCode.Unauthorized,
                    "requiresLogin" to true,
                ),
            )
        }

        // Check if user completed post-login checks
        if (!oauthLoginOptionService.isAfterLoginCheckCompleted(session, call)) {
            return Result.Failure(
                mapOf(
                    "error" to "Login checks not completed",
                    "statusCode" to HttpStatusCode.Unauthorized,
                ),
            )
        }

        // Check consent if required
        if (client.consentRequired) {
            val consents = oauthConsentService.getConsent(userId = session.userId, clientId = client.id, call)
            if (consents == null || !consents.containsAll(client.scopes)) {
                return Result.Failure(
                    mapOf(
                        "error" to "Consent required",
                        "statusCode" to HttpStatusCode.BadRequest,
                        "requiresConsent" to true,
                        "clientId" to client.clientId,
                    ),
                )
            }
        }

        // Get user
        val user =
            oauthUserService.findByUsername(
                session.username,
                call,
            )
                ?: return Result.Failure(
                    mapOf(
                        "error" to "User not found",
                        "statusCode" to HttpStatusCode.BadRequest,
                    ),
                )

        // Update session expiry if needed
        if (session.expiresAt > System.currentTimeMillis()) {
            val ttlSeconds =
                when (session.rememberMe) {
                    true -> 31536000
                    else -> sessionCustomizer.timeout ?: 3200
                }
            val expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000)
            sessionProvider.getSession(call).set(OauthUserSession(session.userId, session.username, expiresAt, session.rememberMe))
        }

        // Create authorization code
        val code = UUID.randomUUID().toString()
        val codeExpiresAt = Instant.now().plusSeconds(300)

        oauthAuthorizationCodeService.createCode(
            code,
            client.id,
            user.id,
            redirectUri,
            scope?.split(" ") ?: emptyList(),
            codeExpiresAt,
            codeChallenge,
            codeChallengeMethod,
            call,
        )

        return Result.Success(
            mapOf(
                "code" to code,
                "state" to state,
                "redirectUri" to redirectUri,
                "clientId" to client.clientId,
            ),
        )
    }
}
