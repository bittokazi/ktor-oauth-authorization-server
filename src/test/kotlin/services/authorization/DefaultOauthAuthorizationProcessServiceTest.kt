package services.authorization

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.authorization.DefaultOauthAuthorizationProcessService
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.session.SessionProvider
import io.ktor.http.HttpStatusCode
import io.ktor.http.RequestConnectionPoint
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.ApplicationRequest
import io.ktor.server.sessions.CurrentSession
import io.ktor.server.sessions.get
import io.ktor.util.Attributes
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.BDDMockito.given
import org.mockito.Mock
import org.mockito.Mockito.mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.any
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

@RunWith(MockitoJUnitRunner::class)
class DefaultOauthAuthorizationProcessServiceTest {
    @Mock
    lateinit var oauthClientService: OauthClientService

    @Mock
    lateinit var oauthUserService: OauthUserService

    @Mock
    lateinit var oauthAuthorizationCodeService: OauthAuthorizationCodeService

    @Mock
    lateinit var sessionCustomizer: SessionCustomizer

    @Mock
    lateinit var oauthConsentService: OauthConsentService

    @Mock
    lateinit var oauthLoginOptionService: OauthLoginOptionService

    @Mock
    lateinit var call: ApplicationCall

    @Mock
    lateinit var request: ApplicationRequest

    @Mock
    lateinit var attributes: Attributes

    @Mock
    lateinit var origin: RequestConnectionPoint

    @Mock
    lateinit var sessionProvider: SessionProvider

    lateinit var defaultOauthAuthorizationService: DefaultOauthAuthorizationProcessService

    @Before
    fun setUp() {
        defaultOauthAuthorizationService =
            DefaultOauthAuthorizationProcessService(
                oauthClientService,
                oauthUserService,
                oauthAuthorizationCodeService,
                sessionCustomizer,
                oauthConsentService,
                oauthLoginOptionService,
                sessionProvider,
            )
    }

    private fun setupCallMocks() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)
    }

    private fun setupSessionMocks(
        userId: String,
        username: String,
        rememberMe: Boolean = false,
    ) {
        val expiresAt = System.currentTimeMillis() + (3600 * 1000)
        val session = OauthUserSession(userId, username, expiresAt, rememberMe)
        val sessionsMock = mock<CurrentSession>()
        given(sessionProvider.getSession(call)).willReturn(sessionsMock)
        given(sessionsMock.get<OauthUserSession>()).willReturn(session)
    }

    // ==================== Success Cases ====================

    @Test
    fun `authorize() returns success for confidential client without PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Confidential Client",
                    clientId = clientId.toString(),
                    clientSecret = "valid_secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = false,
                )

            val user =
                OAuthUserDTO(
                    id = userId,
                    username = username,
                    email = "test@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthUserService.findById(userId, call))
                .willReturn(user)

            given(sessionCustomizer.timeout).willReturn(3600)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId.toString(),
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read write",
                    state = "xyz123",
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome

            assertNotNull(response["code"])
            assertEquals("xyz123", response["state"])
            assertEquals("https://example.com/callback", response["redirectUri"])
            assertEquals(clientId.toString(), response["clientId"])
        }

    @Test
    fun `authorize() returns success for public client with S256 PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId.toString(),
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = false,
                )

            val user =
                OAuthUserDTO(
                    id = userId,
                    username = username,
                    email = "test@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthUserService.findById(userId, call))
                .willReturn(user)

            given(sessionCustomizer.timeout).willReturn(3600)

            given(oauthAuthorizationCodeService.createCode(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .willReturn(true)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId.toString(),
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read write",
                    state = "xyz123",
                    codeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    codeChallengeMethod = "S256",
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome

            assertNotNull(response["code"])
            assertEquals("xyz123", response["state"])
            assertEquals("https://example.com/callback", response["redirectUri"])
        }

    @Test
    fun `authorize() returns success for public client with plain PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId.toString(),
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("openid", "profile"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = false,
                )

            val user =
                OAuthUserDTO(
                    id = userId,
                    username = username,
                    email = "test@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthUserService.findById(userId, call))
                .willReturn(user)

            given(sessionCustomizer.timeout).willReturn(3600)

            given(oauthAuthorizationCodeService.createCode(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .willReturn(true)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId.toString(),
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "openid profile",
                    state = "state_value",
                    codeChallenge = "simple_challenge",
                    codeChallengeMethod = "plain",
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome

            assertNotNull(response["code"])
            assertEquals("state_value", response["state"])
        }

    @Test
    fun `authorize() returns success with consent required and granted`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Consent Client",
                    clientId = clientId.toString(),
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write", "profile"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = true,
                )

            val user =
                OAuthUserDTO(
                    id = userId,
                    username = username,
                    email = "test@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthConsentService.getConsent(userId, clientIdentifier, call))
                .willReturn(listOf("read", "write", "profile"))

            given(oauthUserService.findById(userId, call))
                .willReturn(user)

            given(sessionCustomizer.timeout).willReturn(3600)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId.toString(),
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read write profile",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome

            assertNotNull(response["code"])
            assertTrue(response.containsKey("state"))
            assertNull(response["state"])
        }

    @Test
    fun `authorize() returns success without scope`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = false,
                )

            val user =
                OAuthUserDTO(
                    id = userId,
                    username = username,
                    email = "test@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthUserService.findById(userId, call))
                .willReturn(user)

            given(sessionCustomizer.timeout).willReturn(3600)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId.toString(),
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = null,
                    state = "state123",
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome

            assertNotNull(response["code"])
            assertEquals("state123", response["state"])
        }

    @Test
    fun `authorize() updates session expiry on success`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = false,
                )

            val user =
                OAuthUserDTO(
                    id = userId,
                    username = username,
                    email = "test@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                )

            setupCallMocks()
            setupSessionMocks(userId, username, rememberMe = true)

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthUserService.findById(userId, call))
                .willReturn(user)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId.toString(),
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Success)
        }

    // ==================== Failure Cases ====================

    @Test
    fun `authorize() returns failure for invalid response type`() =
        runTest {
            val clientId = UUID.randomUUID().toString()

            setupCallMocks()

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "token",
                    scope = null,
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertTrue(error.containsKey("error"))
            assertEquals("Invalid request", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure for invalid client_id`() =
        runTest {
            setupCallMocks()

            given(oauthClientService.findByClientId("invalid_client", call))
                .willReturn(null)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = "invalid_client",
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = null,
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertTrue(error.containsKey("error"))
            assertEquals("Invalid client_id", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure for invalid redirect_uri for non-default client`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://malicious.com/callback",
                    responseType = "code",
                    scope = null,
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertTrue(error.containsKey("error"))
            assertEquals("Invalid redirect_uri", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure for invalid redirect_uri for default client`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = true,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://different.com/callback",
                    responseType = "code",
                    scope = null,
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Invalid redirect_uri", error["error"])
        }

    @Test
    fun `authorize() returns failure for invalid scopes`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read write delete",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Invalid scopes", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure for unsupported grant type`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Unauthorized", error["error"])
            assertEquals(HttpStatusCode.Unauthorized, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure for public client without code_challenge`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId,
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Missing code challenge properties", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure for public client without codeChallengeMethod`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId,
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = "challenge_value",
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Missing code challenge properties", error["error"])
        }

    @Test
    fun `authorize() returns failure for invalid code_challenge_method`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId,
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = "challenge_value",
                    codeChallengeMethod = "INVALID",
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Invalid code challenge method", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure when session is null`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            val sessionsMock = mock<CurrentSession>()
            given(sessionProvider.getSession(call)).willReturn(sessionsMock)
            given(sessionsMock.get<OauthUserSession>()).willReturn(null)

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Unauthorized - No active session", error["error"])
            assertEquals(HttpStatusCode.Unauthorized, error["statusCode"])
            assertTrue(error["requiresLogin"] == true)
        }

    @Test
    fun `authorize() returns failure when session is expired`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()

            // Create an expired session
            val expiredSession = OauthUserSession(userId, username, System.currentTimeMillis() - 1000, false)
            val sessionsMock = mock<CurrentSession>()
            given(sessionProvider.getSession(call)).willReturn(sessionsMock)
            given(sessionsMock.get<OauthUserSession>()).willReturn(expiredSession)

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Unauthorized - No active session", error["error"])
            assertEquals(HttpStatusCode.Unauthorized, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure when login checks not completed`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    isDefault = false,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(false)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Login checks not completed", error["error"])
            assertEquals(HttpStatusCode.Unauthorized, error["statusCode"])
        }

    @Test
    fun `authorize() returns failure when consent required but not granted`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = true,
                    isDefault = false,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthConsentService.getConsent(userId, clientIdentifier, call))
                .willReturn(null)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read write",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Consent required", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
            assertTrue(error["requiresConsent"] == true)
            assertEquals(clientId, error["clientId"])
        }

    @Test
    fun `authorize() returns failure when consent granted but not for all requested scopes`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()
            val userId = "user_1"
            val username = "testuser"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write", "delete"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = true,
                    isDefault = false,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthConsentService.getConsent(userId, clientIdentifier, call))
                .willReturn(listOf("read"))

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read write delete",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("Consent required", error["error"])
            assertTrue(error["requiresConsent"] == true)
        }

    @Test
    fun `authorize() returns failure when user not found`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID().toString()
            val userId = "user_1"
            val username = "nonexistent"

            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "secret",
                    clientType = "confidential",
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read"),
                    redirectUris = listOf("https://example.com/callback"),
                    consentRequired = false,
                    isDefault = false,
                )

            setupCallMocks()
            setupSessionMocks(userId, username)

            given(oauthClientService.findByClientId(clientId, call))
                .willReturn(client)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any()))
                .willReturn(true)

            given(oauthUserService.findById(userId, call))
                .willReturn(null)

            val actual =
                defaultOauthAuthorizationService.authorize(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                    responseType = "code",
                    scope = "read",
                    state = null,
                    codeChallenge = null,
                    codeChallengeMethod = null,
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody

            assertEquals("User not found", error["error"])
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }
}
