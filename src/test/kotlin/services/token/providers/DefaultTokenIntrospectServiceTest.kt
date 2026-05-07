package services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.providers.AccessTokenDTO
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.token.providers.DefaultTokenIntrospectService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.BDDMockito.given
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import java.time.Instant
import java.util.UUID

@RunWith(MockitoJUnitRunner::class)
class DefaultTokenIntrospectServiceTest {
    @Mock
    lateinit var oauthClientService: OauthClientService

    @Mock
    lateinit var oauthTokenService: OauthTokenService

    @Mock
    lateinit var call: ApplicationCall

    lateinit var tokenIntrospectService: DefaultTokenIntrospectService

    @Before
    fun setUp() {
        tokenIntrospectService =
            DefaultTokenIntrospectService(
                oauthClientService,
                oauthTokenService,
            )
    }

    // ==================== Success Cases ====================

    @Test
    fun `introspect() returns success with active token`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "test_client_secret"
            val token = "valid_access_token"
            val clientUUID = UUID.randomUUID()
            val futureExpiry = Instant.now().plusSeconds(3600)

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = clientSecret,
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )

            val accessToken =
                AccessTokenDTO(
                    id = UUID.randomUUID(),
                    token = token,
                    clientId = clientUUID,
                    userId = "test_user",
                    expiresAt = futureExpiry,
                    scopes = listOf("read", "write"),
                    revoked = false,
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)
            given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Success)
            val successResult = result as Result.Success
            val response = successResult.outcome
            assertEquals(true, response["active"])
            assertEquals(clientUUID.toString(), response["client_id"])
            assertEquals(futureExpiry.epochSecond, response["exp"])
            assertEquals("read write", response["scope"])
        }

    @Test
    fun `introspect() returns success with inactive token when token is not found`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "test_client_secret"
            val token = "invalid_access_token"
            val clientUUID = UUID.randomUUID()

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = clientSecret,
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)
            given(oauthTokenService.findByAccessToken(token, call)).willReturn(null)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Success)
            val successResult = result as Result.Success
            val response = successResult.outcome
            assertEquals(false, response["active"])
        }

    @Test
    fun `introspect() returns success with inactive token when token is revoked`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "test_client_secret"
            val token = "revoked_access_token"
            val clientUUID = UUID.randomUUID()

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = clientSecret,
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )

            val accessToken =
                AccessTokenDTO(
                    id = UUID.randomUUID(),
                    token = token,
                    clientId = clientUUID,
                    userId = "test_user",
                    expiresAt = Instant.now().plusSeconds(3600),
                    scopes = listOf("read", "write"),
                    revoked = true,
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)
            given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Success)
            val successResult = result as Result.Success
            val response = successResult.outcome
            assertEquals(false, response["active"])
        }

    @Test
    fun `introspect() returns success with inactive token when token is expired`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "test_client_secret"
            val token = "expired_access_token"
            val clientUUID = UUID.randomUUID()

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = clientSecret,
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )

            val accessToken =
                AccessTokenDTO(
                    id = UUID.randomUUID(),
                    token = token,
                    clientId = clientUUID,
                    userId = "test_user",
                    expiresAt = Instant.now().minusSeconds(3600),
                    scopes = listOf("read", "write"),
                    revoked = false,
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)
            given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Success)
            val successResult = result as Result.Success
            val response = successResult.outcome
            assertEquals(false, response["active"])
        }

    // ==================== Failure Cases ====================

    @Test
    fun `introspect() returns failure when client_id is invalid`() =
        runTest {
            val clientId = "invalid_client_id"
            val clientSecret = "test_client_secret"
            val token = "some_token"

            given(oauthClientService.findByClientId(clientId, call)).willReturn(null)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Failure)
            val failureResult = result as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid client_id"))
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `introspect() returns failure when client_secret is invalid`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "invalid_secret"
            val token = "some_token"
            val clientUUID = UUID.randomUUID()

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "correct_secret",
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Failure)
            val failureResult = result as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Unauthorized"))
            assertEquals(HttpStatusCode.Unauthorized, error["statusCode"])
        }

    @Test
    fun `introspect() returns failure with specific status code for invalid client_id`() =
        runTest {
            val clientId = "invalid_client_id"
            val clientSecret = "test_client_secret"
            val token = "some_token"

            given(oauthClientService.findByClientId(clientId, call)).willReturn(null)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Failure)
            val failureResult = result as Result.Failure
            val error = failureResult.errorBody
            assertEquals(HttpStatusCode.BadRequest, error["statusCode"])
        }

    @Test
    fun `introspect() returns failure with specific status code for unauthorized client_secret`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "invalid_secret"
            val token = "some_token"
            val clientUUID = UUID.randomUUID()

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = "correct_secret",
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Failure)
            val failureResult = result as Result.Failure
            val error = failureResult.errorBody
            assertEquals(HttpStatusCode.Unauthorized, error["statusCode"])
        }

    @Test
    fun `introspect() returns success with correct scope information for multiple scopes`() =
        runTest {
            val clientId = "test_client_id"
            val clientSecret = "test_client_secret"
            val token = "valid_access_token"
            val clientUUID = UUID.randomUUID()
            val scopes = listOf("openid", "profile", "email", "read", "write")
            val futureExpiry = Instant.now().plusSeconds(3600)

            val client =
                OAuthClientDTO(
                    id = clientUUID,
                    clientName = "Test Client",
                    clientId = clientId,
                    clientSecret = clientSecret,
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = scopes,
                    redirectUris = listOf("https://example.com/callback"),
                )

            val accessToken =
                AccessTokenDTO(
                    id = UUID.randomUUID(),
                    token = token,
                    clientId = clientUUID,
                    userId = "test_user",
                    expiresAt = futureExpiry,
                    scopes = scopes,
                    revoked = false,
                )

            given(oauthClientService.findByClientId(clientId, call)).willReturn(client)
            given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)

            val result = tokenIntrospectService.introspect(token, clientId, clientSecret, call)

            assertTrue(result is Result.Success)
            val successResult = result as Result.Success
            val response = successResult.outcome
            assertEquals(true, response["active"])
            assertEquals("openid profile email read write", response["scope"])
        }
}
