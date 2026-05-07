package services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.token.providers.DefaultClientCredentialsTokenGenerator
import io.ktor.http.RequestConnectionPoint
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.ApplicationRequest
import io.ktor.util.Attributes
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.BDDMockito.given
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import java.util.UUID
import kotlin.test.assertEquals

@RunWith(MockitoJUnitRunner::class)
class DefaultClientCredentialsTokenGeneratorTest {
    @Mock
    lateinit var oauthClientService: OauthClientService

    @Mock
    lateinit var oauthTokenService: OauthTokenService

    @Mock
    lateinit var jwksProvider: JwksProvider

    @Mock
    lateinit var call: ApplicationCall

    @Mock
    lateinit var request: ApplicationRequest

    @Mock
    lateinit var attributes: Attributes

    @Mock
    lateinit var origin: RequestConnectionPoint

    lateinit var clientCredentialsTokenGenerator: DefaultClientCredentialsTokenGenerator

    @Before
    fun setUp() {
        clientCredentialsTokenGenerator =
            DefaultClientCredentialsTokenGenerator(
                oauthClientService,
                oauthTokenService,
                jwksProvider,
            )
    }

    @Test
    fun `generateTokens() returns generated code successfully`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "valid_client_secret",
                    clientType = "confidential",
                    grantTypes = listOf("client_credentials"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val accessToken = "generated_access_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(
                jwksProvider.generateJwt(
                    subject = clientId.toString(),
                    audience = "",
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
                    client = client,
                    tokenType = TokenType.ACCESS_TOKEN,
                    call = call,
                ),
            ).willReturn(accessToken)

            given(call.request).willReturn(request)
            given(request.call).willReturn(call)
            given(call.attributes).willReturn(attributes)
            given(request.origin).willReturn(origin)
            given(origin.scheme).willReturn("https")
            given(origin.serverHost).willReturn("example.com")
            given(origin.serverPort).willReturn(443)

            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertEquals(accessToken, response["access_token"])
        }

    @Test
    fun `generateTokens() returns failure when client is public`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Client",
                        clientId = clientId.toString(),
                        clientSecret = "valid_client_secret",
                        clientType = "public",
                        grantTypes = listOf("client_credentials"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Unauthorized"))
        }

    @Test
    fun `generateTokens() returns failure when client_id is missing`() =
        runTest {
            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_secret" to "some_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing client_id"))
        }

    @Test
    fun `generateTokens() returns failure when client_secret is missing`() =
        runTest {
            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to "some_client_id",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing client_secret"))
        }

    @Test
    fun `generateTokens() returns failure when client_id is invalid`() =
        runTest {
            given(oauthClientService.findByClientId("invalid_client_id", call))
                .willReturn(null)

            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to "invalid_client_id",
                            "client_secret" to "some_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid client_id"))
        }

    @Test
    fun `generateTokens() returns failure when client_secret is invalid for confidential client`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Client",
                        clientId = clientId.toString(),
                        clientSecret = "valid_client_secret",
                        clientType = "confidential",
                        grantTypes = listOf("client_credentials"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "invalid_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Unauthorized"))
        }

    @Test
    fun `generateTokens() returns failure when grant type is not permitted`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Client",
                        clientId = clientId.toString(),
                        clientSecret = "valid_client_secret",
                        clientType = "confidential",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            val actual =
                clientCredentialsTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Grant type not permitted"))
        }
}
