package services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeDTO
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.token.providers.DefaultDeviceCodeTokenGenerator
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
import org.mockito.Mockito.verify
import org.mockito.junit.MockitoJUnitRunner
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse

@RunWith(MockitoJUnitRunner::class)
class DefaultDeviceCodeTokenGeneratorTest {
    @Mock
    lateinit var oauthClientService: OauthClientService

    @Mock
    lateinit var oauthDeviceCodeService: OauthDeviceCodeService

    @Mock
    lateinit var oauthTokenService: OauthTokenService

    @Mock
    lateinit var oauthUserService: OauthUserService

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

    lateinit var deviceCodeTokenGenerator: DefaultDeviceCodeTokenGenerator

    @Before
    fun setUp() {
        deviceCodeTokenGenerator =
            DefaultDeviceCodeTokenGenerator(
                oauthClientService,
                oauthDeviceCodeService,
                oauthTokenService,
                oauthUserService,
                jwksProvider,
            )
    }

    @Test
    fun `generateTokens() returns failure when client_id is missing`() =
        runTest {
            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_secret" to "some_secret",
                            "device_code" to "some_code",
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
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to "some_client_id",
                            "device_code" to "some_code",
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
    fun `generateTokens() returns failure when device_code is missing`() =
        runTest {
            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to "some_client_id",
                            "client_secret" to "some_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing device_code"))
        }

    @Test
    fun `generateTokens() returns failure when client_id is invalid`() =
        runTest {
            given(oauthClientService.findByClientId("invalid_client_id", call))
                .willReturn(null)

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to "invalid_client_id",
                            "client_secret" to "some_secret",
                            "device_code" to "some_code",
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
    fun `generateTokens() returns failure when client_secret is invalid`() =
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
                        grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "invalid_secret",
                            "device_code" to "some_code",
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
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "some_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Grant type not permitted"))
        }

    @Test
    fun `generateTokens() returns failure when device_code is invalid`() =
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
                        grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthDeviceCodeService.findByDeviceCode("invalid_code", false, false, call))
                .willReturn(null)

            given(oauthDeviceCodeService.findByDeviceCode("invalid_code", true, false, call))
                .willReturn(null)

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "invalid_code",
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
    fun `generateTokens() returns failure when device_code is expired`() =
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
                        grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthDeviceCodeService.findByDeviceCode("expired_code", false, false, call))
                .willReturn(null)

            given(oauthDeviceCodeService.findByDeviceCode("expired_code", true, false, call))
                .willReturn(
                    OauthDeviceCodeDTO(
                        id = UUID.randomUUID(),
                        deviceCode = "expired_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        scopes = listOf("read", "write"),
                        expiresAt = Instant.now().minusSeconds(3600),
                        isDeviceAuthorized = true,
                        consumed = false,
                        userCode = "USER_CODE",
                    ),
                )

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "expired_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("expired_token"))
        }

    @Test
    fun `generateTokens() returns failure when authorization is pending`() =
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
                        grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthDeviceCodeService.findByDeviceCode("pending_code", false, false, call))
                .willReturn(
                    OauthDeviceCodeDTO(
                        id = UUID.randomUUID(),
                        deviceCode = "pending_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        scopes = listOf("read", "write"),
                        expiresAt = Instant.now().plusSeconds(3600),
                        isDeviceAuthorized = false,
                        consumed = false,
                        userCode = "USER_CODE",
                    ),
                )

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "pending_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("authorization_pending"))
        }

    @Test
    fun `generateTokens() returns success with access_token when all parameters are valid`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "valid_client_secret",
                    clientType = "confidential",
                    grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    accessTokenValidity = 3600,
                    refreshTokenValidity = 7200,
                )

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", false, false, call))
                .willReturn(null)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", true, false, call))
                .willReturn(
                    OauthDeviceCodeDTO(
                        id = UUID.randomUUID(),
                        deviceCode = "valid_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        scopes = listOf("read", "write"),
                        expiresAt = Instant.now().plusSeconds(3600),
                        isDeviceAuthorized = true,
                        consumed = false,
                        userCode = "USER_CODE",
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("read", "write"),
                    issuer = "https://example.com",
                    expiresInSeconds = 3600,
                    client = client,
                    userId = userId,
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
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "valid_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success

            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertTrue(response["token_type"] == "bearer")
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
            verify(oauthDeviceCodeService).consumeDeviceCode("valid_code", call)
        }

    @Test
    fun `generateTokens() returns success with refresh_token when grant type is included`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val refreshToken = "generated_refresh_token"
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "valid_client_secret",
                    clientType = "confidential",
                    grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code", "refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                    accessTokenValidity = 3600,
                    refreshTokenValidity = 7200,
                )

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", false, false, call))
                .willReturn(null)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", true, false, call))
                .willReturn(
                    OauthDeviceCodeDTO(
                        id = UUID.randomUUID(),
                        deviceCode = "valid_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        scopes = listOf("read", "write"),
                        expiresAt = Instant.now().plusSeconds(3600),
                        isDeviceAuthorized = true,
                        consumed = false,
                        userCode = "USER_CODE",
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("read", "write"),
                    issuer = "https://example.com",
                    expiresInSeconds = 3600,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ACCESS_TOKEN,
                    call = call,
                ),
            ).willReturn(accessToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("read", "write"),
                    issuer = "https://example.com",
                    expiresInSeconds = 7200,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.REFRESH_TOKEN,
                    call = call,
                ),
            ).willReturn(refreshToken)

            given(call.request).willReturn(request)
            given(request.call).willReturn(call)
            given(call.attributes).willReturn(attributes)
            given(request.origin).willReturn(origin)
            given(origin.scheme).willReturn("https")
            given(origin.serverHost).willReturn("example.com")
            given(origin.serverPort).willReturn(443)

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "valid_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertTrue(response.containsKey("refresh_token"))
            assertEquals(refreshToken, response["refresh_token"])

            assertFalse(response.containsKey("id_token"))

            assertTrue(response["token_type"] == "bearer")
            verify(oauthDeviceCodeService).consumeDeviceCode("valid_code", call)
        }

    @Test
    fun `generateTokens() returns success with id_token when openid scope is included`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"

            val oauthClientDto =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "valid_client_secret",
                    clientType = "confidential",
                    grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code"),
                    scopes = listOf("openid", "profile", "email"),
                    redirectUris = listOf("https://example.com/callback"),
                    accessTokenValidity = 3600,
                    refreshTokenValidity = 7200,
                )

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(oauthClientDto)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", false, false, call))
                .willReturn(null)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", true, false, call))
                .willReturn(
                    OauthDeviceCodeDTO(
                        id = UUID.randomUUID(),
                        deviceCode = "valid_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        scopes = listOf("openid", "profile", "email"),
                        expiresAt = Instant.now().plusSeconds(3600),
                        isDeviceAuthorized = true,
                        consumed = false,
                        userCode = "USER_CODE",
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("openid", "profile", "email"),
                    issuer = "https://example.com",
                    expiresInSeconds = 3600,
                    client = oauthClientDto,
                    userId = userId,
                    tokenType = TokenType.ACCESS_TOKEN,
                    call = call,
                ),
            ).willReturn(accessToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("openid", "profile", "email"),
                    issuer = "https://example.com",
                    expiresInSeconds = 3600,
                    client = oauthClientDto,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = null,
                    call = call,
                ),
            ).willReturn(idToken)

            given(call.request).willReturn(request)
            given(request.call).willReturn(call)
            given(call.attributes).willReturn(attributes)
            given(request.origin).willReturn(origin)
            given(origin.scheme).willReturn("https")
            given(origin.serverHost).willReturn("example.com")
            given(origin.serverPort).willReturn(443)

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "valid_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertTrue(response.containsKey("id_token"))
            assertEquals(idToken, response["id_token"])

            assertFalse(response.containsKey("refresh_token"))

            assertTrue(response["token_type"] == "bearer")
            verify(oauthDeviceCodeService).consumeDeviceCode("valid_code", call)
        }

    @Test
    fun `generateTokens() returns success with all tokens when refresh_token grant and openid scope are included`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val refreshToken = "generated_refresh_token"
            val idToken = "generated_id_token"
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Client",
                    clientId = clientId.toString(),
                    clientSecret = "valid_client_secret",
                    clientType = "confidential",
                    grantTypes = listOf("urn:ietf:params:oauth:grant-type:device_code", "refresh_token"),
                    scopes = listOf("openid", "profile", "email"),
                    redirectUris = listOf("https://example.com/callback"),
                    accessTokenValidity = 3600,
                    refreshTokenValidity = 7200,
                )

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", false, false, call))
                .willReturn(null)

            given(oauthDeviceCodeService.findByDeviceCode("valid_code", true, false, call))
                .willReturn(
                    OauthDeviceCodeDTO(
                        id = UUID.randomUUID(),
                        deviceCode = "valid_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        scopes = listOf("openid", "profile", "email"),
                        expiresAt = Instant.now().plusSeconds(3600),
                        isDeviceAuthorized = true,
                        consumed = false,
                        userCode = "USER_CODE",
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("openid", "profile", "email"),
                    issuer = "https://example.com",
                    expiresInSeconds = 3600,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ACCESS_TOKEN,
                    call = call,
                ),
            ).willReturn(accessToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("openid", "profile", "email"),
                    issuer = "https://example.com",
                    expiresInSeconds = 7200,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.REFRESH_TOKEN,
                    call = call,
                ),
            ).willReturn(refreshToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = listOf("openid", "profile", "email"),
                    issuer = "https://example.com",
                    expiresInSeconds = 3600,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = null,
                    call = call,
                ),
            ).willReturn(idToken)

            given(call.request).willReturn(request)
            given(request.call).willReturn(call)
            given(call.attributes).willReturn(attributes)
            given(request.origin).willReturn(origin)
            given(origin.scheme).willReturn("https")
            given(origin.serverHost).willReturn("example.com")
            given(origin.serverPort).willReturn(443)

            val actual =
                deviceCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                            "device_code" to "valid_code",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertTrue(response.containsKey("id_token"))
            assertEquals(idToken, response["id_token"])

            assertTrue(response.containsKey("refresh_token"))
            assertEquals(refreshToken, response["refresh_token"])

            assertTrue(response["token_type"] == "bearer")
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
            verify(oauthDeviceCodeService).consumeDeviceCode("valid_code", call)
        }
}
