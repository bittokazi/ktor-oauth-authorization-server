package services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.AuthorizationCodeDTO
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.token.providers.DefaultAuthorizationCodeTokenGenerator
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
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse

@RunWith(MockitoJUnitRunner::class)
class DefaultAuthorizationCodeTokenGeneratorTest {
    @Mock
    lateinit var oauthClientService: OauthClientService

    @Mock
    lateinit var oauthAuthorizationCodeService: OauthAuthorizationCodeService

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

    lateinit var authorizationCodeTokenGenerator: DefaultAuthorizationCodeTokenGenerator

    @Before
    fun setUp() {
        authorizationCodeTokenGenerator =
            DefaultAuthorizationCodeTokenGenerator(
                oauthClientService,
                oauthAuthorizationCodeService,
                oauthTokenService,
                oauthUserService,
                jwksProvider,
            )
    }

    @Test
    fun `generateTokens() returns generated code successfully for confidential client`() =
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
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("unconsumed_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "unconsumed_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "unconsumed_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertFalse(response.containsKey("id_token"))
            assertFalse(response.containsKey("refreshToken"))

            assertTrue(response["token_type"] == "bearer")
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with S256 PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
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
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        codeChallengeMethod = "S256",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertFalse(response.containsKey("id_token"))
            assertFalse(response.containsKey("refreshToken"))

            assertTrue(response["token_type"] == "bearer")
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with plain PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
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
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("plain_pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "plain_pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "simple_challenge",
                        codeChallengeMethod = "plain",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "plain_pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "simple_challenge",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Success)
            val successResult = actual as Result.Success
            val response = successResult.outcome
            assertTrue(response.containsKey("access_token"))
            assertEquals(accessToken, response["access_token"])

            assertFalse(response.containsKey("id_token"))
            assertFalse(response.containsKey("refreshToken"))

            assertTrue(response["token_type"] == "bearer")
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns failure when code is missing`() =
        runTest {
            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to "some_client_id",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing code"))
        }

    @Test
    fun `generateTokens() returns failure when redirect_uri is missing`() =
        runTest {
            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "some_code",
                            "client_id" to "some_client_id",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing redirect_uri"))
        }

    @Test
    fun `generateTokens() returns failure when client_id is missing`() =
        runTest {
            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "some_code",
                            "redirect_uri" to "https://example.com/callback",
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
    fun `generateTokens() returns failure when client_id is invalid`() =
        runTest {
            given(oauthClientService.findByClientId("invalid_client_id", call))
                .willReturn(null)

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "some_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to "invalid_client_id",
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
                        grantTypes = listOf("client_credentials"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "some_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
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
    fun `generateTokens() returns failure when authorization code is invalid`() =
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

            given(oauthAuthorizationCodeService.findByCode("invalid_code", call))
                .willReturn(null)

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "invalid_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid code"))
        }

    @Test
    fun `generateTokens() returns failure when client_id does not match authorization code client_id`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val mismatchedClientIdentifier = UUID.randomUUID()
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

            given(oauthAuthorizationCodeService.findByCode("valid_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "valid_code",
                        clientId = mismatchedClientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "valid_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
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
    fun `generateTokens() returns failure when client_secret is missing for confidential client`() =
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

            given(oauthAuthorizationCodeService.findByCode("valid_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "valid_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "valid_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
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
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("valid_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "valid_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "valid_code",
                            "redirect_uri" to "https://example.com/callback",
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
    fun `generateTokens() returns failure when redirect_uri does not match`() =
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

            given(oauthAuthorizationCodeService.findByCode("valid_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "valid_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "valid_code",
                            "redirect_uri" to "https://different.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid redirect_uri"))
        }

    @Test
    fun `generateTokens() returns failure when authorization code is already consumed`() =
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

            given(oauthAuthorizationCodeService.findByCode("consumed_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "consumed_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = true,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "consumed_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid or used code"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for confidential client with id_token only`() =
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
                    grantTypes = listOf("authorization_code"),
                    scopes = listOf("openid", "profile"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("unconsumed_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "unconsumed_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("openid", "profile"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "unconsumed_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
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
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for confidential client with refresh_token only`() =
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
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val refreshToken = "generated_refresh_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("unconsumed_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "unconsumed_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.refreshTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "unconsumed_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
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
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for confidential client with both id_token and refresh_token`() =
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
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scopes = listOf("openid", "profile", "email"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"
            val refreshToken = "generated_refresh_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("unconsumed_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "unconsumed_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("openid", "profile", "email"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = null,
                    call = call,
                ),
            ).willReturn(idToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.refreshTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "unconsumed_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
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
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with S256 PKCE with id_token only`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
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
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("openid", "profile"),
                        codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        codeChallengeMethod = "S256",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
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
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with S256 PKCE with refresh_token only`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId.toString(),
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val refreshToken = "generated_refresh_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        codeChallengeMethod = "S256",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.refreshTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
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
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with S256 PKCE with both id_token and refresh_token`() =
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
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scopes = listOf("openid", "profile", "email"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"
            val refreshToken = "generated_refresh_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("unconsumed_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "unconsumed_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("openid", "profile", "email"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = null,
                    call = call,
                ),
            ).willReturn(idToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.refreshTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "unconsumed_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "client_secret" to "valid_client_secret",
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
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with plain PKCE with id_token only`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
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
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("plain_pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "plain_pkce_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("openid", "profile"),
                        codeChallenge = "simple_challenge",
                        codeChallengeMethod = "plain",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "plain_pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "simple_challenge",
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
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with plain PKCE with refresh_token only`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId.toString(),
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val refreshToken = "generated_refresh_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("plain_pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "plain_pkce_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "simple_challenge",
                        codeChallengeMethod = "plain",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.refreshTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "plain_pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "simple_challenge",
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
            assertTrue(response.containsKey("expires_in"))
            assertTrue(response.containsKey("scope"))
        }

    @Test
    fun `generateTokens() returns generated code successfully for public client with plain PKCE with both id_token and refresh_token`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()
            val client =
                OAuthClientDTO(
                    id = clientIdentifier,
                    clientName = "Test Public Client",
                    clientId = clientId.toString(),
                    clientSecret = null,
                    clientType = "public",
                    grantTypes = listOf("authorization_code", "refresh_token"),
                    scopes = listOf("openid", "profile", "email"),
                    redirectUris = listOf("https://example.com/callback"),
                )
            val userId = "user_1"
            val accessToken = "generated_access_token"
            val idToken = "generated_id_token"
            val refreshToken = "generated_refresh_token"

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(client)

            given(oauthAuthorizationCodeService.findByCode("plain_pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "plain_pkce_code",
                        clientId = clientIdentifier,
                        userId = userId,
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("openid", "profile", "email"),
                        codeChallenge = "simple_challenge",
                        codeChallengeMethod = "plain",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
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
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.accessTokenValidity,
                    client = client,
                    userId = userId,
                    tokenType = TokenType.ID_TOKEN,
                    user = null,
                    call = call,
                ),
            ).willReturn(idToken)

            given(
                jwksProvider.generateJwt(
                    subject = userId,
                    audience = clientId.toString(),
                    scopes = client.scopes,
                    issuer = "https://example.com",
                    expiresInSeconds = client.refreshTokenValidity,
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
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "plain_pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "simple_challenge",
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
        }

    @Test
    fun `generateTokens() returns failure when code_verifier is missing for public client with plain PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Public Client",
                        clientId = clientId.toString(),
                        clientSecret = null,
                        clientType = "public",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("plain_pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "plain_pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "simple_challenge",
                        codeChallengeMethod = "plain",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "plain_pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing code_verifier"))
        }

    @Test
    fun `generateTokens() returns failure when code_verifier is missing for public client with S256 PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Public Client",
                        clientId = clientId.toString(),
                        clientSecret = null,
                        clientType = "public",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        codeChallengeMethod = "S256",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing code_verifier"))
        }

    @Test
    fun `generateTokens() returns failure when code_verifier does not match code_challenge for plain PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Public Client",
                        clientId = clientId.toString(),
                        clientSecret = null,
                        clientType = "public",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("plain_pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "plain_pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "simple_challenge",
                        codeChallengeMethod = "plain",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "plain_pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "wrong_challenge",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid code challenge"))
        }

    @Test
    fun `generateTokens() returns failure when code_verifier does not match code_challenge for S256 PKCE`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Public Client",
                        clientId = clientId.toString(),
                        clientSecret = null,
                        clientType = "public",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        codeChallengeMethod = "S256",
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "invalid_verifier_that_does_not_match",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Invalid code challenge"))
        }

    @Test
    fun `generateTokens() returns failure when code_challenge is missing for public client with plain PKCE during token request`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Public Client",
                        clientId = clientId.toString(),
                        clientSecret = null,
                        clientType = "public",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "simple_challenge",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing code_challenge"))
        }

    @Test
    fun `generateTokens() returns failure when code_challenge is missing for public client with S256 PKCE during token request`() =
        runTest {
            val clientIdentifier = UUID.randomUUID()
            val clientId = UUID.randomUUID()

            given(oauthClientService.findByClientId(clientId.toString(), call))
                .willReturn(
                    OAuthClientDTO(
                        id = clientIdentifier,
                        clientName = "Test Public Client",
                        clientId = clientId.toString(),
                        clientSecret = null,
                        clientType = "public",
                        grantTypes = listOf("authorization_code"),
                        scopes = listOf("read", "write"),
                        redirectUris = listOf("https://example.com/callback"),
                    ),
                )

            given(oauthAuthorizationCodeService.findByCode("pkce_code", call))
                .willReturn(
                    AuthorizationCodeDTO(
                        code = "pkce_code",
                        clientId = clientIdentifier,
                        userId = "user_1",
                        redirectUri = "https://example.com/callback",
                        scopes = listOf("read", "write"),
                        codeChallenge = null,
                        codeChallengeMethod = null,
                        expiresAt = Instant.now().plusSeconds(600),
                        consumed = false,
                    ),
                )

            val actual =
                authorizationCodeTokenGenerator.generateTokens(
                    params =
                        mapOf(
                            "code" to "pkce_code",
                            "redirect_uri" to "https://example.com/callback",
                            "client_id" to clientId.toString(),
                            "code_verifier" to "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        ),
                    call = call,
                )

            assertTrue(actual is Result.Failure)
            val failureResult = actual as Result.Failure
            val error = failureResult.errorBody
            assertTrue(error.containsKey("error"))
            assertTrue(error["error"].toString().contains("Missing code_challenge"))
        }
}
