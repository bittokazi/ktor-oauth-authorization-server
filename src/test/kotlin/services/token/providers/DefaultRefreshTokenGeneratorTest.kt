package services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.providers.RefreshTokenDTO
import com.bittokazi.ktor.auth.services.token.providers.DefaultRefreshTokenGenerator
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
class DefaultRefreshTokenGeneratorTest {

    @Mock
    lateinit var oauthClientService: OauthClientService

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

    lateinit var refreshTokenGenerator: DefaultRefreshTokenGenerator

    @Before
    fun setUp() {
        refreshTokenGenerator = DefaultRefreshTokenGenerator(
            oauthClientService,
            oauthTokenService,
            oauthUserService,
            jwksProvider
        )
    }

    @Test
    fun `generateTokens() returns token successfully`() = runTest {
        val clientIdentifier = UUID.randomUUID()
        val clientId = UUID.randomUUID()
        val client = OAuthClientDTO(
            id = clientIdentifier,
            clientName = "Test Client",
            clientId = clientId.toString(),
            clientSecret = "valid_client_secret",
            clientType = "confidential",
            grantTypes = listOf("refresh_token"),
            scopes = listOf("read", "write"),
            redirectUris = listOf("https://example.com/callback")
        )
        val accessToken = "generated_access_token"
        val refreshToken = "generated_refresh_token"
        val userId = "user_1"

        given(oauthClientService.findByClientId(clientId.toString(), call))
            .willReturn(client)

        given(oauthTokenService.findByRefreshToken("valid_refresh_token", call))
            .willReturn(
                RefreshTokenDTO(
                    id = UUID.randomUUID(),
                    token = "valid_refresh_token",
                    clientId = clientIdentifier,
                    userId = userId,
                    scopes = client.scopes,
                    expiresAt = Instant.now().plusSeconds(3600),
                    revoked = false,
                    rotatedTo = null
                )
            )

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.accessTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.ACCESS_TOKEN,
            call = call
        )).willReturn(accessToken)

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.refreshTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.REFRESH_TOKEN,
            user = null,
            call = call
        )).willReturn(refreshToken)

        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "valid_refresh_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
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
    fun `generateTokens() returns token successfully for public client`() = runTest {
        val clientIdentifier = UUID.randomUUID()
        val clientId = UUID.randomUUID()
        val accessToken = "generated_access_token"
        val refreshToken = "generated_refresh_token"
        val userId = "user_1"
        val client = OAuthClientDTO(
            id = clientIdentifier,
            clientName = "Test Client",
            clientId = clientId.toString(),
            clientSecret = "valid_client_secret",
            clientType = "public",
            grantTypes = listOf("refresh_token"),
            scopes = listOf("read", "write"),
            redirectUris = listOf("https://example.com/callback")
        )

        given(oauthClientService.findByClientId(clientId.toString(), call))
            .willReturn(client)

        given(oauthTokenService.findByRefreshToken("valid_refresh_token", call))
            .willReturn(
                RefreshTokenDTO(
                    id = UUID.randomUUID(),
                    token = "valid_refresh_token",
                    clientId = clientIdentifier,
                    userId = userId,
                    scopes = client.scopes,
                    expiresAt = Instant.now().plusSeconds(3600),
                    revoked = false,
                    rotatedTo = null
                )
            )

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.accessTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.ACCESS_TOKEN,
            call = call
        )).willReturn(accessToken)

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.refreshTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.REFRESH_TOKEN,
            user = null,
            call = call
        )).willReturn(refreshToken)

        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "valid_refresh_token",
                "client_id" to clientId.toString(),
            ),
            call = call
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
    fun `generateTokens() returns token successfully with id_token when openid scope is present`() = runTest {
        val clientIdentifier = UUID.randomUUID()
        val clientId = UUID.randomUUID()
        val client = OAuthClientDTO(
            id = clientIdentifier,
            clientName = "Test Client",
            clientId = clientId.toString(),
            clientSecret = "valid_client_secret",
            clientType = "confidential",
            grantTypes = listOf("refresh_token"),
            scopes = listOf("openid", "profile", "email"),
            redirectUris = listOf("https://example.com/callback")
        )
        val accessToken = "generated_access_token"
        val refreshToken = "generated_refresh_token"
        val idToken = "generated_id_token"
        val userId = "user_1"

        given(oauthClientService.findByClientId(clientId.toString(), call))
            .willReturn(client)

        given(oauthTokenService.findByRefreshToken("valid_refresh_token", call))
            .willReturn(
                RefreshTokenDTO(
                    id = UUID.randomUUID(),
                    token = "valid_refresh_token",
                    clientId = clientIdentifier,
                    userId = userId,
                    scopes = client.scopes,
                    expiresAt = Instant.now().plusSeconds(3600),
                    revoked = false,
                    rotatedTo = null
                )
            )

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.accessTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.ACCESS_TOKEN,
            call = call
        )).willReturn(accessToken)

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.accessTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.ID_TOKEN,
            user = null,
            call = call
        )).willReturn(idToken)

        given(jwksProvider.generateJwt(
            subject = userId,
            audience = clientId.toString(),
            scopes = client.scopes,
            issuer = "https://example.com",
            expiresInSeconds = client.refreshTokenValidity,
            client = client,
            userId = userId,
            tokenType = TokenType.REFRESH_TOKEN,
            user = null,
            call = call
        )).willReturn(refreshToken)

        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "valid_refresh_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Success)
        val successResult = actual as Result.Success
        val response = successResult.outcome
        assertTrue(response.containsKey("access_token"))
        assertEquals(accessToken, response["access_token"])

        assertTrue(response.containsKey("refresh_token"))
        assertEquals(refreshToken, response["refresh_token"])

        assertTrue(response.containsKey("id_token"))
        assertEquals(idToken, response["id_token"])

        assertTrue(response["token_type"] == "bearer")
        assertTrue(response.containsKey("expires_in"))
        assertTrue(response.containsKey("scope"))
    }

    @Test
    fun `generateTokens() returns failure when refresh_token is missing`() = runTest {
        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "client_id" to "some_client_id",
                "client_secret" to "some_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Missing refresh_token"))
    }

    @Test
    fun `generateTokens() returns failure when client_id is missing`() = runTest {
        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "some_token",
                "client_secret" to "some_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Missing client_id"))
    }

    @Test
    fun `generateTokens() returns failure when client_id is invalid`() = runTest {
        given(oauthClientService.findByClientId("invalid_client_id", call))
            .willReturn(null)

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "some_token",
                "client_id" to "invalid_client_id"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Invalid client_id"))
    }

    @Test
    fun `generateTokens() returns failure when client_secret is missing for confidential client`() = runTest {
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
                    grantTypes = listOf("refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "some_token",
                "client_id" to clientId.toString()
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Missing client_secret"))
    }

    @Test
    fun `generateTokens() returns failure when client_secret is invalid`() = runTest {
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
                    grantTypes = listOf("refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "some_token",
                "client_id" to clientId.toString(),
                "client_secret" to "invalid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Unauthorized"))
    }

    @Test
    fun `generateTokens() returns failure when grant type is not permitted`() = runTest {
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
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "some_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Grant type not permitted"))
    }

    @Test
    fun `generateTokens() returns failure when refresh_token is invalid`() = runTest {
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
                    grantTypes = listOf("refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        given(oauthTokenService.findByRefreshToken("invalid_token", call))
            .willReturn(null)

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "invalid_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Invalid refresh_token"))
    }

    @Test
    fun `generateTokens() returns failure when client_id does not match refresh_token client_id`() = runTest {
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
                    grantTypes = listOf("refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        given(oauthTokenService.findByRefreshToken("valid_token", call))
            .willReturn(
                RefreshTokenDTO(
                    id = UUID.randomUUID(),
                    token = "valid_token",
                    clientId = mismatchedClientIdentifier,
                    userId = "user_1",
                    scopes = listOf("read", "write"),
                    expiresAt = Instant.now().plusSeconds(3600),
                    revoked = false,
                    rotatedTo = null
                )
            )

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "valid_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Unauthorized"))
    }

    @Test
    fun `generateTokens() returns failure when refresh_token is expired`() = runTest {
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
                    grantTypes = listOf("refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        given(oauthTokenService.findByRefreshToken("expired_token", call))
            .willReturn(
                RefreshTokenDTO(
                    id = UUID.randomUUID(),
                    token = "expired_token",
                    clientId = clientIdentifier,
                    userId = "user_1",
                    scopes = listOf("read", "write"),
                    expiresAt = Instant.now().minusSeconds(3600),
                    revoked = false,
                    rotatedTo = null
                )
            )

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "expired_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Expired or revoked token"))
    }

    @Test
    fun `generateTokens() returns failure when refresh_token is revoked`() = runTest {
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
                    grantTypes = listOf("refresh_token"),
                    scopes = listOf("read", "write"),
                    redirectUris = listOf("https://example.com/callback")
                )
            )

        given(oauthTokenService.findByRefreshToken("revoked_token", call))
            .willReturn(
                RefreshTokenDTO(
                    id = UUID.randomUUID(),
                    token = "revoked_token",
                    clientId = clientIdentifier,
                    userId = "user_1",
                    scopes = listOf("read", "write"),
                    expiresAt = Instant.now().plusSeconds(3600),
                    revoked = true,
                    rotatedTo = null
                )
            )

        val actual = refreshTokenGenerator.generateTokens(
            params = mapOf(
                "refresh_token" to "revoked_token",
                "client_id" to clientId.toString(),
                "client_secret" to "valid_client_secret"
            ),
            call = call
        )

        assertTrue(actual is Result.Failure)
        val failureResult = actual as Result.Failure
        val error = failureResult.errorBody
        assertTrue(error.containsKey("error"))
        assertTrue(error["error"].toString().contains("Expired or revoked token"))
    }
}
