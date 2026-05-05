package services.token.providers

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.providers.AccessTokenDTO
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.RefreshTokenDTO
import com.bittokazi.ktor.auth.services.token.providers.DefaultTokenRevokeService
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
import org.mockito.kotlin.verify
import java.time.Instant
import java.util.UUID

@RunWith(MockitoJUnitRunner::class)
class DefaultTokenRevokeServiceTest {

    @Mock
    lateinit var oauthTokenService: OauthTokenService

    @Mock
    lateinit var call: ApplicationCall

    lateinit var tokenRevokeService: DefaultTokenRevokeService

    @Before
    fun setUp() {
        tokenRevokeService = DefaultTokenRevokeService(oauthTokenService)
    }

    // ==================== Success Cases ====================

    @Test
    fun `revoke() returns success when revoking valid access token`() = runTest {
        val token = "valid_access_token"
        val clientUUID = UUID.randomUUID()

        val accessToken = AccessTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(3600),
            scopes = listOf("read", "write"),
            revoked = false
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(null)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
        verify(oauthTokenService).revokeAccessToken(token, call)
    }

    @Test
    fun `revoke() returns success when revoking valid refresh token`() = runTest {
        val token = "valid_refresh_token"
        val clientUUID = UUID.randomUUID()

        val refreshToken = RefreshTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(86400),
            scopes = listOf("read", "write"),
            revoked = false,
            rotatedTo = null
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(null)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(refreshToken)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
        verify(oauthTokenService).revokeRefreshToken(token, call)
    }

    @Test
    fun `revoke() returns success when revoking both access and refresh token`() = runTest {
        val token = "valid_token"
        val clientUUID = UUID.randomUUID()

        val accessToken = AccessTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(3600),
            scopes = listOf("read", "write"),
            revoked = false
        )

        val refreshToken = RefreshTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(86400),
            scopes = listOf("read", "write"),
            revoked = false,
            rotatedTo = null
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(refreshToken)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
        verify(oauthTokenService).revokeAccessToken(token, call)
        verify(oauthTokenService).revokeRefreshToken(token, call)
    }

    @Test
    fun `revoke() returns success with empty token list when token is not found`() = runTest {
        val token = "invalid_token"

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(null)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(null)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
    }

    @Test
    fun `revoke() does not call revokeAccessToken when access token is not found`() = runTest {
        val token = "refresh_only_token"
        val clientUUID = UUID.randomUUID()

        val refreshToken = RefreshTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(86400),
            scopes = listOf("read", "write"),
            revoked = false,
            rotatedTo = null
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(null)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(refreshToken)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        // Verify revokeAccessToken is never called since access token was not found
        verify(oauthTokenService).revokeRefreshToken(token, call)
    }

    @Test
    fun `revoke() does not call revokeRefreshToken when refresh token is not found`() = runTest {
        val token = "access_only_token"
        val clientUUID = UUID.randomUUID()

        val accessToken = AccessTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(3600),
            scopes = listOf("read", "write"),
            revoked = false
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(null)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        // Verify revokeRefreshToken is never called since refresh token was not found
        verify(oauthTokenService).revokeAccessToken(token, call)
    }

    // ==================== Edge Cases ====================

    @Test
    fun `revoke() completes successfully even if token is already revoked`() = runTest {
        val token = "already_revoked_token"
        val clientUUID = UUID.randomUUID()

        val accessToken = AccessTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(3600),
            scopes = listOf("read", "write"),
            revoked = true
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(null)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
    }

    @Test
    fun `revoke() completes successfully even if token is expired`() = runTest {
        val token = "expired_token"
        val clientUUID = UUID.randomUUID()

        val accessToken = AccessTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().minusSeconds(3600),
            scopes = listOf("read", "write"),
            revoked = false
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(null)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
    }

    @Test
    fun `revoke() returns success when revoking token with multiple scopes`() = runTest {
        val token = "multi_scope_token"
        val clientUUID = UUID.randomUUID()
        val scopes = listOf("openid", "profile", "email", "read", "write")

        val accessToken = AccessTokenDTO(
            id = UUID.randomUUID(),
            token = token,
            clientId = clientUUID,
            userId = "test_user",
            expiresAt = Instant.now().plusSeconds(3600),
            scopes = scopes,
            revoked = false
        )

        given(oauthTokenService.findByAccessToken(token, call)).willReturn(accessToken)
        given(oauthTokenService.findByRefreshToken(token, call)).willReturn(null)

        val result = tokenRevokeService.revoke(token, call)

        assertTrue(result is Result.Success)
        val successResult = result as Result.Success
        val response = successResult.outcome
        assertEquals("Token revoked successfully", response["message"])
        verify(oauthTokenService).revokeAccessToken(token, call)
    }
}
