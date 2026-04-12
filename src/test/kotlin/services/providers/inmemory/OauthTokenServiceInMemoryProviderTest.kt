package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.AccessTokenDTO
import com.bittokazi.ktor.auth.services.providers.RefreshTokenDTO
import io.ktor.server.application.ApplicationCall
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.time.Instant
import java.util.UUID

class OauthTokenServiceInMemoryProviderTest {

    private lateinit var provider: OauthTokenServiceInMemoryProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()
    private val accessTokenExpiresAt = Instant.now().plusSeconds(3600)
    private val refreshTokenExpiresAt = Instant.now().plusSeconds(86400)

    @Before
    fun setUp() {
        provider = OauthTokenServiceInMemoryProvider()
    }

    @Test
    fun `storeAccessToken adds token successfully`() {
        val result = provider.storeAccessToken(
            token = "access_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read", "write"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        assertTrue(result)
        assertEquals(1, provider.accessTokens.size)
        assertEquals("access_token_123", provider.accessTokens[0].token)
    }

    @Test
    fun `findByAccessToken returns token when exists`() {
        provider.storeAccessToken(
            token = "access_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        val result = provider.findByAccessToken("access_token_123", mockCall)
        assertNotNull(result)
        assertEquals("access_token_123", result?.token)
        assertEquals("user_1", result?.userId)
        assertFalse(result?.revoked ?: true)
    }

    @Test
    fun `findByAccessToken returns null when token not found`() {
        val result = provider.findByAccessToken("nonexistent_token", mockCall)
        assertNull(result)
    }

    @Test
    fun `revokeAccessToken sets revoked flag`() {
        provider.storeAccessToken(
            token = "access_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        val result = provider.revokeAccessToken("access_token_123", mockCall)
        assertTrue(result)
        assertTrue(provider.accessTokens[0].revoked)
    }

    @Test
    fun `storeRefreshToken adds refresh token and returns id`() {
        val id = provider.storeRefreshToken(
            token = "refresh_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read", "write"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        assertNotNull(id)
        assertEquals(1, provider.refreshTokens.size)
        assertEquals("refresh_token_123", provider.refreshTokens[0].token)
        assertEquals(id, provider.refreshTokens[0].id)
    }

    @Test
    fun `findByRefreshToken returns token when exists`() {
        provider.storeRefreshToken(
            token = "refresh_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val result = provider.findByRefreshToken("refresh_token_123", mockCall)
        assertNotNull(result)
        assertEquals("refresh_token_123", result?.token)
        assertEquals("user_1", result?.userId)
        assertFalse(result?.revoked ?: true)
    }

    @Test
    fun `findByRefreshToken returns null when token not found`() {
        val result = provider.findByRefreshToken("nonexistent_token", mockCall)
        assertNull(result)
    }

    @Test
    fun `revokeRefreshToken sets revoked flag`() {
        provider.storeRefreshToken(
            token = "refresh_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val result = provider.revokeRefreshToken("refresh_token_123", mockCall)
        assertTrue(result)
        assertTrue(provider.refreshTokens[0].revoked)
    }

    @Test
    fun `rotateRefreshToken creates new token and revokes old one`() {
        val oldTokenId = provider.storeRefreshToken(
            token = "refresh_token_old",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val result = provider.rotateRefreshToken(
            oldToken = "refresh_token_old",
            newToken = "refresh_token_new",
            expiresAt = refreshTokenExpiresAt.plusSeconds(3600),
            call = mockCall
        )

        assertTrue(result)
        assertEquals(2, provider.refreshTokens.size)

        // Old token should be revoked
        val oldToken = provider.refreshTokens.find { it.token == "refresh_token_old" }
        assertTrue(oldToken?.revoked ?: false)

        // New token should exist with reference to old token
        val newToken = provider.refreshTokens.find { it.token == "refresh_token_new" }
        assertNotNull(newToken)
        assertEquals(oldTokenId, newToken?.rotatedTo)
    }

    @Test
    fun `storeAccessToken with null userId`() {
        val result = provider.storeAccessToken(
            token = "client_credentials_token",
            clientId = clientId,
            userId = null,
            scopes = listOf("client_scope"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        assertTrue(result)
        assertNull(provider.accessTokens[0].userId)
    }

    @Test
    fun `storeRefreshToken with multiple scopes`() {
        provider.storeRefreshToken(
            token = "refresh_token_scopes",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("openid", "profile", "email", "offline_access"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val token = provider.refreshTokens[0]
        assertEquals(4, token.scopes.size)
        assertTrue(token.scopes.contains("offline_access"))
    }

    @Test
    fun `logoutAction completes without error`() {
        provider.logoutAction("user_1", clientId.toString(), mockCall)
        // No exception should be thrown
    }
}

