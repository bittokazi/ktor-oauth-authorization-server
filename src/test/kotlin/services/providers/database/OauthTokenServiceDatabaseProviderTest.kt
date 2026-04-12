package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.config.TestOauthDatabaseConfiguration
import io.ktor.server.application.ApplicationCall
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import org.mockito.Mockito
import java.time.Instant
import java.util.UUID

class OauthTokenServiceDatabaseProviderTest {

    private lateinit var databaseConfiguration: TestOauthDatabaseConfiguration
    private lateinit var tokenService: OauthTokenServiceDatabaseProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()
    private val accessTokenExpiresAt = Instant.now().plusSeconds(3600)
    private val refreshTokenExpiresAt = Instant.now().plusSeconds(86400)

    @Before
    fun setUp() {
        databaseConfiguration = TestOauthDatabaseConfiguration()
        tokenService = OauthTokenServiceDatabaseProvider(databaseConfiguration)
    }

    @After
    fun tearDown() {
        databaseConfiguration.stop()
    }

    @Test
    fun `storeAccessToken successfully stores token`() {
        val result = tokenService.storeAccessToken(
            token = "access_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read", "write"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        assertTrue(result)
        val retrieved = tokenService.findByAccessToken("access_token_123", mockCall)
        assertNotNull(retrieved)
        assertEquals("access_token_123", retrieved?.token)
    }

    @Test
    fun `findByAccessToken returns token when exists`() {
        tokenService.storeAccessToken(
            token = "access_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        val result = tokenService.findByAccessToken("access_token_123", mockCall)
        assertNotNull(result)
        assertEquals("access_token_123", result?.token)
        assertEquals("user_1", result?.userId)
        assertEquals(clientId, result?.clientId)
        assertFalse(result?.revoked ?: true)
    }

    @Test
    fun `findByAccessToken returns null when token not found`() {
        val result = tokenService.findByAccessToken("nonexistent", mockCall)
        assertNull(result)
    }

    @Test
    fun `revokeAccessToken sets revoked flag`() {
        tokenService.storeAccessToken(
            token = "access_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        val revokeResult = tokenService.revokeAccessToken("access_token_123", mockCall)
        assertTrue(revokeResult)

        val retrieved = tokenService.findByAccessToken("access_token_123", mockCall)
        assertTrue(retrieved?.revoked ?: false)
    }

    @Test
    fun `storeRefreshToken successfully stores token and returns UUID`() {
        val tokenId = tokenService.storeRefreshToken(
            token = "refresh_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read", "write"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        assertNotNull(tokenId)
        val retrieved = tokenService.findByRefreshToken("refresh_token_123", mockCall)
        assertEquals(tokenId, retrieved?.id)
    }

    @Test
    fun `findByRefreshToken returns token when exists`() {
        tokenService.storeRefreshToken(
            token = "refresh_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val result = tokenService.findByRefreshToken("refresh_token_123", mockCall)
        assertNotNull(result)
        assertEquals("refresh_token_123", result?.token)
        assertEquals("user_1", result?.userId)
        assertFalse(result?.revoked ?: true)
    }

    @Test
    fun `findByRefreshToken returns null when token not found`() {
        val result = tokenService.findByRefreshToken("nonexistent", mockCall)
        assertNull(result)
    }

    @Test
    fun `revokeRefreshToken sets revoked flag`() {
        tokenService.storeRefreshToken(
            token = "refresh_token_123",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val revokeResult = tokenService.revokeRefreshToken("refresh_token_123", mockCall)
        assertTrue(revokeResult)

        val retrieved = tokenService.findByRefreshToken("refresh_token_123", mockCall)
        assertTrue(retrieved?.revoked ?: false)
    }

    @Test
    fun `rotateRefreshToken creates new token and revokes old`() {
        val oldTokenId = tokenService.storeRefreshToken(
            token = "refresh_token_old",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = refreshTokenExpiresAt,
            call = mockCall
        )

        val rotateResult = tokenService.rotateRefreshToken(
            oldToken = "refresh_token_old",
            newToken = "refresh_token_new",
            expiresAt = refreshTokenExpiresAt.plusSeconds(3600),
            call = mockCall
        )

        assertTrue(rotateResult)

        // Old token should be revoked
        val oldToken = tokenService.findByRefreshToken("refresh_token_old", mockCall)
        assertTrue(oldToken?.revoked ?: false)

        // New token should exist with rotatedTo reference
        val newToken = tokenService.findByRefreshToken("refresh_token_new", mockCall)
        assertNotNull(newToken)
        assertEquals(oldToken?.rotatedTo, newToken?.id)
    }

    @Test
    fun `storeAccessToken with null userId for client credentials`() {
        val result = tokenService.storeAccessToken(
            token = "client_token",
            clientId = clientId,
            userId = null,
            scopes = listOf("client_scope"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        assertTrue(result)
        val retrieved = tokenService.findByAccessToken("client_token", mockCall)
        assertNull(retrieved?.userId)
    }

    @Test
    fun `multiple access tokens can be stored and retrieved`() {
        for (i in 1..3) {
            tokenService.storeAccessToken(
                token = "access_token_$i",
                clientId = clientId,
                userId = "user_$i",
                scopes = listOf("read"),
                expiresAt = accessTokenExpiresAt,
                call = mockCall
            )
        }

        for (i in 1..3) {
            val token = tokenService.findByAccessToken("access_token_$i", mockCall)
            assertNotNull(token)
            assertEquals("user_$i", token?.userId)
        }
    }

    @Test
    fun `revoking one token does not affect others`() {
        tokenService.storeAccessToken(
            token = "access_token_1",
            clientId = clientId,
            userId = "user_1",
            scopes = listOf("read"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        tokenService.storeAccessToken(
            token = "access_token_2",
            clientId = clientId,
            userId = "user_2",
            scopes = listOf("write"),
            expiresAt = accessTokenExpiresAt,
            call = mockCall
        )

        tokenService.revokeAccessToken("access_token_1", mockCall)

        val token1 = tokenService.findByAccessToken("access_token_1", mockCall)
        val token2 = tokenService.findByAccessToken("access_token_2", mockCall)

        assertTrue(token1?.revoked ?: false)
        assertFalse(token2?.revoked ?: true)
    }

    @Test
    fun `logoutAction completes without error`() {
        tokenService.logoutAction("user_1", clientId.toString(), mockCall)
        // No exception should be thrown
    }
}
