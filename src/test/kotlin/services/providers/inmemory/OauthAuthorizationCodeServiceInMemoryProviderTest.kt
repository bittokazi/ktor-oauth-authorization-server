package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.AuthorizationCodeDTO
import io.ktor.server.application.ApplicationCall
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.time.Instant
import java.util.UUID

class OauthAuthorizationCodeServiceInMemoryProviderTest {

    private lateinit var provider: OauthAuthorizationCodeServiceInMemoryProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()
    private val expiresAt = Instant.now().plusSeconds(3600)

    @Before
    fun setUp() {
        provider = OauthAuthorizationCodeServiceInMemoryProvider()
    }

    @Test
    fun `createCode adds authorization code successfully`() {
        val result = provider.createCode(
            code = "auth_code_123",
            clientId = clientId,
            userId = "user_1",
            redirectUri = "https://example.com/callback",
            scopes = listOf("read", "write"),
            expiresAt = expiresAt,
            challenge = "challenge_value",
            challengeMethod = "S256",
            call = mockCall
        )

        assertTrue(result)
        assertEquals(1, provider.codes.size)
        assertEquals("auth_code_123", provider.codes[0].code)
    }

    @Test
    fun `findByCode returns authorization code when exists`() {
        provider.createCode(
            code = "auth_code_123",
            clientId = clientId,
            userId = "user_1",
            redirectUri = "https://example.com/callback",
            scopes = listOf("read"),
            expiresAt = expiresAt,
            challenge = null,
            challengeMethod = null,
            call = mockCall
        )

        val result = provider.findByCode("auth_code_123", mockCall)
        assertNotNull(result)
        assertEquals("auth_code_123", result?.code)
        assertEquals("user_1", result?.userId)
    }

    @Test
    fun `findByCode returns null when code not found`() {
        val result = provider.findByCode("nonexistent_code", mockCall)
        assertNull(result)
    }

    @Test
    fun `consumeCode returns consumed status of code`() {
        provider.createCode(
            code = "auth_code_123",
            clientId = clientId,
            userId = "user_1",
            redirectUri = "https://example.com/callback",
            scopes = listOf("read"),
            expiresAt = expiresAt,
            challenge = null,
            challengeMethod = null,
            call = mockCall
        )

        // New codes are created with consumed = false
        val result = provider.consumeCode("auth_code_123", mockCall)
        assertFalse(result)
    }

    @Test
    fun `consumeCode returns true when code not found`() {
        val result = provider.consumeCode("nonexistent_code", mockCall)
        assertTrue(result)
    }

    @Test
    fun `createCode stores code with all parameters`() {
        provider.createCode(
            code = "code_with_pkce",
            clientId = clientId,
            userId = "user_2",
            redirectUri = "https://app.example.com/auth",
            scopes = listOf("openid", "profile", "email"),
            expiresAt = expiresAt,
            challenge = "E9Mrozoa2owUednMd1jWfJM5CKvbZ5X4P8f7sB5gdk",
            challengeMethod = "S256",
            call = mockCall
        )

        val code = provider.codes[0]
        assertEquals("code_with_pkce", code.code)
        assertEquals(clientId, code.clientId)
        assertEquals("user_2", code.userId)
        assertEquals("E9Mrozoa2owUednMd1jWfJM5CKvbZ5X4P8f7sB5gdk", code.codeChallenge)
        assertEquals("S256", code.codeChallengeMethod)
        assertEquals(3, code.scopes.size)
    }

    @Test
    fun `logoutAction completes without error`() {
        provider.logoutAction("user_1", clientId.toString(), mockCall)
        // No exception should be thrown
    }
}

