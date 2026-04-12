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

class OauthAuthorizationCodeServiceDatabaseProviderTest {

    private lateinit var databaseConfiguration: TestOauthDatabaseConfiguration
    private lateinit var codeService: OauthAuthorizationCodeServiceDatabaseProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()
    private val expiresAt = Instant.now().plusSeconds(3600)

    @Before
    fun setUp() {
        databaseConfiguration = TestOauthDatabaseConfiguration()
        codeService = OauthAuthorizationCodeServiceDatabaseProvider(databaseConfiguration)
    }

    @After
    fun tearDown() {
        databaseConfiguration.stop()
    }

    @Test
    fun `createCode successfully creates authorization code`() {
        val result = codeService.createCode(
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
        val retrieved = codeService.findByCode("auth_code_123", mockCall)
        assertNotNull(retrieved)
        assertEquals("auth_code_123", retrieved?.code)
        assertEquals("user_1", retrieved?.userId)
    }

    @Test
    fun `findByCode returns code when exists`() {
        codeService.createCode(
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

        val result = codeService.findByCode("auth_code_123", mockCall)
        assertNotNull(result)
        assertEquals("auth_code_123", result?.code)
        assertEquals("user_1", result?.userId)
        assertEquals(clientId, result?.clientId)
        assertEquals("https://example.com/callback", result?.redirectUri)
        assertFalse(result?.consumed ?: true)
    }

    @Test
    fun `findByCode returns null when code not found`() {
        val result = codeService.findByCode("nonexistent", mockCall)
        assertNull(result)
    }

    @Test
    fun `consumeCode marks code as consumed`() {
        codeService.createCode(
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

        val consumeResult = codeService.consumeCode("auth_code_123", mockCall)
        assertTrue(consumeResult)

        val retrieved = codeService.findByCode("auth_code_123", mockCall)
        assertTrue(retrieved?.consumed ?: false)
    }

    @Test
    fun `consumeCode returns false when code not found`() {
        val result = codeService.consumeCode("nonexistent", mockCall)
        assertFalse(result)
    }

    @Test
    fun `createCode with PKCE stores challenge and method`() {
        val codeChallenge = "E9Mrozoa2owUednMd1jWfJM5CKvbZ5X4P8f7sB5gdk"
        codeService.createCode(
            code = "auth_code_pkce",
            clientId = clientId,
            userId = "user_1",
            redirectUri = "https://example.com/callback",
            scopes = listOf("read"),
            expiresAt = expiresAt,
            challenge = codeChallenge,
            challengeMethod = "S256",
            call = mockCall
        )

        val result = codeService.findByCode("auth_code_pkce", mockCall)
        assertEquals(codeChallenge, result?.codeChallenge)
        assertEquals("S256", result?.codeChallengeMethod)
    }

    @Test
    fun `createCode with multiple scopes`() {
        val scopes = listOf("openid", "profile", "email")
        codeService.createCode(
            code = "auth_code_scopes",
            clientId = clientId,
            userId = "user_1",
            redirectUri = "https://example.com/callback",
            scopes = scopes,
            expiresAt = expiresAt,
            challenge = null,
            challengeMethod = null,
            call = mockCall
        )

        val result = codeService.findByCode("auth_code_scopes", mockCall)
        assertEquals(3, result?.scopes?.size)
        assertTrue(result?.scopes?.containsAll(scopes) ?: false)
    }

    @Test
    fun `multiple codes can be created independently`() {
        for (i in 1..3) {
            codeService.createCode(
                code = "code_$i",
                clientId = clientId,
                userId = "user_$i",
                redirectUri = "https://example.com/callback",
                scopes = listOf("read"),
                expiresAt = expiresAt,
                challenge = null,
                challengeMethod = null,
                call = mockCall
            )
        }

        for (i in 1..3) {
            val code = codeService.findByCode("code_$i", mockCall)
            assertNotNull(code)
            assertEquals("user_$i", code?.userId)
        }
    }

    @Test
    fun `consumeCode does not affect other codes`() {
        codeService.createCode(
            code = "code_1",
            clientId = clientId,
            userId = "user_1",
            redirectUri = "https://example.com/callback",
            scopes = listOf("read"),
            expiresAt = expiresAt,
            challenge = null,
            challengeMethod = null,
            call = mockCall
        )

        codeService.createCode(
            code = "code_2",
            clientId = clientId,
            userId = "user_2",
            redirectUri = "https://example.com/callback",
            scopes = listOf("write"),
            expiresAt = expiresAt,
            challenge = null,
            challengeMethod = null,
            call = mockCall
        )

        codeService.consumeCode("code_1", mockCall)

        val code1 = codeService.findByCode("code_1", mockCall)
        val code2 = codeService.findByCode("code_2", mockCall)

        assertTrue(code1?.consumed ?: false)
        assertFalse(code2?.consumed ?: true)
    }

    @Test
    fun `logoutAction completes without error`() {
        codeService.logoutAction("user_1", clientId.toString(), mockCall)
        // No exception should be thrown
    }
}
