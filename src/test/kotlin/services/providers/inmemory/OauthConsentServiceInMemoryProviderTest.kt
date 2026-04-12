package com.bittokazi.ktor.auth.services.providers.inmemory

import io.ktor.server.application.ApplicationCall
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.util.UUID

class OauthConsentServiceInMemoryProviderTest {

    private lateinit var provider: OauthConsentServiceInMemoryProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()

    @Before
    fun setUp() {
        provider = OauthConsentServiceInMemoryProvider()
    }

    @Test
    fun `grantConsent adds consent successfully`() {
        val result = provider.grantConsent(
            userId = "user_1",
            clientId = clientId,
            scopes = listOf("read", "write"),
            call = mockCall
        )

        assertTrue(result)
    }

    @Test
    fun `getConsent returns scopes after granting consent`() {
        val scopes = listOf("openid", "profile", "email")
        provider.grantConsent(
            userId = "user_1",
            clientId = clientId,
            scopes = scopes,
            call = mockCall
        )

        val result = provider.getConsent("user_1", clientId, mockCall)
        assertNotNull(result)
        assertEquals(3, result?.size)
        assertTrue(result?.containsAll(scopes) ?: false)
    }

    @Test
    fun `getConsent returns null when consent not granted`() {
        val result = provider.getConsent("user_1", clientId, mockCall)
        assertNull(result)
    }

    @Test
    fun `getConsent returns null for wrong user`() {
        provider.grantConsent(
            userId = "user_1",
            clientId = clientId,
            scopes = listOf("read"),
            call = mockCall
        )

        val result = provider.getConsent("user_2", clientId, mockCall)
        assertNull(result)
    }

    @Test
    fun `getConsent returns null for wrong client`() {
        provider.grantConsent(
            userId = "user_1",
            clientId = clientId,
            scopes = listOf("read"),
            call = mockCall
        )

        val result = provider.getConsent("user_1", UUID.randomUUID(), mockCall)
        assertNull(result)
    }

    @Test
    fun `grantConsent replaces existing consent for same user and client`() {
        val oldScopes = listOf("read")
        val newScopes = listOf("write", "admin")

        provider.grantConsent("user_1", clientId, oldScopes, mockCall)
        provider.grantConsent("user_1", clientId, newScopes, mockCall)

        val result = provider.getConsent("user_1", clientId, mockCall)
        assertEquals(2, result?.size)
        assertTrue(result?.containsAll(newScopes) ?: false)
        assertFalse(result?.contains("read") ?: false)
    }

    @Test
    fun `multiple users can have consent for same client`() {
        val clientId = UUID.randomUUID()

        provider.grantConsent("user_1", clientId, listOf("read"), mockCall)
        provider.grantConsent("user_2", clientId, listOf("write"), mockCall)

        val result1 = provider.getConsent("user_1", clientId, mockCall)
        val result2 = provider.getConsent("user_2", clientId, mockCall)

        assertEquals(1, result1?.size)
        assertEquals("read", result1?.get(0))
        assertEquals(1, result2?.size)
        assertEquals("write", result2?.get(0))
    }

    @Test
    fun `same user can have consent for multiple clients`() {
        val client1 = UUID.randomUUID()
        val client2 = UUID.randomUUID()

        provider.grantConsent("user_1", client1, listOf("read"), mockCall)
        provider.grantConsent("user_1", client2, listOf("write"), mockCall)

        val result1 = provider.getConsent("user_1", client1, mockCall)
        val result2 = provider.getConsent("user_1", client2, mockCall)

        assertEquals("read", result1?.get(0))
        assertEquals("write", result2?.get(0))
    }

    @Test
    fun `grantConsent with empty scopes list`() {
        provider.grantConsent("user_1", clientId, emptyList(), mockCall)

        val result = provider.getConsent("user_1", clientId, mockCall)
        assertNotNull(result)
        assertEquals(0, result?.size)
    }

    @Test
    fun `grantConsent with all common OAuth scopes`() {
        val commonScopes = listOf("openid", "profile", "email", "address", "phone", "offline_access")
        provider.grantConsent("user_1", clientId, commonScopes, mockCall)

        val result = provider.getConsent("user_1", clientId, mockCall)
        assertEquals(6, result?.size)
        assertTrue(result?.containsAll(commonScopes) ?: false)
    }

    @Test
    fun `grantConsent returns true`() {
        val result = provider.grantConsent("user_1", clientId, listOf("read"), mockCall)
        assertTrue(result)
    }

    @Test
    fun `multiple consecutive consents for same user and client`() {
        provider.grantConsent("user_1", clientId, listOf("read"), mockCall)
        val result1 = provider.getConsent("user_1", clientId, mockCall)

        provider.grantConsent("user_1", clientId, listOf("write"), mockCall)
        val result2 = provider.getConsent("user_1", clientId, mockCall)

        // After first grant
        assertEquals(1, result1?.size)
        assertEquals("read", result1?.get(0))

        // After second grant (should replace)
        assertEquals(1, result2?.size)
        assertEquals("write", result2?.get(0))
    }
}

