package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeDTO
import io.ktor.server.application.ApplicationCall
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import java.time.Instant
import java.util.UUID

class OauthDeviceCodeServiceInMemoryProviderTest {

    private lateinit var provider: OauthDeviceCodeServiceInMemoryProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()
    private val expiresAt = Instant.now().plusSeconds(600)

    @Before
    fun setUp() {
        provider = OauthDeviceCodeServiceInMemoryProvider()
    }

    @Test
    fun `createCode adds device code successfully`() {
        val result = provider.createCode(
            clientId = clientId,
            scopes = listOf("read", "write"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        assertTrue(result)
        assertEquals(1, provider.codes.size)
        assertEquals("DEVICE_CODE_123", provider.codes[0].deviceCode)
        assertEquals("USER_CODE_ABC", provider.codes[0].userCode)
        assertFalse(provider.codes[0].consumed)
        assertFalse(provider.codes[0].isDeviceAuthorized)
    }

    @Test
    fun `findByUserCode returns code when not authorized and not consumed`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        val result = provider.findByUserCode("USER_CODE_ABC", mockCall)
        assertNotNull(result)
        assertEquals("USER_CODE_ABC", result?.userCode)
    }

    @Test
    fun `findByUserCode returns null when authorized`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )
        provider.authorizeDevice("DEVICE_CODE_123", "user_1", mockCall)

        val result = provider.findByUserCode("USER_CODE_ABC", mockCall)
        assertNull(result)
    }

    @Test
    fun `findByUserCode returns null when consumed`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )
        provider.consumeDeviceCode("DEVICE_CODE_123", mockCall)

        val result = provider.findByUserCode("USER_CODE_ABC", mockCall)
        assertNull(result)
    }

    @Test
    fun `findByDeviceCode returns code with correct status`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        val result = provider.findByDeviceCode("USER_CODE_ABC", false, false, mockCall)
        assertNotNull(result)
        assertFalse(result?.isDeviceAuthorized ?: true)
        assertFalse(result?.consumed ?: true)
    }

    @Test
    fun `findByDeviceCode returns null when status doesn't match`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        val result = provider.findByDeviceCode("USER_CODE_ABC", true, false, mockCall)
        assertNull(result)
    }

    @Test
    fun `consumeDeviceCode sets consumed flag`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        val result = provider.consumeDeviceCode("DEVICE_CODE_123", mockCall)
        assertTrue(result)
        assertTrue(provider.codes[0].consumed)
    }

    @Test
    fun `authorizeDevice sets userId and authorization flag`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        val result = provider.authorizeDevice("DEVICE_CODE_123", "user_1", mockCall)
        assertTrue(result)
        assertEquals("user_1", provider.codes[0].userId)
        assertTrue(provider.codes[0].isDeviceAuthorized)
    }

    @Test
    fun `createCode with multiple scopes`() {
        val scopes = listOf("openid", "profile", "email", "offline_access")
        provider.createCode(
            clientId = clientId,
            scopes = scopes,
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_123",
            userCode = "USER_CODE_ABC"
        )

        val code = provider.codes[0]
        assertEquals(4, code.scopes.size)
        assertTrue(code.scopes.containsAll(scopes))
    }

    @Test
    fun `consumeDeviceCode on nonexistent code returns true`() {
        val result = provider.consumeDeviceCode("NONEXISTENT", mockCall)
        assertTrue(result)
    }

    @Test
    fun `authorizeDevice on nonexistent code returns true`() {
        val result = provider.authorizeDevice("NONEXISTENT", "user_1", mockCall)
        assertTrue(result)
    }

    @Test
    fun `logoutAction completes without error`() {
        provider.logoutAction("user_1", clientId.toString(), mockCall)
        // No exception should be thrown
    }

    @Test
    fun `multiple device codes can coexist`() {
        provider.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_1",
            userCode = "USER_CODE_A"
        )
        provider.createCode(
            clientId = clientId,
            scopes = listOf("write"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = "DEVICE_CODE_2",
            userCode = "USER_CODE_B"
        )

        assertEquals(2, provider.codes.size)
        val code1 = provider.codes.find { it.deviceCode == "DEVICE_CODE_1" }
        val code2 = provider.codes.find { it.deviceCode == "DEVICE_CODE_2" }

        assertNotNull(code1)
        assertNotNull(code2)
        assertEquals("USER_CODE_A", code1?.userCode)
        assertEquals("USER_CODE_B", code2?.userCode)
    }
}

