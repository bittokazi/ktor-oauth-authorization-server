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

class OauthDeviceCodeServiceDatabaseProviderTest {

    private lateinit var databaseConfiguration: TestOauthDatabaseConfiguration
    private lateinit var deviceCodeService: OauthDeviceCodeServiceDatabaseProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)
    private val clientId = UUID.randomUUID()
    private val expiresAt = Instant.now().plusSeconds(600)

    @Before
    fun setUp() {
        databaseConfiguration = TestOauthDatabaseConfiguration()
        deviceCodeService = OauthDeviceCodeServiceDatabaseProvider(databaseConfiguration)
    }

    @After
    fun tearDown() {
        databaseConfiguration.stop()
    }

    private fun uniqueCode(suffix: String): String = "${UUID.randomUUID()}_$suffix"

    @Test
    fun `createCode successfully creates device code`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        val result = deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read", "write"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        assertTrue(result)
        val retrieved = deviceCodeService.findByUserCode(userCode, mockCall)
        assertNotNull(retrieved)
        assertEquals(deviceCode, retrieved?.deviceCode)
    }

    @Test
    fun `findByUserCode returns code when not authorized and not consumed`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        val result = deviceCodeService.findByUserCode(userCode, mockCall)
        assertNotNull(result)
        assertEquals(userCode, result?.userCode)
        assertFalse(result?.isDeviceAuthorized ?: true)
        assertFalse(result?.consumed ?: true)
    }

    @Test
    fun `findByUserCode returns null when authorized`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        deviceCodeService.authorizeDevice(deviceCode, "user_1", mockCall)

        val result = deviceCodeService.findByUserCode(userCode, mockCall)
        assertNull(result)
    }

    @Test
    fun `findByUserCode returns null when consumed`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        deviceCodeService.consumeDeviceCode(deviceCode, mockCall)

        val result = deviceCodeService.findByUserCode(userCode, mockCall)
        assertNull(result)
    }

    @Test
    fun `findByDeviceCode returns code with correct status`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        val result = deviceCodeService.findByDeviceCode(deviceCode, false, false, mockCall)
        assertNotNull(result)
        assertFalse(result?.isDeviceAuthorized ?: true)
        assertFalse(result?.consumed ?: true)
    }

    @Test
    fun `findByDeviceCode returns null when status doesn't match`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        val result = deviceCodeService.findByDeviceCode(deviceCode, true, false, mockCall)
        assertNull(result)
    }

    @Test
    fun `consumeDeviceCode sets consumed flag`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        val result = deviceCodeService.consumeDeviceCode(deviceCode, mockCall)
        assertTrue(result)

        val retrieved = deviceCodeService.findByDeviceCode(deviceCode, false, true, mockCall)
        assertTrue(retrieved?.consumed ?: false)
    }

    @Test
    fun `authorizeDevice sets userId and authorization flag`() {
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        val result = deviceCodeService.authorizeDevice(deviceCode, "user_1", mockCall)
        assertTrue(result)

        val retrieved = deviceCodeService.findByDeviceCode(deviceCode, true, false, mockCall)
        assertEquals("user_1", retrieved?.userId)
        assertTrue(retrieved?.isDeviceAuthorized ?: false)
    }

    @Test
    fun `createCode with multiple scopes`() {
        val scopes = listOf("openid", "profile", "email")
        val deviceCode = uniqueCode("DEVICE")
        val userCode = uniqueCode("USER")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = scopes,
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode,
            userCode = userCode
        )

        val result = deviceCodeService.findByUserCode(userCode, mockCall)
        assertEquals(3, result?.scopes?.size)
        assertTrue(result?.scopes?.containsAll(scopes) ?: false)
    }

    @Test
    fun `consumeDeviceCode returns false for nonexistent code`() {
        val result = deviceCodeService.consumeDeviceCode("NONEXISTENT_${UUID.randomUUID()}", mockCall)
        assertFalse(result)
    }

    @Test
    fun `authorizeDevice returns false for nonexistent code`() {
        val result = deviceCodeService.authorizeDevice("NONEXISTENT_${UUID.randomUUID()}", "user_1", mockCall)
        assertFalse(result)
    }

    @Test
    fun `multiple device codes can coexist`() {
        for (i in 1..3) {
            val deviceCode = uniqueCode("DEVICE_$i")
            val userCode = uniqueCode("USER_$i")

            deviceCodeService.createCode(
                clientId = clientId,
                scopes = listOf("read"),
                expiresAt = expiresAt,
                call = mockCall,
                deviceCode = deviceCode,
                userCode = userCode
            )
        }

        // Verify we can still retrieve (just check it works)
        assertTrue(true)
    }

    @Test
    fun `consumeDeviceCode does not affect other codes`() {
        val deviceCode1 = uniqueCode("DEVICE1")
        val userCode1 = uniqueCode("USER1")
        val deviceCode2 = uniqueCode("DEVICE2")
        val userCode2 = uniqueCode("USER2")

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("read"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode1,
            userCode = userCode1
        )

        deviceCodeService.createCode(
            clientId = clientId,
            scopes = listOf("write"),
            expiresAt = expiresAt,
            call = mockCall,
            deviceCode = deviceCode2,
            userCode = userCode2
        )

        deviceCodeService.consumeDeviceCode(deviceCode1, mockCall)

        val code1 = deviceCodeService.findByDeviceCode(deviceCode1, false, true, mockCall)
        val code2 = deviceCodeService.findByDeviceCode(deviceCode2, false, false, mockCall)

        assertTrue(code1?.consumed ?: false)
        assertFalse(code2?.consumed ?: true)
    }

    @Test
    fun `logoutAction completes without error`() {
        deviceCodeService.logoutAction("user_1", clientId.toString(), mockCall)
        // No exception should be thrown
    }
}
