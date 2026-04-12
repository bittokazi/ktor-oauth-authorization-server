package com.bittokazi.ktor.auth.services.providers.inmemory

import org.junit.Test
import org.junit.Assert.*
import org.mockito.Mockito
import io.ktor.server.application.ApplicationCall
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO

class OauthUserServiceInMemoryProviderTest {

    private val mockCall = Mockito.mock(ApplicationCall::class.java)

    @Test
    fun `findByUsername returns user when exists`() {
        val user = OAuthUserDTO("1", "testuser", "test@example.com", "Test", "User", true)
        val provider = OauthUserServiceInMemoryProvider(mutableListOf(user))
        val result = provider.findByUsername("testuser", mockCall)
        assertNotNull(result)
        assertEquals("testuser", result?.username)
    }

    @Test
    fun `findByUsername returns null when not exists`() {
        val provider = OauthUserServiceInMemoryProvider(mutableListOf())
        val result = provider.findByUsername("nonexistent", mockCall)
        assertNull(result)
    }

    @Test
    fun `findById returns user when exists`() {
        val user = OAuthUserDTO("1", "testuser", "test@example.com", "Test", "User", true)
        val provider = OauthUserServiceInMemoryProvider(mutableListOf(user))
        val result = provider.findById("1", mockCall)
        assertNotNull(result)
        assertEquals("1", result?.id)
    }

    @Test
    fun `findById returns null when not exists`() {
        val provider = OauthUserServiceInMemoryProvider(mutableListOf())
        val result = provider.findById("999", mockCall)
        assertNull(result)
    }
}
