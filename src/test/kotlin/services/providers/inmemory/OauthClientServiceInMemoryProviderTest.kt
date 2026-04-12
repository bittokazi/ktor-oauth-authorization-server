package com.bittokazi.ktor.auth.services.providers.inmemory

import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import io.ktor.server.application.ApplicationCall
import org.junit.Assert.*
import org.junit.Test
import org.mockito.Mockito
import java.util.UUID

class OauthClientServiceInMemoryProviderTest {

    private val mockCall = Mockito.mock(ApplicationCall::class.java)

    @Test
    fun `findByClientId returns client when exists`() {
        val client1 = OAuthClientDTO(
            id = UUID.randomUUID(),
            clientId = "client_1",
            clientName = "Client One",
            clientType = "public",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read", "write"),
            grantTypes = listOf("authorization_code")
        )
        val provider = OauthClientServiceInMemoryProvider(mutableListOf(client1))

        val result = provider.findByClientId("client_1", mockCall)
        assertNotNull(result)
        assertEquals("client_1", result?.clientId)
        assertEquals("Client One", result?.clientName)
    }

    @Test
    fun `findByClientId returns null when not found`() {
        val client1 = OAuthClientDTO(
            id = UUID.randomUUID(),
            clientId = "client_1",
            clientName = "Client One",
            clientType = "public",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code")
        )
        val provider = OauthClientServiceInMemoryProvider(mutableListOf(client1))

        val result = provider.findByClientId("nonexistent", mockCall)
        assertNull(result)
    }

    @Test
    fun `findDefaultClient returns first client as default`() {
        val client1 = OAuthClientDTO(
            id = UUID.randomUUID(),
            clientId = "client_1",
            clientName = "Client One",
            clientType = "public",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code")
        )
        val client2 = OAuthClientDTO(
            id = UUID.randomUUID(),
            clientId = "client_2",
            clientName = "Client Two",
            clientType = "confidential",
            redirectUris = listOf("https://example2.com/callback"),
            scopes = listOf("write"),
            grantTypes = listOf("client_credentials")
        )
        val provider = OauthClientServiceInMemoryProvider(mutableListOf(client1, client2))

        val result = provider.findDefaultClient(mockCall)
        assertNotNull(result)
        assertEquals("client_1", result?.clientId)
        assertTrue(result?.isDefault ?: false)
    }

    @Test
    fun `init sets first client as default`() {
        val client1 = OAuthClientDTO(
            id = UUID.randomUUID(),
            clientId = "client_1",
            clientName = "Client One",
            clientType = "public",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            isDefault = false
        )
        val client2 = OAuthClientDTO(
            id = UUID.randomUUID(),
            clientId = "client_2",
            clientName = "Client Two",
            clientType = "public",
            redirectUris = listOf("https://example2.com/callback"),
            scopes = listOf("write"),
            grantTypes = listOf("authorization_code"),
            isDefault = false
        )
        val provider = OauthClientServiceInMemoryProvider(mutableListOf(client1, client2))

        assertTrue(provider.clients[0].isDefault)
        assertFalse(provider.clients[1].isDefault)
    }

    @Test
    fun `init throws exception when no clients provided`() {
        assertThrows(RuntimeException::class.java) {
            OauthClientServiceInMemoryProvider(mutableListOf())
        }
    }

    @Test
    fun `init sets isDefault correctly for multiple clients`() {
        val clients = mutableListOf(
            OAuthClientDTO(
                id = UUID.randomUUID(),
                clientId = "client_1",
                clientName = "Client One",
                clientType = "public",
                redirectUris = listOf("https://example.com/callback"),
                scopes = listOf("read"),
                grantTypes = listOf("authorization_code")
            ),
            OAuthClientDTO(
                id = UUID.randomUUID(),
                clientId = "client_2",
                clientName = "Client Two",
                clientType = "public",
                redirectUris = listOf("https://example2.com/callback"),
                scopes = listOf("write"),
                grantTypes = listOf("authorization_code")
            ),
            OAuthClientDTO(
                id = UUID.randomUUID(),
                clientId = "client_3",
                clientName = "Client Three",
                clientType = "public",
                redirectUris = listOf("https://example3.com/callback"),
                scopes = listOf("admin"),
                grantTypes = listOf("client_credentials")
            )
        )
        val provider = OauthClientServiceInMemoryProvider(clients)

        for (i in clients.indices) {
            if (i == 0) {
                assertTrue(clients[i].isDefault)
            } else {
                assertFalse(clients[i].isDefault)
            }
        }
    }

    @Test
    fun `findByClientId works with multiple clients`() {
        val clients = mutableListOf(
            OAuthClientDTO(
                id = UUID.randomUUID(),
                clientId = "client_1",
                clientName = "Client One",
                clientType = "public",
                redirectUris = listOf("https://example.com/callback"),
                scopes = listOf("read"),
                grantTypes = listOf("authorization_code")
            ),
            OAuthClientDTO(
                id = UUID.randomUUID(),
                clientId = "client_2",
                clientName = "Client Two",
                clientType = "public",
                redirectUris = listOf("https://example2.com/callback"),
                scopes = listOf("write"),
                grantTypes = listOf("authorization_code")
            )
        )
        val provider = OauthClientServiceInMemoryProvider(clients)

        val result1 = provider.findByClientId("client_1", mockCall)
        val result2 = provider.findByClientId("client_2", mockCall)

        assertEquals("Client One", result1?.clientName)
        assertEquals("Client Two", result2?.clientName)
    }
}

