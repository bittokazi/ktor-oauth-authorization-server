package com.bittokazi.ktor.auth.services.providers.database

import com.bittokazi.ktor.auth.config.TestOauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.providers.database.OAuthClients.isDefault
import io.ktor.server.application.*
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.exceptions.ExposedSQLException
import org.jetbrains.exposed.v1.jdbc.update
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito

class OauthClientServiceDatabaseProviderTest {

    private lateinit var databaseConfiguration: TestOauthDatabaseConfiguration
    private lateinit var clientService: OauthClientServiceDatabaseProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)

    @Before
    fun setUp() {
        databaseConfiguration = TestOauthDatabaseConfiguration()
        clientService = OauthClientServiceDatabaseProvider(databaseConfiguration)
    }

    @After
    fun tearDown() {
        databaseConfiguration.stop()
    }

    @Test
    fun `createClient successfully creates a new client`() {
        val client = clientService.createClient(
            clientId = "test_client_1",
            clientSecret = "test_secret",
            name = "Test Client",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("openid", "profile"),
            grantTypes = listOf("authorization_code", "refresh_token"),
            accessTokenValidity = 3600,
            refreshTokenValidity = 86400,
            consentRequired = true,
            call = mockCall
        )

        assertNotNull(client)
        assertEquals("test_client_1", client.clientId)
        assertEquals("Test Client", client.clientName)
        assertEquals("confidential", client.clientType)
        assertEquals(2, client.scopes.size)
        assertEquals(2, client.grantTypes.size)
    }

    @Test
    fun `findByClientId returns client when exists`() {
        clientService.createClient(
            clientId = "test_client_1",
            clientSecret = "test_secret",
            name = "Test Client",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read", "write"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        val result = clientService.findByClientId("test_client_1", mockCall)
        assertNotNull(result)
        assertEquals("test_client_1", result?.clientId)
        assertEquals("Test Client", result?.clientName)
        assertEquals("confidential", result?.clientType)
    }

    @Test
    fun `findByClientId returns null when client not found`() {
        val result = clientService.findByClientId("nonexistent_client", mockCall)
        assertNull(result)
    }

    @Test
    fun `updateClient successfully updates client details`() {
        // Create a client first
        clientService.createClient(
            clientId = "test_client_1",
            clientSecret = "test_secret",
            name = "Old Name",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        // Update the client
        val updateResult = clientService.updateClient(
            clientId = "test_client_1",
            name = "Updated Name",
            type = "public",
            redirectUris = listOf("https://example.com/callback", "https://example.com/callback2"),
            scopes = listOf("read", "write", "admin"),
            grantTypes = listOf("authorization_code", "implicit"),
            consentRequired = false,
            call = mockCall
        )

        assertTrue(updateResult)

        // Verify the update
        val updated = clientService.findByClientId("test_client_1", mockCall)
        assertNotNull(updated)
        assertEquals("Updated Name", updated?.clientName)
        assertEquals("public", updated?.clientType)
        assertEquals(2, updated?.redirectUris?.size)
        assertEquals(3, updated?.scopes?.size)
        assertEquals(2, updated?.grantTypes?.size)
    }

    @Test
    fun `updateClient returns false for nonexistent client`() {
        val result = clientService.updateClient(
            clientId = "nonexistent",
            name = "Name",
            type = "confidential",
            redirectUris = listOf("https://example.com"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        assertFalse(result)
    }

    @Test
    fun `updateClientSecret successfully updates the secret`() {
        clientService.createClient(
            clientId = "test_client_1",
            clientSecret = "old_secret",
            name = "Test Client",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        val updateResult = clientService.updateClientSecret(
            clientId = "test_client_1",
            clientSecret = "new_secret",
            call = mockCall
        )

        assertTrue(updateResult)

        val updated = clientService.findByClientId("test_client_1", mockCall)
        assertEquals("new_secret", updated?.clientSecret)
    }

    @Test
    fun `updateClientSecret returns false for nonexistent client`() {
        val result = clientService.updateClientSecret(
            clientId = "nonexistent",
            clientSecret = "new_secret",
            call = mockCall
        )

        assertFalse(result)
    }

    @Test
    fun `findByClientId returns all client properties correctly`() {
        val redirectUris = listOf("https://example.com/callback", "https://example.com/callback2")
        val scopes = listOf("openid", "profile", "email")
        val grantTypes = listOf("authorization_code", "refresh_token", "client_credentials")

        clientService.createClient(
            clientId = "full_client",
            clientSecret = "secret_value",
            name = "Full Client",
            type = "confidential",
            redirectUris = redirectUris,
            scopes = scopes,
            grantTypes = grantTypes,
            accessTokenValidity = 7200,
            refreshTokenValidity = 604800,
            consentRequired = false,
            call = mockCall
        )

        val result = clientService.findByClientId("full_client", mockCall)
        assertNotNull(result)
        assertEquals(2, result?.redirectUris?.size)
        assertEquals(3, result?.scopes?.size)
        assertEquals(3, result?.grantTypes?.size)
        assertEquals("secret_value", result?.clientSecret)
        // Check token validity values are returned as Long not Int
        if (result != null) {
            assertEquals(7200L, result.accessTokenValidity)
            assertEquals(604800L, result.refreshTokenValidity)
        }
        assertFalse(result?.consentRequired ?: true)
    }

    @Test
    fun `createClient with null clientSecret throws error`() {
        assertThrows(ExposedSQLException::class.java) {
            clientService.createClient(
                clientId = "public_client",
                clientSecret = null,
                name = "Public Client",
                type = "public",
                redirectUris = listOf("https://example.com/callback"),
                scopes = listOf("read"),
                grantTypes = listOf("implicit"),
                call = mockCall
            )
        }
    }

    @Test
    fun `createClient with default token validity values`() {
        clientService.createClient(
            clientId = "default_validity_client",
            clientSecret = "secret",
            name = "Default Validity",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        val result = clientService.findByClientId("default_validity_client", mockCall)
        assertNotNull(result)
        assertNotNull("Access token validity should not be null", result?.accessTokenValidity)
        assertNotNull("Refresh token validity should not be null", result?.refreshTokenValidity)
        // Check if values are actually present and are the defaults
        if (result != null) {
            assertEquals(300L, result.accessTokenValidity)
            assertEquals(7200L, result.refreshTokenValidity)
        }
    }

    @Test
    fun `multiple clients can be created and retrieved independently`() {
        // Create multiple clients
        for (i in 1..5) {
            clientService.createClient(
                clientId = "client_$i",
                clientSecret = "secret_$i",
                name = "Client $i",
                type = if (i % 2 == 0) "public" else "confidential",
                redirectUris = listOf("https://app$i.com/callback"),
                scopes = listOf("scope_$i"),
                grantTypes = listOf("authorization_code"),
                call = mockCall
            )
        }

        // Verify each client can be retrieved
        for (i in 1..5) {
            val client = clientService.findByClientId("client_$i", mockCall)
            assertNotNull(client)
            assertEquals("Client $i", client?.clientName)
            assertEquals("secret_$i", client?.clientSecret)
        }
    }

    @Test
    fun `updateClient does not affect other clients`() {
        clientService.createClient(
            clientId = "client_1",
            clientSecret = "secret_1",
            name = "Client 1",
            type = "confidential",
            redirectUris = listOf("https://app1.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        clientService.createClient(
            clientId = "client_2",
            clientSecret = "secret_2",
            name = "Client 2",
            type = "public",
            redirectUris = listOf("https://app2.com/callback"),
            scopes = listOf("write"),
            grantTypes = listOf("implicit"),
            call = mockCall
        )

        // Update first client
        clientService.updateClient(
            clientId = "client_1",
            name = "Updated Client 1",
            type = "public",
            redirectUris = listOf("https://updated.com/callback"),
            scopes = listOf("admin"),
            grantTypes = listOf("client_credentials"),
            call = mockCall
        )

        // Verify second client is unchanged
        val client2 = clientService.findByClientId("client_2", mockCall)
        assertEquals("Client 2", client2?.clientName)
        assertEquals("public", client2?.clientType)
        assertEquals("write", client2?.scopes?.get(0))
    }

    @Test
    fun `client creation stores all redirect URIs correctly`() {
        val redirectUris = listOf(
            "https://app.example.com/callback",
            "https://app.example.com/callback2",
            "https://mobile.example.com/callback"
        )

        clientService.createClient(
            clientId = "multi_redirect",
            clientSecret = "secret",
            name = "Multi Redirect",
            type = "confidential",
            redirectUris = redirectUris,
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        val result = clientService.findByClientId("multi_redirect", mockCall)
        assertEquals(3, result?.redirectUris?.size)
        assertTrue(result?.redirectUris?.containsAll(redirectUris) ?: false)
    }

    @Test
    fun `client creation stores all scopes correctly`() {
        val scopes = listOf("openid", "profile", "email", "address", "phone", "offline_access")

        clientService.createClient(
            clientId = "multi_scope",
            clientSecret = "secret",
            name = "Multi Scope",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = scopes,
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        val result = clientService.findByClientId("multi_scope", mockCall)
        assertEquals(6, result?.scopes?.size)
        assertTrue(result?.scopes?.containsAll(scopes) ?: false)
    }

    @Test
    fun `client creation stores all grant types correctly`() {
        val grantTypes = listOf(
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "implicit",
            "password"
        )

        clientService.createClient(
            clientId = "multi_grant",
            clientSecret = "secret",
            name = "Multi Grant",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = grantTypes,
            call = mockCall
        )

        val result = clientService.findByClientId("multi_grant", mockCall)
        assertEquals(5, result?.grantTypes?.size)
        assertTrue(result?.grantTypes?.containsAll(grantTypes) ?: false)
    }

    @Test
    fun `updating returns error when default flag is set to true`() {
        clientService.createClient(
            clientId = "default_client",
            clientSecret = "secret",
            name = "Default Client",
            type = "confidential",
            redirectUris = listOf("https://example.com/callback"),
            scopes = listOf("read"),
            grantTypes = listOf("authorization_code"),
            call = mockCall
        )

        assertThrows(ExposedSQLException::class.java) {
            databaseConfiguration.dbQuery(mockCall) {
                OAuthClients.update({ OAuthClients.clientId eq "default_client" }) {
                    it[isDefault] = true
                }
            }
        }
    }
}
