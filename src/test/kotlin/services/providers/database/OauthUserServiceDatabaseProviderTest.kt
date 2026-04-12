package com.bittokazi.ktor.auth.services.providers.database

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.config.TestOauthDatabaseConfiguration
import io.ktor.server.application.ApplicationCall
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import org.mockito.Mockito

class OauthUserServiceDatabaseProviderTest {

    private lateinit var databaseConfiguration: TestOauthDatabaseConfiguration
    private lateinit var userService: OauthUserServiceDatabaseProvider
    private val mockCall = Mockito.mock(ApplicationCall::class.java)

    @Before
    fun setUp() {
        databaseConfiguration = TestOauthDatabaseConfiguration()
        userService = OauthUserServiceDatabaseProvider(databaseConfiguration)
    }

    @After
    fun tearDown() {
        databaseConfiguration.stop()
    }

    @Test
    fun `createUser successfully creates a new user`() {
        val user = userService.createUser(
            username = "testuser",
            password = "password123",
            email = "test@example.com",
            firstName = "Test",
            lastName = "User",
            call = mockCall
        )

        assertNotNull(user)
        assertEquals("testuser", user.username)
        assertEquals("test@example.com", user.email)
        assertEquals("Test", user.firstName)
        assertEquals("User", user.lastName)
        assertTrue(user.isActive)
    }

    @Test
    fun `findByUsername returns user when exists`() {
        userService.createUser(
            username = "testuser",
            password = "password123",
            email = "test@example.com",
            firstName = "Test",
            lastName = "User",
            call = mockCall
        )

        val result = userService.findByUsername("testuser", mockCall)
        assertNotNull(result)
        assertEquals("testuser", result?.username)
        assertEquals("test@example.com", result?.email)
    }

    @Test
    fun `findByUsername returns null when user not found`() {
        val result = userService.findByUsername("nonexistent", mockCall)
        assertNull(result)
    }

    @Test
    fun `findById returns user when exists`() {
        val created = userService.createUser(
            username = "testuser",
            password = "password123",
            email = "test@example.com",
            firstName = "Test",
            lastName = "User",
            call = mockCall
        )

        val result = userService.findById(created.id, mockCall)
        assertNotNull(result)
        assertEquals("testuser", result?.username)
        assertEquals(created.id, result?.id)
    }

    @Test
    fun `findById returns null when user not found`() {
        val result = userService.findById("nonexistent_id", mockCall)
        assertNull(result)
    }

    @Test
    fun `createUser hashes password with bcrypt`() {
        val user = userService.createUser(
            username = "testuser",
            password = "password123",
            email = "test@example.com",
            firstName = "Test",
            lastName = "User",
            call = mockCall
        )

        val result = userService.findByUsername("testuser", mockCall)
        assertNotNull(result?.passwordHash)
        assertNotEquals("password123", result?.passwordHash)
        // Verify the hash is valid
        assertTrue(BCrypt.verifyer().verify("password123".toCharArray(), result?.passwordHash).verified)
    }

    @Test
    fun `updateUser successfully updates user properties`() {
        val created = userService.createUser(
            username = "testuser",
            password = "password123",
            email = "test@example.com",
            firstName = "Test",
            lastName = "User",
            call = mockCall
        )

        val updateResult = userService.updateUser(
            userId = created.id,
            username = "updateduser",
            email = "updated@example.com",
            firstName = "Updated",
            lastName = "Name",
            call = mockCall
        )

        assertTrue(updateResult)

        val updated = userService.findById(created.id, mockCall)
        assertEquals("updateduser", updated?.username)
        assertEquals("updated@example.com", updated?.email)
        assertEquals("Updated", updated?.firstName)
        assertEquals("Name", updated?.lastName)
    }

    @Test
    fun `updateUser returns false for nonexistent user`() {
        val result = userService.updateUser(
            userId = "nonexistent",
            username = "newname",
            email = "new@example.com",
            firstName = "New",
            lastName = "User",
            call = mockCall
        )

        assertFalse(result)
    }

    @Test
    fun `updateUserPassword changes password hash`() {
        val created = userService.createUser(
            username = "testuser",
            password = "oldpassword",
            email = "test@example.com",
            firstName = "Test",
            lastName = "User",
            call = mockCall
        )

        val oldPasswordHash = userService.findById(created.id, mockCall)?.passwordHash

        val updateResult = userService.updateUserPassword(
            userId = created.id,
            password = "newpassword",
            call = mockCall
        )

        assertTrue(updateResult)

        val updated = userService.findById(created.id, mockCall)
        assertNotNull(updated?.passwordHash)
        assertNotEquals(oldPasswordHash, updated?.passwordHash)
        assertTrue(BCrypt.verifyer().verify("newpassword".toCharArray(), updated?.passwordHash).verified)
    }

    @Test
    fun `updateUserPassword returns false for nonexistent user`() {
        val result = userService.updateUserPassword(
            userId = "nonexistent",
            password = "newpassword",
            call = mockCall
        )

        assertFalse(result)
    }

    @Test
    fun `createUser with null optional fields`() {
        val user = userService.createUser(
            username = "testuser",
            password = "password123",
            email = null,
            firstName = null,
            lastName = null,
            call = mockCall
        )

        val result = userService.findByUsername("testuser", mockCall)
        assertNull(result?.email)
        assertNull(result?.firstName)
        assertNull(result?.lastName)
    }

    @Test
    fun `multiple users can be created independently`() {
        for (i in 1..3) {
            userService.createUser(
                username = "user_$i",
                password = "password_$i",
                email = "user$i@example.com",
                firstName = "User",
                lastName = "Number$i",
                call = mockCall
            )
        }

        for (i in 1..3) {
            val user = userService.findByUsername("user_$i", mockCall)
            assertNotNull(user)
            assertEquals("user_$i", user?.username)
            assertEquals("User", user?.firstName)
        }
    }

    @Test
    fun `updating one user does not affect others`() {
        val user1 = userService.createUser(
            username = "user_1",
            password = "password",
            email = "user1@example.com",
            firstName = "User",
            lastName = "One",
            call = mockCall
        )

        val user2 = userService.createUser(
            username = "user_2",
            password = "password",
            email = "user2@example.com",
            firstName = "User",
            lastName = "Two",
            call = mockCall
        )

        userService.updateUser(
            userId = user1.id,
            username = "updated_user_1",
            email = "updated1@example.com",
            firstName = "Updated",
            lastName = "One",
            call = mockCall
        )

        val result2 = userService.findById(user2.id, mockCall)
        assertEquals("user_2", result2?.username)
        assertEquals("user2@example.com", result2?.email)
    }
}
