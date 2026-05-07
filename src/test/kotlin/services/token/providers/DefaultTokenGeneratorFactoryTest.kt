package services.token.providers

import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.services.token.providers.DefaultTokenGeneratorFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner

@RunWith(MockitoJUnitRunner::class)
class DefaultTokenGeneratorFactoryTest {
    @Mock
    lateinit var clientCredentialsGenerator: TokenGenerator

    @Mock
    lateinit var authorizationCodeGenerator: TokenGenerator

    @Mock
    lateinit var refreshTokenGenerator: TokenGenerator

    @Mock
    lateinit var deviceCodeGenerator: TokenGenerator

    lateinit var tokenGeneratorFactory: DefaultTokenGeneratorFactory

    @Before
    fun setUp() {
        tokenGeneratorFactory =
            DefaultTokenGeneratorFactory(
                clientCredentialsGenerator,
                authorizationCodeGenerator,
                refreshTokenGenerator,
                deviceCodeGenerator,
            )
    }

    @Test
    fun `getGenerator() returns client_credentials generator for client_credentials grant type`() {
        val actual = tokenGeneratorFactory.getGenerator("client_credentials")

        assertEquals(clientCredentialsGenerator, actual)
    }

    @Test
    fun `getGenerator() returns authorization_code generator for authorization_code grant type`() {
        val actual = tokenGeneratorFactory.getGenerator("authorization_code")

        assertEquals(authorizationCodeGenerator, actual)
    }

    @Test
    fun `getGenerator() returns refresh_token generator for refresh_token grant type`() {
        val actual = tokenGeneratorFactory.getGenerator("refresh_token")

        assertEquals(refreshTokenGenerator, actual)
    }

    @Test
    fun `getGenerator() returns device_code generator for device_code grant type`() {
        val actual = tokenGeneratorFactory.getGenerator("urn:ietf:params:oauth:grant-type:device_code")

        assertEquals(deviceCodeGenerator, actual)
    }

    @Test
    fun `getGenerator() returns null for unsupported grant type`() {
        val actual = tokenGeneratorFactory.getGenerator("unsupported_grant_type")

        assertNull(actual)
    }

    @Test
    fun `getGenerator() returns null for null grant type`() {
        val actual = tokenGeneratorFactory.getGenerator(null)

        assertNull(actual)
    }

    @Test
    fun `getGenerator() returns null for empty grant type`() {
        val actual = tokenGeneratorFactory.getGenerator("")

        assertNull(actual)
    }

    @Test
    fun `getGenerator() is case sensitive for grant type matching`() {
        val actual = tokenGeneratorFactory.getGenerator("CLIENT_CREDENTIALS")

        assertNull(actual)
    }

    @Test
    fun `getGenerator() handles all registered grant types correctly`() {
        // Test all four grant types are correctly mapped
        val clientCredentials = tokenGeneratorFactory.getGenerator("client_credentials")
        val authorizationCode = tokenGeneratorFactory.getGenerator("authorization_code")
        val refreshToken = tokenGeneratorFactory.getGenerator("refresh_token")
        val deviceCode = tokenGeneratorFactory.getGenerator("urn:ietf:params:oauth:grant-type:device_code")

        assertEquals(clientCredentialsGenerator, clientCredentials)
        assertEquals(authorizationCodeGenerator, authorizationCode)
        assertEquals(refreshTokenGenerator, refreshToken)
        assertEquals(deviceCodeGenerator, deviceCode)
    }
}
