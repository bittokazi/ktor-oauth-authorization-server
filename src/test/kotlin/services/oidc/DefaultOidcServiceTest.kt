package services.oidc

import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.domains.token.TokenType
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.oidc.DefaultOidcService
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.server.application.*
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.runner.RunWith
import org.mockito.BDDMockito.given
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.mock

@RunWith(MockitoJUnitRunner::class)
class DefaultOidcServiceTest {
    @Mock
    lateinit var oauthUserService: OauthUserService

    @Mock
    lateinit var jwksProvider: JwksProvider

    @Mock
    lateinit var jwtVerifier: JwtVerifier

    @Mock
    lateinit var signedJWT: SignedJWT

    @Mock
    lateinit var call: ApplicationCall

    private lateinit var oidcService: DefaultOidcService

    @Before
    fun setUp() {
        oidcService = DefaultOidcService(oauthUserService, jwksProvider, jwtVerifier)
    }

    @Test
    fun `should return Failure when Authorization header is missing`() =
        runTest {
            val result = oidcService.getUserInfo(null, call)

            assertTrue(result is Result.Failure)
            assertEquals("No Authorization Provided", (result as Result.Failure).errorBody)
        }

    @Test
    fun `should return Failure when Authorization header does not start with Bearer`() =
        runTest {
            val result = oidcService.getUserInfo("Basic abc123xyz", call)

            assertTrue(result is Result.Failure)
            assertEquals("Invalid authorization token", (result as Result.Failure).errorBody)
        }

    @Test
    fun `should return Failure when token verification fails`() =
        runTest {
            val token = "invalid.jwt.token"

            given(jwtVerifier.verify(token)).willReturn(null)

            val result = oidcService.getUserInfo("Bearer $token", call)

            assertTrue(result is Result.Failure)
            assertEquals("Unauthorized", (result as Result.Failure).errorBody)
        }

    @Test
    fun `should return Failure when token_type claim is not ACCESS_TOKEN`() =
        runTest {
            val token = "valid.jwt.token"
            val claimsSet =
                JWTClaimsSet.Builder()
                    .claim("token_type", "REFRESH_TOKEN")
                    .build()

            given(jwtVerifier.verify(token)).willReturn(signedJWT)
            given(signedJWT.jwtClaimsSet).willReturn(claimsSet)

            val result = oidcService.getUserInfo("Bearer $token", call)

            assertTrue(result is Result.Failure)
            assertEquals("Unauthorized", (result as Result.Failure).errorBody)
        }

    @Test
    fun `should return Success with minimal subject if openid scope is not present`() =
        runTest {
            val token = "valid.jwt.token"
            val claimsSet =
                JWTClaimsSet.Builder()
                    .subject("user-123")
                    .claim("token_type", TokenType.ACCESS_TOKEN.name)
                    .claim("scope", "profile") // Missing 'openid'
                    .build()

            given(jwtVerifier.verify(token)).willReturn(signedJWT)
            given(signedJWT.jwtClaimsSet).willReturn(claimsSet)

            val result = oidcService.getUserInfo("Bearer $token", call)

            assertTrue(result is Result.Success)
            val outcome = (result as Result.Success).outcome
            assertEquals(1, outcome.size)
            assertEquals("user-123", outcome["sub"])
        }

    @Test
    fun `should return Failure when openid is present but user cannot be found in database`() =
        runTest {
            val token = "valid.jwt.token"
            val claimsSet =
                JWTClaimsSet.Builder()
                    .subject("non-existent-user")
                    .claim("token_type", TokenType.ACCESS_TOKEN.name)
                    .claim("scope", "openid")
                    .build()

            given(jwtVerifier.verify(token)).willReturn(signedJWT)
            given(signedJWT.jwtClaimsSet).willReturn(claimsSet)
            given(oauthUserService.findById("non-existent-user", call)).willReturn(null)

            val result = oidcService.getUserInfo("Bearer $token", call)

            assertTrue(result is Result.Failure)
            assertEquals("User not found", (result as Result.Failure).errorBody)
        }

    @Test
    fun `should return Success with all claims if openid, profile, and email scopes are authorized`() =
        runTest {
            val token = "valid.jwt.token"
            val claimsSet =
                JWTClaimsSet.Builder()
                    .subject("user-123")
                    .claim("token_type", TokenType.ACCESS_TOKEN.name)
                    .claim("scope", "openid profile email")
                    .build()

            // Mock database User entity
            val mockUser = mock<OAuthUserDTO>()
            given(mockUser.email).willReturn("john.doe@example.com")
            given(mockUser.firstName).willReturn("John")
            given(mockUser.lastName).willReturn("Doe")
            given(mockUser.username).willReturn("johndoe")

            given(oauthUserService.findById("user-123", call)).willReturn(mockUser)

            given(jwtVerifier.verify(token)).willReturn(signedJWT)
            given(signedJWT.jwtClaimsSet).willReturn(claimsSet)

            val result = oidcService.getUserInfo("Bearer $token", call)

            assertTrue(result is Result.Success)
            val outcome = (result as Result.Success).outcome
            assertEquals("user-123", outcome["sub"])
            assertEquals("john.doe@example.com", outcome["email"])
            assertEquals("John Doe", outcome["name"])
            assertEquals("johndoe", outcome["preferred_username"])
        }

    @Test
    fun `should map and build OpenId Configuration correctly`() {
        val baseUrl = "https://auth.example.com/oauth"
        val issuer = "https://auth.example.com"

        val metadata = oidcService.getOpenIdConfiguration(baseUrl, issuer)

        assertEquals(issuer, metadata["issuer"])
        assertEquals("$baseUrl/authorize", metadata["authorization_endpoint"])
        assertEquals("$baseUrl/userinfo", metadata["userinfo_endpoint"])
        assertEquals("$issuer/.well-known/jwks.json", metadata["jwks_uri"])
        assertEquals(listOf("authorization_code", "refresh_token"), metadata["grant_types_supported"])
    }

    @Test
    fun `should map and return JWKS keys definition securely`() {
        val expectedJwk = mapOf("kty" to "RSA", "kid" to "key-id-1")
        given(jwksProvider.getPublicJwk()).willReturn(expectedJwk)

        val jwks = oidcService.getJwksConfiguration()

        val keys = jwks["keys"] as List<*>
        assertEquals(1, keys.size)
        assertEquals(expectedJwk, keys[0])
    }
}
