package routes

import com.bittokazi.ktor.auth.configureSerialization
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.routes.tokenRoutes
import com.bittokazi.ktor.auth.services.token.TokenGenerator
import com.bittokazi.ktor.auth.services.token.TokenGeneratorFactory
import com.bittokazi.ktor.auth.services.token.TokenIntrospectService
import com.bittokazi.ktor.auth.services.token.TokenRevokeService
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.formUrlEncode
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.testing.*
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.mockito.kotlin.given

@RunWith(MockitoJUnitRunner::class)
@ExtendWith(MockitoExtension::class)
class TokenRoutesTest {

    @Mock
    lateinit var tokenGeneratorFactory: TokenGeneratorFactory

    @Mock
    lateinit var tokenGenerator: TokenGenerator

    @Mock
    lateinit var tokenIntrospectService: TokenIntrospectService

    @Mock
    lateinit var tokenRevokeService: TokenRevokeService

    // ==================== POST /oauth/token Tests ====================

    @ParameterizedTest
    @ValueSource(strings = ["client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"])
    fun `POST oauth token - success`(grantType: String) = testApplication {
        given(tokenGeneratorFactory.getGenerator(grantType))
            .willReturn(tokenGenerator)

        given(tokenGenerator.generateTokens(any(), any()))
            .willReturn(
                Result.Success(
                    outcome = mapOf("access_token" to "abc123")
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "grant_type" to grantType
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.OK, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("abc123"))
    }

    @Test
    fun `POST oauth token - missing grant_type - error`() = testApplication {
        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf<Pair<String, String>>().formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Unsupported grant type"))
    }

    @Test
    fun `POST oauth token - unknown grant type - error`() = testApplication {
        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "grant_type" to "authorization_code"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Unsupported grant type"))
    }

    @ParameterizedTest
    @CsvSource(
        "BadRequest,Invalid credentials",
        "Unauthorized,Unauthorized",
        "Forbidden,Forbidden",
        "InternalServerError,Internal server error"
    )
    fun `POST oauth token - generator failure with different status codes`(
        statusCodeName: String,
        errorMessage: String
    ) = testApplication {
        val statusCode = HttpStatusCode.fromValue(
            when (statusCodeName) {
                "BadRequest" -> 400
                "Unauthorized" -> 401
                "Forbidden" -> 403
                "InternalServerError" -> 500
                else -> 500
            }
        )

        given(tokenGeneratorFactory.getGenerator("client_credentials"))
            .willReturn(tokenGenerator)

        given(tokenGenerator.generateTokens(any(), any()))
            .willReturn(
                Result.Failure(
                    errorBody = mapOf(
                        "error" to errorMessage,
                        "statusCode" to statusCode
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "grant_type" to "client_credentials"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(statusCode, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains(errorMessage))
    }

    @Test
    fun `POST oauth token - generator failure without status code defaults to InternalServerError`() = testApplication {
        given(tokenGeneratorFactory.getGenerator("client_credentials"))
            .willReturn(tokenGenerator)

        given(tokenGenerator.generateTokens(any(), any()))
            .willReturn(
                Result.Failure(
                    errorBody = mapOf(
                        "error" to "Something went wrong"
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "grant_type" to "client_credentials"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.InternalServerError, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Something went wrong"))
    }

    // ==================== POST /oauth/introspect Tests ====================

    @ParameterizedTest
    @CsvSource(
        "true",
        "false"
    )
    fun `POST oauth introspect - success`(active: Boolean) = testApplication {
        given(tokenIntrospectService.introspect(any(), any(), any(), any()))
            .willReturn(
                Result.Success(
                    outcome = mapOf(
                        "active" to active,
                        "scope" to "openid profile email",
                        "client_id" to "test_client",
                        "username" to "test_user",
                        "token_type" to "Bearer"
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/introspect") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token",
                    "client_id" to "test_client",
                    "client_secret" to "test_secret"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.OK, response.status)
        val responseBody = response.bodyAsText()
        Assertions.assertTrue(responseBody.contains("active"), "Response should contain active field")
        Assertions.assertTrue(responseBody.contains("scope"), "Response should contain scope")
        Assertions.assertTrue(responseBody.contains("test_client"), "Response should contain client_id")
    }

    @Test
    fun `POST oauth introspect - missing token - error`() = testApplication {
        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/introspect") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "client_id" to "test_client",
                    "client_secret" to "test_secret"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Missing token"))
    }

    @Test
    fun `POST oauth introspect - missing client_id - error`() = testApplication {
        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/introspect") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token",
                    "client_secret" to "test_secret"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Missing client_id"))
    }

    @Test
    fun `POST oauth introspect - missing client_secret - error`() = testApplication {
        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/introspect") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token",
                    "client_id" to "test_client"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Missing client_secret"))
    }

    @ParameterizedTest
    @CsvSource(
        "BadRequest,Invalid token",
        "Unauthorized,Token expired",
        "Forbidden,Access denied"
    )
    fun `POST oauth introspect - service failure with different status codes`(
        statusCodeName: String,
        errorMessage: String
    ) = testApplication {
        val statusCode = HttpStatusCode.fromValue(
            when (statusCodeName) {
                "BadRequest" -> 400
                "Unauthorized" -> 401
                "Forbidden" -> 403
                else -> 500
            }
        )

        given(tokenIntrospectService.introspect(any(), any(), any(), any()))
            .willReturn(
                Result.Failure(
                    errorBody = mapOf(
                        "error" to errorMessage,
                        "statusCode" to statusCode
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/introspect") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token",
                    "client_id" to "test_client",
                    "client_secret" to "test_secret"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(statusCode, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains(errorMessage))
    }

    @Test
    fun `POST oauth introspect - service failure without status code defaults to InternalServerError`() = testApplication {
        given(tokenIntrospectService.introspect(any(), any(), any(), any()))
            .willReturn(
                Result.Failure(
                    errorBody = mapOf(
                        "error" to "Service error"
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/introspect") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token",
                    "client_id" to "test_client",
                    "client_secret" to "test_secret"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.InternalServerError, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Service error"))
    }

    // ==================== POST /oauth/revoke Tests ====================

    @ParameterizedTest
    @CsvSource(
        "access_token,Access token revoked successfully",
        "refresh_token,Refresh token revoked successfully",
        "device_code,Device code revoked successfully"
    )
    fun `POST oauth revoke - success`(tokenType: String, message: String) = testApplication {
        given(tokenRevokeService.revoke(any(), any()))
            .willReturn(
                Result.Success(
                    outcome = mapOf(
                        "revoked" to true,
                        "token_type" to tokenType,
                        "message" to message,
                        "revocation_timestamp" to System.currentTimeMillis()
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/revoke") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.OK, response.status)
        val responseBody = response.bodyAsText()
        Assertions.assertTrue(responseBody.contains("revoked"), "Response should contain revoked field")
        Assertions.assertTrue(responseBody.contains(tokenType), "Response should contain token type")
        Assertions.assertTrue(responseBody.contains(message), "Response should contain revocation message")
    }

    @Test
    fun `POST oauth revoke - missing token - error`() = testApplication {
        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/revoke") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf<Pair<String, String>>().formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Missing token"))
    }

    @ParameterizedTest
    @CsvSource(
        "BadRequest,Invalid token format",
        "Unauthorized,Token not found",
        "Forbidden,Cannot revoke token"
    )
    fun `POST oauth revoke - service failure with different status codes`(
        statusCodeName: String,
        errorMessage: String
    ) = testApplication {
        val statusCode = HttpStatusCode.fromValue(
            when (statusCodeName) {
                "BadRequest" -> 400
                "Unauthorized" -> 401
                "Forbidden" -> 403
                else -> 500
            }
        )

        given(tokenRevokeService.revoke(any(), any()))
            .willReturn(
                Result.Failure(
                    errorBody = mapOf(
                        "error" to errorMessage,
                        "statusCode" to statusCode
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/revoke") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(statusCode, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains(errorMessage))
    }

    @Test
    fun `POST oauth revoke - service failure without status code defaults to InternalServerError`() = testApplication {
        given(tokenRevokeService.revoke(any(), any()))
            .willReturn(
                Result.Failure(
                    errorBody = mapOf(
                        "error" to "Revocation service error"
                    )
                )
            )

        application {
            configureSerialization()

            dependencies {
                provide { tokenGeneratorFactory }
                provide { tokenIntrospectService }
                provide { tokenRevokeService }
            }
            tokenRoutes()
        }

        val response = client.post("/oauth/revoke") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                listOf(
                    "token" to "test_token"
                ).formUrlEncode()
            )
        }

        Assertions.assertEquals(HttpStatusCode.InternalServerError, response.status)
        Assertions.assertEquals(true, response.bodyAsText().contains("Revocation service error"))
    }
}

