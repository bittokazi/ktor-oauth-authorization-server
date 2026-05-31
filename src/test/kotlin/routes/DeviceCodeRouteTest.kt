package routes

import com.bittokazi.ktor.auth.configureSerialization
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.routes.deviceCodeRoute
import com.bittokazi.ktor.auth.services.device.code.DeviceCodeProcessService
import com.bittokazi.ktor.auth.services.device.code.VerificationFailure
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.testing.testApplication
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.given

@RunWith(MockitoJUnitRunner::class)
@ExtendWith(MockitoExtension::class)
class DeviceCodeRouteTest {
    @Mock
    lateinit var deviceCodeProcessService: DeviceCodeProcessService

    // ==================== POST /oauth/device_authorization ====================

    @Test
    fun `POST oauth device_authorization - success`() =
        testApplication {
            given(
                deviceCodeProcessService.createDeviceAuthorization(
                    clientId = eq("test_client"),
                    scope = eq("openid profile"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        mapOf(
                            "device_code" to "device_123",
                            "user_code" to "user_123",
                            "verification_uri" to "http://localhost/oauth/device-verification",
                            "verification_uri_complete" to "http://localhost/oauth/device-verification?user_code=user_123",
                            "expires_in" to 1200,
                            "interval" to 5,
                        ),
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response =
                client.post("/oauth/device_authorization") {
                    setBody(
                        "client_id=test_client&scope=openid%20profile",
                    )
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("device_code"))
            Assertions.assertTrue(response.bodyAsText().contains("user_code"))
        }

    @Test
    fun `POST oauth device_authorization - service failure`() =
        testApplication {
            given(
                deviceCodeProcessService.createDeviceAuthorization(
                    clientId = eq("test_client"),
                    scope = eq("openid profile"),
                    call = any(),
                ),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        Pair(
                            400,
                            mapOf("error" to "Invalid client_id"),
                        ),
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response =
                client.post("/oauth/device_authorization") {
                    setBody(
                        "client_id=test_client&scope=openid%20profile",
                    )
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid client_id"))
        }

    // ==================== GET /oauth/device-verification ====================

    @Test
    fun `GET device verification - success`() =
        testApplication {
            given(
                deviceCodeProcessService.getDeviceVerificationPage(any()),
            ).willReturn(
                Result.Success(
                    outcome =
                        mapOf(
                            "result" to false,
                            "userCode" to "user_123",
                        ),
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response = client.get("/oauth/device-verification?user_code=user_123")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("userCode"))
        }

    @Test
    fun `GET device verification - login required redirects`() =
        testApplication {
            given(
                deviceCodeProcessService.getDeviceVerificationPage(any()),
            ).willReturn(
                Result.Failure(
                    errorBody = VerificationFailure.LoginRequired,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response = client.get("/oauth/device-verification?user_code=user_123")

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals("/oauth/login", response.headers["Location"])
        }

    @Test
    fun `GET device verification - template response`() =
        testApplication {
            given(
                deviceCodeProcessService.getDeviceVerificationPage(any()),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        VerificationFailure.Template(
                            data = mapOf("error" to "template_error"),
                        ),
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response = client.get("/oauth/device-verification?user_code=user_123")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("template_error"))
        }

    // ==================== POST /oauth/device-verification ====================

    @Test
    fun `POST device verification - success`() =
        testApplication {
            given(
                deviceCodeProcessService.verifyDeviceCode(
                    userCode = eq("user_123"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        mapOf(
                            "result" to true,
                            "isSuccess" to true,
                        ),
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response =
                client.post("/oauth/device-verification") {
                    setBody("user_code=user_123")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("isSuccess"))
        }

    @Test
    fun `POST device verification - login required redirects`() =
        testApplication {
            given(
                deviceCodeProcessService.verifyDeviceCode(
                    userCode = eq("user_123"),
                    call = any(),
                ),
            ).willReturn(
                Result.Failure(
                    errorBody = VerificationFailure.LoginRequired,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response =
                client.post("/oauth/device-verification") {
                    setBody("user_code=user_123")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals("/oauth/login", response.headers["Location"])
        }

    @Test
    fun `POST device verification - template failure`() =
        testApplication {
            given(
                deviceCodeProcessService.verifyDeviceCode(
                    userCode = eq("user_123"),
                    call = any(),
                ),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        VerificationFailure.Template(
                            data = mapOf("error" to "invalid_code"),
                        ),
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { deviceCodeProcessService }
                }

                deviceCodeRoute()
            }

            val response =
                client.post("/oauth/device-verification") {
                    setBody("user_code=user_123")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("invalid_code"))
        }
}
