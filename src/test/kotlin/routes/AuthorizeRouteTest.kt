package routes

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.configureSerialization
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.routes.authorizeRoute
import com.bittokazi.ktor.auth.services.authorization.OauthAuthorizationProcessService
import com.bittokazi.ktor.auth.services.session.DefaultSessionProvider
import com.bittokazi.ktor.auth.services.session.SessionProvider
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.install
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.sessions.SessionTransportTransformerEncrypt
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.testing.testApplication
import io.ktor.util.hex
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.eq
import org.mockito.kotlin.given
import kotlin.random.Random

@RunWith(MockitoJUnitRunner::class)
@ExtendWith(MockitoExtension::class)
class AuthorizeRouteTest {
    @Mock
    lateinit var oauthAuthorizationProcessService: OauthAuthorizationProcessService

    // ==================== GET /oauth/authorize Success Tests ====================

    @Test
    fun `GET oauth authorize - success with state`() =
        testApplication {
            given(
                oauthAuthorizationProcessService.authorize(
                    clientId = eq("test_client"),
                    redirectUri = eq("http://localhost:3000/callback"),
                    responseType = eq("code"),
                    scope = eq("openid profile"),
                    state = eq("xyz123"),
                    codeChallenge = eq("challenge"),
                    codeChallengeMethod = eq("S256"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        mapOf(
                            "code" to "auth_code_123",
                            "state" to "xyz123",
                            "redirectUri" to "http://localhost:3000/callback",
                            "clientId" to "test_client",
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
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?client_id=test_client" +
                        "&redirect_uri=http://localhost:3000/callback" +
                        "&response_type=code" +
                        "&scope=openid%20profile" +
                        "&state=xyz123" +
                        "&code_challenge=challenge" +
                        "&code_challenge_method=S256",
                )

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals(
                "http://localhost:3000/callback?code=auth_code_123&state=xyz123",
                response.headers["Location"],
            )
        }

    @Test
    fun `GET oauth authorize - success without state`() =
        testApplication {
            given(
                oauthAuthorizationProcessService.authorize(
                    clientId = eq("test_client"),
                    redirectUri = eq("http://localhost:3000/callback"),
                    responseType = eq("code"),
                    scope = eq("openid"),
                    state = eq(null),
                    codeChallenge = eq("challenge"),
                    codeChallengeMethod = eq("S256"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        mapOf(
                            "code" to "auth_code_456",
                            "state" to null,
                            "redirectUri" to "http://localhost:3000/callback",
                            "clientId" to "test_client",
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
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?client_id=test_client" +
                        "&redirect_uri=http://localhost:3000/callback" +
                        "&response_type=code" +
                        "&scope=openid" +
                        "&code_challenge=challenge" +
                        "&code_challenge_method=S256",
                )

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals(
                "http://localhost:3000/callback?code=auth_code_456",
                response.headers["Location"],
            )
        }

    // ==================== Missing Required Parameters ====================

    @Test
    fun `GET oauth authorize - missing client_id - error`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?redirect_uri=http://localhost:3000/callback",
                )

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid request"))
        }

    @Test
    fun `GET oauth authorize - missing redirect_uri - error`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?client_id=test_client",
                )

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid request"))
        }

    // ==================== Authorization Service Failure Cases ====================

    @ParameterizedTest
    @CsvSource(
        "BadRequest,Invalid request",
        "BadRequest,Invalid client_id",
        "BadRequest,Invalid redirect_uri",
        "BadRequest,Invalid scopes",
        "BadRequest,Missing code challenge properties",
        "BadRequest,Invalid code challenge method",
        "Unauthorized,Unauthorized",
        "Unauthorized,Login checks not completed",
    )
    fun `GET oauth authorize - service failure with different status codes`(
        statusCodeName: String,
        errorMessage: String,
    ) = testApplication {
        val client =
            createClient {
                followRedirects = false
            }

        val statusCode =
            HttpStatusCode.fromValue(
                when (statusCodeName) {
                    "BadRequest" -> 400
                    "Unauthorized" -> 401
                    "Forbidden" -> 403
                    else -> 500
                },
            )

        given(
            oauthAuthorizationProcessService.authorize(
                clientId = any(),
                redirectUri = any(),
                responseType = any(),
                scope = anyOrNull(),
                state = anyOrNull(),
                codeChallenge = anyOrNull(),
                codeChallengeMethod = anyOrNull(),
                call = any(),
            ),
        ).willReturn(
            Result.Failure(
                errorBody =
                    mapOf(
                        "error" to errorMessage,
                        "statusCode" to statusCode,
                    ),
            ),
        )

        application {
            configureSerialization()

            dependencies {
                provide { oauthAuthorizationProcessService }
            }

            authorizeRoute()
        }

        val response =
            client.get(
                "/oauth/authorize" +
                    "?client_id=test_client" +
                    "&redirect_uri=http://localhost:3000/callback" +
                    "&response_type=code",
            )

        Assertions.assertEquals(statusCode, response.status)
        Assertions.assertTrue(response.bodyAsText().contains(errorMessage))
    }

    @Test
    fun `GET oauth authorize - requires login redirects to login`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            given(
                oauthAuthorizationProcessService.authorize(
                    clientId = any(),
                    redirectUri = any(),
                    responseType = any(),
                    scope = anyOrNull(),
                    state = anyOrNull(),
                    codeChallenge = anyOrNull(),
                    codeChallengeMethod = anyOrNull(),
                    call = any(),
                ),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        mapOf(
                            "error" to "Unauthorized - No active session",
                            "statusCode" to HttpStatusCode.Unauthorized,
                            "requiresLogin" to true,
                        ),
                ),
            )

            application {
                configureSerialization()

                val secretEncryptKey =
                    hex(
                        Random.nextBytes(16)
                            .joinToString("") { "%02x".format(it) },
                    ) // 16 bytes = AES128
                val secretSignKey =
                    hex(
                        Random.nextBytes(16)
                            .joinToString("") { "%02x".format(it) },
                    ) // 16 bytes

                dependencies {
                    provide<SessionProvider>(DefaultSessionProvider::class)
                }

                install(Sessions) {
                    cookie<OauthUserSession>("OAUTH_USER_SESSION") {
                        cookie.httpOnly = true
                        cookie.secure = false // set true in production (HTTPS only)
                        cookie.maxAgeInSeconds = 31536000
                        transform(SessionTransportTransformerEncrypt(secretEncryptKey, secretSignKey))
                    }
                    cookie<String>("OAUTH_ORIGINAL_URL") {
                        cookie.httpOnly = true
                        cookie.secure = false // set true in production (HTTPS only)
                    }
                }

                dependencies {
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?client_id=test_client" +
                        "&redirect_uri=http://localhost:3000/callback" +
                        "&response_type=code",
                )

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals("/oauth/login", response.headers["Location"])
        }

    @Test
    fun `GET oauth authorize - requires consent redirects to consent`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            given(
                oauthAuthorizationProcessService.authorize(
                    clientId = any(),
                    redirectUri = any(),
                    responseType = any(),
                    scope = anyOrNull(),
                    state = anyOrNull(),
                    codeChallenge = anyOrNull(),
                    codeChallengeMethod = anyOrNull(),
                    call = any(),
                ),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        mapOf(
                            "error" to "Consent required",
                            "statusCode" to HttpStatusCode.BadRequest,
                            "requiresConsent" to true,
                            "clientId" to "test_client",
                        ),
                ),
            )

            application {
                configureSerialization()

                val secretEncryptKey =
                    hex(
                        Random.nextBytes(16)
                            .joinToString("") { "%02x".format(it) },
                    ) // 16 bytes = AES128
                val secretSignKey =
                    hex(
                        Random.nextBytes(16)
                            .joinToString("") { "%02x".format(it) },
                    ) // 16 bytes

                dependencies {
                    provide<SessionProvider>(DefaultSessionProvider::class)
                }

                install(Sessions) {
                    cookie<OauthUserSession>("OAUTH_USER_SESSION") {
                        cookie.httpOnly = true
                        cookie.secure = false // set true in production (HTTPS only)
                        cookie.maxAgeInSeconds = 31536000
                        transform(SessionTransportTransformerEncrypt(secretEncryptKey, secretSignKey))
                    }
                    cookie<String>("OAUTH_ORIGINAL_URL") {
                        cookie.httpOnly = true
                        cookie.secure = false // set true in production (HTTPS only)
                    }
                }

                dependencies {
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?client_id=test_client" +
                        "&redirect_uri=http://localhost:3000/callback" +
                        "&response_type=code",
                )

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals(
                "/oauth/consent?client_id=test_client",
                response.headers["Location"],
            )
        }

    @Test
    fun `GET oauth authorize - service failure without status code defaults to BadRequest`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            given(
                oauthAuthorizationProcessService.authorize(
                    clientId = any(),
                    redirectUri = any(),
                    responseType = any(),
                    scope = anyOrNull(),
                    state = anyOrNull(),
                    codeChallenge = anyOrNull(),
                    codeChallengeMethod = anyOrNull(),
                    call = any(),
                ),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        mapOf(
                            "error" to "Something went wrong",
                        ),
                ),
            )

            application {
                configureSerialization()

                dependencies {
                    provide { oauthAuthorizationProcessService }
                }

                authorizeRoute()
            }

            val response =
                client.get(
                    "/oauth/authorize" +
                        "?client_id=test_client" +
                        "&redirect_uri=http://localhost:3000/callback" +
                        "&response_type=code",
                )

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Something went wrong"))
        }
}
