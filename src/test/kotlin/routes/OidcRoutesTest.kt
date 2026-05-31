package routes

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.bittokazi.ktor.auth.configureSecurity
import com.bittokazi.ktor.auth.configureSerialization
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.routes.oidcRoutes
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.oidc.OidcService
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.di.*
import io.ktor.server.testing.*
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
import java.util.*

@RunWith(MockitoJUnitRunner::class)
@ExtendWith(MockitoExtension::class)
class OidcRoutesTest {
    @Mock
    lateinit var oidcService: OidcService

    // ==================== GET /oauth/userinfo Tests ====================

    @Test
    fun `GET userinfo - success`() =
        testApplication {
            val token = tokenGenerator()

            given(
                oidcService.getUserInfo(
                    authHeader = eq("Bearer $token"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        mapOf(
                            "sub" to "user_999",
                            "email" to "user@example.com",
                            "name" to "John Doe",
                        ),
                ),
            )

            application {
                configureSerialization()

                dependencies {
                    provide(SessionCustomizer::class)
                }
                configureSecurity()

                authentication {
                    oidcOauthAuthenticationTestConfig()
                }
                dependencies {
                    provide { oidcService }
                }

                oidcRoutes()
            }

            val response =
                client.get("/oauth/userinfo") {
                    header("Authorization", "Bearer $token")
                }

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("user_999"))
            Assertions.assertTrue(response.bodyAsText().contains("user@example.com"))
        }

    @ParameterizedTest
    @CsvSource(
        "No Authorization Provided,Unauthorized",
        "Invalid authorization token,Unauthorized",
        "Unauthorized,Unauthorized",
        "User not found,NotFound",
        "Some bad request error,BadRequest",
    )
    fun `GET userinfo - service failures with mapped status codes`(
        errorMessage: String,
        expectedStatusName: String,
    ) = testApplication {
        val token = tokenGenerator()

        val expectedStatus =
            when (expectedStatusName) {
                "Unauthorized" -> HttpStatusCode.Unauthorized
                "NotFound" -> HttpStatusCode.NotFound
                else -> HttpStatusCode.BadRequest
            }

        given(
            oidcService.getUserInfo(
                authHeader = anyOrNull(),
                call = any(),
            ),
        ).willReturn(
            Result.Failure(
                errorBody = errorMessage,
            ),
        )

        application {
            configureSerialization()

            dependencies {
                provide(SessionCustomizer::class)
            }

            configureSecurity()

            authentication {
                oidcOauthAuthenticationTestConfig()
            }

            dependencies {
                provide { oidcService }
            }

            oidcRoutes()
        }

        val response =
            client.get("/oauth/userinfo") {
                header("Authorization", "Bearer $token")
            }

        Assertions.assertEquals(expectedStatus, response.status)
        Assertions.assertTrue(response.bodyAsText().contains(errorMessage))
    }

    // ==================== GET /.well-known/openid-configuration Tests ====================

    @Test
    fun `GET openid-configuration - success`() =
        testApplication {
            val token = tokenGenerator()

            given(
                oidcService.getOpenIdConfiguration(
                    baseUrl = any(),
                    issuer = any(),
                ),
            ).willReturn(
                mapOf(
                    "issuer" to "http://localhost",
                    "authorization_endpoint" to "http://localhost/oauth/authorize",
                    "userinfo_endpoint" to "http://localhost/oauth/userinfo",
                ),
            )

            application {
                configureSerialization()

                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                authentication {
                    oidcOauthAuthenticationTestConfig()
                }

                dependencies {
                    provide { oidcService }
                }

                oidcRoutes()
            }

            val response = client.get("/.well-known/openid-configuration")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("http://localhost"))
            Assertions.assertTrue(response.bodyAsText().contains("authorization_endpoint"))
        }

    // ==================== GET /.well-known/jwks.json Tests ====================

    @Test
    fun `GET jwks json - success`() =
        testApplication {
            val token = tokenGenerator()

            given(
                oidcService.getJwksConfiguration(),
            ).willReturn(
                mapOf(
                    "keys" to
                        listOf(
                            mapOf(
                                "kty" to "RSA",
                                "kid" to "key_1",
                            ),
                        ),
                ),
            )

            application {
                configureSerialization()

                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                authentication {
                    oidcOauthAuthenticationTestConfig()
                }

                dependencies {
                    provide { oidcService }
                }

                oidcRoutes()
            }

            val response = client.get("/.well-known/jwks.json")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("keys"))
            Assertions.assertTrue(response.bodyAsText().contains("RSA"))
        }

    private fun tokenGenerator(): String? {
        val token =
            JWT.create()
                .withAudience("audience")
                .withIssuer("issuer")
                .withClaim("username", "username")
                .withExpiresAt(Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.HMAC256("secret"))
        return token
    }
}

fun AuthenticationConfig.oidcOauthAuthenticationTestConfig() {
    jwt {
        realm = "ktor-oauth-server"

        verifier(
            JWT
                .require(Algorithm.HMAC256("secret"))
                .withAudience("audience")
                .withIssuer("issuer")
                .build(),
        )

        validate { credential ->
            if (credential.payload.getClaim("username").asString() != "") {
                JWTPrincipal(credential.payload)
            } else {
                null
            }
        }
    }
}
