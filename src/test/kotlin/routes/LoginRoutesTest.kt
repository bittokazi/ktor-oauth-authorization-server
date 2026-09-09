package routes

import at.favre.lib.crypto.bcrypt.BCrypt
import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.configureSecurity
import com.bittokazi.ktor.auth.configureSerialization
import com.bittokazi.ktor.auth.routes.loginRoutes
import com.bittokazi.ktor.auth.services.DefaultTemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.TemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OAuthUserDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthDeviceCodeService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.userSessionCheck
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
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
import kotlin.test.assertEquals

@RunWith(MockitoJUnitRunner::class)
@ExtendWith(MockitoExtension::class)
class LoginRoutesTest {
    @Mock
    lateinit var oauthUserService: OauthUserService

    @Mock
    lateinit var oauthLoginOptionService: OauthLoginOptionService

    @Mock
    lateinit var oauthTokenService: OauthTokenService

    @Mock
    lateinit var oauthAuthorizationCodeService: OauthAuthorizationCodeService

    @Mock
    lateinit var oauthDeviceCodeService: OauthDeviceCodeService

    // GET /oauth/login - renders the login template when no session exists
    @Test
    fun `GET oauth login - render login template`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                    install(HttpCookies) {
                        storage = AcceptAllCookiesStorage()
                    }
                }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthUserService }
                    provide<OauthLoginOptionService>(DefaultOauthLoginOptionService::class)
                    provide { oauthTokenService }
                    provide { oauthAuthorizationCodeService }
                    provide { oauthDeviceCodeService }
                    provide(SessionCustomizer::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                configureSecurity()

                loginRoutes()
            }

            val response = client.get("/oauth/login")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Login"))
        }

    // GET /oauth/login - redirect when session exists and is valid
    @Test
    fun `GET oauth login - redirect when session exists and is valid`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                    install(HttpCookies) {
                        storage = AcceptAllCookiesStorage()
                    }
                }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthUserService }
                    provide<OauthLoginOptionService>(DefaultOauthLoginOptionService::class)
                    provide { oauthTokenService }
                    provide { oauthAuthorizationCodeService }
                    provide { oauthDeviceCodeService }
                    provide(SessionCustomizer::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                configureSecurity()

                loginRoutes()

                routing {
                    get("/create/test/session") {
                        val ttlSeconds = 3600
                        val expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000)
                        val userSession = OauthUserSession("1", "user", expiresAt, false)
                        call.sessions.set(userSession)

                        userSessionCheck(call) {
                            call.respond(HttpStatusCode.OK, "ok")
                        }
                    }
                }
            }

            val create = client.get("/create/test/session")
            Assertions.assertEquals(HttpStatusCode.OK, create.status)
            Assertions.assertTrue(create.bodyAsText().contains("ok"))

            val response = client.get("/oauth/login")

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            assertEquals("/", response.headers["Location"])
        }

    // GET /oauth/login - redirect when session exists but is expired
    @Test
    fun `GET oauth login - redirect when session exists but is expired`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                    install(HttpCookies) {
                        storage = AcceptAllCookiesStorage()
                    }
                }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthUserService }
                    provide<OauthLoginOptionService>(DefaultOauthLoginOptionService::class)
                    provide { oauthTokenService }
                    provide { oauthAuthorizationCodeService }
                    provide { oauthDeviceCodeService }
                    provide(SessionCustomizer::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                configureSecurity()

                loginRoutes()

                routing {
                    get("/create/test/session") {
                        val ttlSeconds = 3600
                        val expiresAt = System.currentTimeMillis() - (ttlSeconds * 1000)
                        val userSession = OauthUserSession("1", "user", expiresAt, false)
                        call.sessions.set(userSession)
                        call.respond(HttpStatusCode.OK, "ok")
                    }
                }
            }

            val create = client.get("/create/test/session")
            Assertions.assertEquals(HttpStatusCode.OK, create.status)
            Assertions.assertTrue(create.bodyAsText().contains("ok"))

            val response = client.get("/oauth/login")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Login"))
        }

    // POST /oauth/login - invalid credentials should re-render template with error
    @Test
    fun `POST oauth login - invalid credentials`() =
        testApplication {
            given(
                oauthUserService.findByUsername(eq("bad_user"), any()),
            ).willReturn(null)

            val client = createClient { followRedirects = false }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthUserService }
                    provide { oauthLoginOptionService }
                    provide { oauthTokenService }
                    provide { oauthAuthorizationCodeService }
                    provide { oauthDeviceCodeService }
                    provide(SessionCustomizer::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                configureSecurity()

                loginRoutes()
            }

            val response =
                client.post("/oauth/login") {
                    setBody("username=bad_user&password=wrongpass")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Login credentials do not match"))
        }

    // POST /oauth/login - successful login should redirect using DefaultOauthLoginOptionService
    @Test
    fun `POST oauth login - success redirects`() =
        testApplication {
            // Create a user with bcrypt hashed password
            val plainPassword = "pass123"
            val hashed = BCrypt.withDefaults().hashToString(12, plainPassword.toCharArray())
            val user =
                OAuthUserDTO(
                    id = "1",
                    username = "good_user",
                    email = "user@example.com",
                    firstName = "Test",
                    lastName = "User",
                    isActive = true,
                    passwordHash = hashed,
                )

            given(
                oauthUserService.findByUsername(eq("good_user"), any()),
            ).willReturn(user)

            val client = createClient { followRedirects = false }

            application {
                configureSerialization()

                dependencies {
                    provide { oauthUserService }
                    provide { oauthTokenService }
                    provide { oauthAuthorizationCodeService }
                    provide { oauthDeviceCodeService }
                    provide(SessionCustomizer::class)
                    provide<OauthLoginOptionService>(DefaultOauthLoginOptionService::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                configureSecurity()

                loginRoutes()
            }

            val response =
                client.post("/oauth/login") {
                    setBody("username=good_user&password=$plainPassword")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            // DefaultOauthLoginOptionService will redirect to fallback "/"
            Assertions.assertEquals("/", response.headers["Location"])
        }
}
