package services

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.configureSecurity
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.userSessionCheck
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.testApplication
import org.junit.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.runner.RunWith
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.junit.jupiter.MockitoExtension
import kotlin.test.assertEquals

@RunWith(MockitoJUnitRunner::class)
@ExtendWith(MockitoExtension::class)
class UserSessionCheckTest {
    @Test
    fun `userSessionCheck - check valid session`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            application {
                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                routing {
                    get("/test/session") {
                        val ttlSeconds = 3600
                        val expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000)
                        val userSession = OauthUserSession("1", "user", expiresAt, true)
                        call.sessions.set(userSession)

                        userSessionCheck(call) {
                            call.respond(HttpStatusCode.OK, "ok")
                        }
                    }
                }
            }

            val response = client.get("/test/session")

            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals("ok", response.bodyAsText())
        }

    @Test
    fun `userSessionCheck - check null session`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            application {
                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                routing {
                    get("/test/session") {
                        userSessionCheck(call) {
                            call.respond(HttpStatusCode.OK, "ok")
                        }
                    }
                }
            }

            val response = client.get("/test/session")

            assertEquals(HttpStatusCode.Found, response.status)
            assertEquals("/oauth/login", response.headers["Location"])
        }

    @Test
    fun `userSessionCheck - check expired session`() =
        testApplication {
            val client =
                createClient {
                    followRedirects = false
                }

            application {
                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                routing {
                    get("/test/session") {
                        val ttlSeconds = 3600
                        val expiresAt = System.currentTimeMillis() - (ttlSeconds * 1000)
                        val userSession = OauthUserSession("1", "user", expiresAt, true)
                        call.sessions.set(userSession)

                        userSessionCheck(call) {
                            call.respond(HttpStatusCode.OK, "ok")
                        }
                    }
                }
            }

            val response = client.get("/test/session")

            assertEquals(HttpStatusCode.Found, response.status)
            assertEquals("/oauth/login", response.headers["Location"])
        }
}
