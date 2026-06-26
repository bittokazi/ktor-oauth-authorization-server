package routes

import com.bittokazi.ktor.auth.configureSecurity
import com.bittokazi.ktor.auth.configureSerialization
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.routes.consentRoute
import com.bittokazi.ktor.auth.services.DefaultTemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.TemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.consent.ConsentFailure
import com.bittokazi.ktor.auth.services.consent.ConsentProcessService
import com.bittokazi.ktor.auth.services.consent.TemplateContent
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
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
class ConsentRouteTest {
    @Mock
    lateinit var consentProcessService: ConsentProcessService

    @Mock
    lateinit var oauthLoginOptionService: OauthLoginOptionService

    // ==================== GET /oauth/consent ====================

    @Test
    fun `GET oauth consent - success mustache`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(
                    clientId = eq("test_client"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        TemplateContent(
                            "oauth_templates/consent.hbs",
                            mapOf(
                                "clientName" to "Test App",
                                "clientId" to "test_client",
                                "scopes" to listOf("openid"),
                            ),
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
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Test App"))
        }

    @Test
    fun `GET oauth consent - success complete login`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(
                    clientId = eq("test_client"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome = null,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                dependencies {
                    provide { consentProcessService }
                    provide<OauthLoginOptionService>(DefaultOauthLoginOptionService::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
        }

    // ==================== GET failure cases ====================

    @Test
    fun `GET oauth consent - login required redirects`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.LoginRequired,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals("/oauth/login", response.headers["Location"])
        }

    @Test
    fun `GET oauth consent - bad request`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.BadRequest,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid request"))
        }

    @Test
    fun `GET oauth consent - invalid client`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.InvalidClient,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid client_id"))
        }

    @Test
    fun `GET oauth consent - invalid action`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.InvalidAction,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid action"))
        }

    @Test
    fun `GET oauth consent - template failure`() =
        testApplication {
            given(
                consentProcessService.getConsentPage(any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        ConsentFailure.Template(
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
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.get("/oauth/consent?client_id=test_client")

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Template not found"))
        }

    // ==================== POST /oauth/consent ====================

    @Test
    fun `POST oauth consent - success mustache`() =
        testApplication {
            given(
                consentProcessService.processConsent(
                    clientId = eq("test_client"),
                    action = eq("approve"),
                    call = any(),
                ),
            ).willReturn(
                Result.Success(
                    outcome =
                        TemplateContent(
                            "oauth_templates/consent.hbs",
                            mapOf("clientName" to "Test App"),
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
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.OK, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Test App"))
        }

    @Test
    fun `POST oauth consent - success complete login`() =
        testApplication {
            given(
                consentProcessService.processConsent(any(), any(), any()),
            ).willReturn(
                Result.Success(
                    outcome = null,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide(SessionCustomizer::class)
                }

                configureSecurity()

                dependencies {
                    provide { consentProcessService }
                    provide<OauthLoginOptionService>(DefaultOauthLoginOptionService::class)
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
        }

    // ==================== POST failure cases ====================

    @Test
    fun `POST oauth consent - login required redirects`() =
        testApplication {
            given(
                consentProcessService.processConsent(any(), any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.LoginRequired,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.Found, response.status)
            Assertions.assertEquals("/oauth/login", response.headers["Location"])
        }

    @Test
    fun `POST oauth consent - bad request`() =
        testApplication {
            given(
                consentProcessService.processConsent(any(), any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.BadRequest,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid request"))
        }

    @Test
    fun `POST oauth consent - invalid client`() =
        testApplication {
            given(
                consentProcessService.processConsent(any(), any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.InvalidClient,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid client_id"))
        }

    @Test
    fun `POST oauth consent - invalid action`() =
        testApplication {
            given(
                consentProcessService.processConsent(any(), any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody = ConsentFailure.InvalidAction,
                ),
            )

            val client =
                createClient {
                    followRedirects = false
                }

            application {
                configureSerialization()

                dependencies {
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Invalid action"))
        }

    @Test
    fun `POST oauth consent - template failure`() =
        testApplication {
            given(
                consentProcessService.processConsent(any(), any(), any()),
            ).willReturn(
                Result.Failure(
                    errorBody =
                        ConsentFailure.Template(
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
                    provide { consentProcessService }
                    provide { oauthLoginOptionService }
                    provide<TemplateCustomizerFactory>(DefaultTemplateCustomizerFactory::class)
                }

                consentRoute()
            }

            val response =
                client.post("/oauth/consent?client_id=test_client") {
                    setBody("action=approve")
                    header(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded)
                }

            Assertions.assertEquals(HttpStatusCode.BadRequest, response.status)
            Assertions.assertTrue(response.bodyAsText().contains("Template not found"))
        }
}
