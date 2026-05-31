package services.device.code

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.device.code.DefaultDeviceCodeProcessService
import com.bittokazi.ktor.auth.services.device.code.VerificationFailure
import com.bittokazi.ktor.auth.services.providers.*
import com.bittokazi.ktor.auth.services.session.SessionProvider
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.sessions.*
import io.ktor.util.*
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.BDDMockito.given
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@RunWith(MockitoJUnitRunner::class)
class DefaultDeviceCodeProcessServiceTest {
    @Mock lateinit var oauthClientService: OauthClientService

    @Mock lateinit var oauthLoginOptionService: OauthLoginOptionService

    @Mock lateinit var oauthDeviceCodeService: OauthDeviceCodeService

    @Mock lateinit var templateCustomizer: TemplateCustomizer

    @Mock lateinit var call: ApplicationCall

    @Mock lateinit var request: ApplicationRequest

    @Mock lateinit var sessions: CurrentSession

    @Mock lateinit var attributes: Attributes

    @Mock lateinit var origin: RequestConnectionPoint

    @Mock lateinit var sessionProvider: SessionProvider

    private lateinit var service: DefaultDeviceCodeProcessService

    @Before
    fun setUp() {
        service =
            DefaultDeviceCodeProcessService(
                oauthClientService,
                oauthLoginOptionService,
                oauthDeviceCodeService,
                templateCustomizer,
                sessionProvider,
            )

        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)
    }

    // -------------------------
    // createDeviceAuthorization
    // -------------------------

    @Test
    fun `createDeviceAuthorization returns failure when clientId is missing`() =
        runTest {
            val result = service.createDeviceAuthorization(null, "openid", call)

            assertTrue(result is Result.Failure)
            val error = (result as Result.Failure).errorBody
            assertEquals(400, error.first)
            assertEquals("Missing client_id", (error.second as Map<*, *>)["error"])
        }

    @Test
    fun `createDeviceAuthorization returns failure when scope is missing`() =
        runTest {
            val result = service.createDeviceAuthorization("client", null, call)

            assertTrue(result is Result.Failure)
            val error = (result as Result.Failure).errorBody
            assertEquals(400, error.first)
            assertEquals("Missing scope", (error.second as Map<*, *>)["error"])
        }

    @Test
    fun `createDeviceAuthorization returns failure when client is invalid`() =
        runTest {
            given(oauthClientService.findByClientId("client", call)).willReturn(null)

            val result = service.createDeviceAuthorization("client", "openid", call)

            assertTrue(result is Result.Failure)
            val error = (result as Result.Failure).errorBody
            assertEquals("Invalid client_id", (error.second as Map<*, *>)["message"])
        }

    @Test
    fun `createDeviceAuthorization returns failure when scopes are invalid`() =
        runTest {
            val client = mock<OAuthClientDTO>()
            given(client.scopes).willReturn(listOf("openid"))

            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.createDeviceAuthorization("client", "openid profile", call)

            assertTrue(result is Result.Failure)
            val error = (result as Result.Failure).errorBody
            assertEquals("Invalid scopes", (error.second as Map<*, *>)["message"])
        }

    @Test
    fun `createDeviceAuthorization returns success`() =
        runTest {
            val client = mock<OAuthClientDTO>()
            val clientId = UUID.randomUUID()

            given(client.id).willReturn(clientId)
            given(client.scopes).willReturn(listOf("openid", "profile"))

            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.createDeviceAuthorization("client", "openid profile", call)

            assertTrue(result is Result.Success)
            val data = (result as Result.Success).outcome

            assertTrue(data.containsKey("device_code"))
            assertTrue(data.containsKey("user_code"))
            assertEquals(1200, data["expires_in"])
            assertEquals(5, data["interval"])
        }

    // -------------------------
    // getDeviceVerificationPage
    // -------------------------

    private fun mockSession(
        userId: String,
        username: String,
        rememberMe: Boolean,
        expiresIn: Int = 3600 * 1000,
    ) {
        val expiresAt = System.currentTimeMillis() + expiresIn
        val session = OauthUserSession(userId, username, expiresAt, rememberMe)
        val sessionsMock = Mockito.mock<CurrentSession>()
        given(sessionProvider.getSession(call)).willReturn(sessionsMock)
        given(sessionsMock.get<OauthUserSession>()).willReturn(session)
    }

    @Test
    fun `getDeviceVerificationPage returns failure when session is null`() =
        runTest {
            val sessionsMock = Mockito.mock<CurrentSession>()
            given(sessionProvider.getSession(call)).willReturn(sessionsMock)
            given(sessionsMock.get<OauthUserSession>()).willReturn(null)

            given(request.queryParameters).willReturn(
                parametersOf(
                    "user_code",
                    "user_code",
                ),
            )

            val result = service.getDeviceVerificationPage(call)

            assertTrue(result is Result.Failure)
            assertEquals(VerificationFailure.LoginRequired, (result as Result.Failure).errorBody)
        }

    @Test
    fun `getDeviceVerificationPage returns failure when session expired`() =
        runTest {
            mockSession("user", "u", false, -1000)
            given(request.queryParameters).willReturn(
                parametersOf(
                    "user_code",
                    "user_code",
                ),
            )

            val result = service.getDeviceVerificationPage(call)

            assertTrue(result is Result.Failure)
            assertEquals(VerificationFailure.LoginRequired, (result as Result.Failure).errorBody)
        }

    @Test
    fun `getDeviceVerificationPage returns failure when login check not completed`() =
        runTest {
            mockSession("user", "u", false)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(false)

            given(request.queryParameters).willReturn(
                parametersOf(
                    "user_code",
                    "user_code",
                ),
            )

            val result = service.getDeviceVerificationPage(call)

            assertTrue(result is Result.Failure)
            assertTrue(result.errorBody is VerificationFailure.Template)
        }

    @Test
    fun `getDeviceVerificationPage returns success`() =
        runTest {
            mockSession("user", "u", false)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(templateCustomizer.addExtraData(call)).willReturn(mapOf("theme" to "dark"))

            given(request.queryParameters).willReturn(
                parametersOf(
                    "user_code",
                    "user_code",
                ),
            )

            val result = service.getDeviceVerificationPage(call)

            assertTrue(result is Result.Success)
            val data = (result as Result.Success).outcome

            assertEquals(false, data["result"])
            assertEquals("dark", data["theme"])
        }

    // -------------------------
    // verifyDeviceCode
    // -------------------------

    @Test
    fun `verifyDeviceCode returns failure when session is null`() =
        runTest {
            val sessionsMock = Mockito.mock<CurrentSession>()
            given(sessionProvider.getSession(call)).willReturn(sessionsMock)
            given(sessionsMock.get<OauthUserSession>()).willReturn(null)

            val result = service.verifyDeviceCode("code", call)

            assertTrue(result is Result.Failure)
            assertEquals(VerificationFailure.LoginRequired, (result as Result.Failure).errorBody)
        }

    @Test
    fun `verifyDeviceCode returns failure when login check fails`() =
        runTest {
            mockSession("user", "u", true)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(false)

            val result = service.verifyDeviceCode("code", call)

            assertTrue(result is Result.Failure)
            assertTrue(result.errorBody is VerificationFailure.Template)
        }

    @Test
    fun `verifyDeviceCode returns failure when userCode is null`() =
        runTest {
            mockSession("user", "u", true)

            given(templateCustomizer.addExtraData(call)).willReturn(emptyMap())
            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)

            val result = service.verifyDeviceCode(null, call)

            assertTrue(result is Result.Failure)
            val failure = result.errorBody as VerificationFailure.Template
            assertTrue(failure.data["isInvalid"] == true)
        }

    @Test
    fun `verifyDeviceCode returns failure when device code not found`() =
        runTest {
            mockSession("user", "u", true)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(oauthDeviceCodeService.findByUserCode("code", call)).willReturn(null)

            val result = service.verifyDeviceCode("code", call)

            assertTrue(result is Result.Failure)
            val failure = result.errorBody as VerificationFailure.Template
            assertTrue(failure.data["isInvalid"] == true)
        }

    @Test
    fun `verifyDeviceCode returns success`() =
        runTest {
            mockSession("user", "u", true)

            val device = mock<OauthDeviceCodeDTO>()
            given(device.deviceCode).willReturn("device")

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(oauthDeviceCodeService.findByUserCode("code", call)).willReturn(device)

            val result = service.verifyDeviceCode("code", call)

            assertTrue(result is Result.Success)
            val data = (result as Result.Success).outcome

            assertEquals(true, data["isSuccess"])
        }
}
