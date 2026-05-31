package services.consent

import com.bittokazi.ktor.auth.OauthUserSession
import com.bittokazi.ktor.auth.domains.rest.Result
import com.bittokazi.ktor.auth.services.TemplateCustomizer
import com.bittokazi.ktor.auth.services.consent.DefaultConsentProcessService
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.session.SessionProvider
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.ApplicationRequest
import io.ktor.server.sessions.CurrentSession
import io.ktor.server.sessions.get
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
import java.util.UUID
import kotlin.test.assertTrue

@RunWith(MockitoJUnitRunner::class)
class DefaultConsentProcessServiceTest {
    @Mock lateinit var oauthClientService: OauthClientService

    @Mock lateinit var oauthConsentService: OauthConsentService

    @Mock lateinit var oauthLoginOptionService: OauthLoginOptionService

    @Mock lateinit var templateCustomizer: TemplateCustomizer

    @Mock lateinit var sessionProvider: SessionProvider

    @Mock lateinit var call: ApplicationCall

    @Mock lateinit var request: ApplicationRequest

    private lateinit var service: DefaultConsentProcessService

    @Before
    fun setUp() {
        service =
            DefaultConsentProcessService(
                oauthClientService,
                oauthConsentService,
                oauthLoginOptionService,
                templateCustomizer,
                sessionProvider,
            )
    }

    // -------------------------
    // getConsentPage
    // -------------------------

    private fun mockSession(
        userId: String,
        username: String,
        expiresAt: Long,
    ) {
        val session = OauthUserSession(userId, username, expiresAt, false)
        val sessionsMock = Mockito.mock(CurrentSession::class.java)
        given(sessionProvider.getSession(call)).willReturn(sessionsMock)
        given(sessionsMock.get<OauthUserSession>()).willReturn(session)
    }

    @Test
    fun `getConsentPage returns failure when session is null`() =
        runTest {
            val sessionsMock = Mockito.mock(CurrentSession::class.java)
            given(sessionProvider.getSession(call)).willReturn(sessionsMock)
            given(sessionsMock.get<OauthUserSession>()).willReturn(null)

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `getConsentPage returns failure when session expired`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() - 1000)

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `getConsentPage returns failure when login check not completed`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(false)

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `getConsentPage returns failure when clientId missing`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)

            val result = service.getConsentPage(null, call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `getConsentPage returns failure when client not found`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(oauthClientService.findByClientId("client", call)).willReturn(null)

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `getConsentPage returns success when no consent exists`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val client = mock<OAuthClientDTO>()
            given(client.id).willReturn(UUID.randomUUID())
            given(client.clientId).willReturn("client")
            given(client.clientName).willReturn("Test App")
            given(client.scopes).willReturn(listOf("openid", "profile"))
            given(client.consentRequired).willReturn(true)

            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(oauthClientService.findByClientId("client", call)).willReturn(client)
            given(oauthConsentService.getConsent(any(), any(), any())).willReturn(null)
            given(templateCustomizer.addExtraData(call)).willReturn(mapOf("theme" to "dark"))

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Success)
        }

    @Test
    fun `getConsentPage returns success when consent exists and all scopes approved`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val client = mock<OAuthClientDTO>()
            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Success)
        }

    @Test
    fun `getConsentPage returns success directly when consent not required`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val client = mock<OAuthClientDTO>()
            given(oauthLoginOptionService.isAfterLoginCheckCompleted(any(), any())).willReturn(true)
            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.getConsentPage("client", call)

            assertTrue(result is Result.Success)
        }

    // -------------------------
    // postConsent
    // -------------------------

    @Test
    fun `postConsent returns failure when session is null`() =
        runTest {
            val sessionsMock = Mockito.mock(CurrentSession::class.java)
            given(sessionProvider.getSession(call)).willReturn(sessionsMock)
            given(sessionsMock.get<OauthUserSession>()).willReturn(null)

            val result = service.processConsent("client", "approve", call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `postConsent returns failure when clientId or action missing`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val result = service.processConsent(null, null, call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `postConsent returns failure when client not found`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            given(oauthClientService.findByClientId("client", call)).willReturn(null)

            val result = service.processConsent("client", "approve", call)

            assertTrue(result is Result.Failure)
        }

    @Test
    fun `postConsent approve returns success`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val client = mock<OAuthClientDTO>()
            given(client.id).willReturn(UUID.randomUUID())
            given(client.scopes).willReturn(listOf("openid"))

            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.processConsent("client", "approve", call)

            assertTrue(result is Result.Success)
        }

    @Test
    fun `postConsent deny returns failure template`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val client = mock<OAuthClientDTO>()

            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.processConsent("client", "deny", call)

            assertTrue(result is Result.Success)
        }

    @Test
    fun `postConsent invalid action returns bad request`() =
        runTest {
            mockSession("user", "u", System.currentTimeMillis() + 10000)

            val client = mock<OAuthClientDTO>()
            given(oauthClientService.findByClientId("client", call)).willReturn(client)

            val result = service.processConsent("client", "invalid", call)

            assertTrue(result is Result.Failure)
        }
}
