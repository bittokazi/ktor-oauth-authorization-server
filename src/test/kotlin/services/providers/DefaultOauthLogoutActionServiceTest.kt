package services.providers

import com.bittokazi.ktor.auth.config.Oauth2Config
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.ApplicationResponse
import io.ktor.server.response.ResponseHeaders
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.mockito.BDDMockito
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.given
import org.mockito.kotlin.times
import org.mockito.kotlin.verify

class DefaultOauthLogoutActionServiceTest {
    private val mockCall = Mockito.mock(ApplicationCall::class.java)

    private val oauth2Config = Mockito.mock(Oauth2Config::class.java)

    private val oauthClientService = Mockito.mock(OauthClientService::class.java)

    private val oauthClientDTO = Mockito.mock(OAuthClientDTO::class.java)

    private val response = Mockito.mock(ApplicationResponse::class.java)

    private val headers = Mockito.mock(ResponseHeaders::class.java)

    private fun setupCallMocks() {
        BDDMockito.given(mockCall.response).willReturn(response)
        BDDMockito.given(response.headers).willReturn(headers)
    }

    @Test
    fun `afterLogoutAction calls configured redirect url`() =
        runTest {
            val fixture =
                DefaultOauthLogoutActionService(
                    oauth2Config = oauth2Config,
                    oauthClientService = oauthClientService,
                )

            setupCallMocks()
            given(oauthClientService.findByClientId(any(), any()))
                .willReturn(oauthClientDTO)
            given(oauthClientDTO.postLogoutRedirectUri)
                .willReturn("/app")

            fixture.afterLogoutAction(
                userId = "user_1",
                clientId = "client_1",
                call = mockCall,
            )

            verify(oauthClientService, times(1)).findByClientId(any(), any())
            verify(oauthClientDTO, times(1)).postLogoutRedirectUri
            verify(oauth2Config, times(0)).afterLogoutRedirectUrl
        }

    @Test
    fun `afterLogoutAction calls fallback redirect url`() =
        runTest {
            val fixture =
                DefaultOauthLogoutActionService(
                    oauth2Config = oauth2Config,
                    oauthClientService = oauthClientService,
                )

            setupCallMocks()
            given(oauthClientService.findByClientId(any(), any()))
                .willReturn(null)

            fixture.afterLogoutAction(
                userId = "user_1",
                clientId = "client_1",
                call = mockCall,
            )

            verify(oauthClientService, times(1)).findByClientId(any(), any())
            verify(oauthClientDTO, times(0)).postLogoutRedirectUri
            verify(oauth2Config, times(1)).afterLogoutRedirectUrl
        }

    @Test
    fun `afterLogoutAction calls fallback redirect url when post logout url is null`() =
        runTest {
            val fixture =
                DefaultOauthLogoutActionService(
                    oauth2Config = oauth2Config,
                    oauthClientService = oauthClientService,
                )

            setupCallMocks()
            given(oauthClientService.findByClientId(any(), any()))
                .willReturn(oauthClientDTO)
            given(oauthClientDTO.postLogoutRedirectUri)
                .willReturn(null)

            fixture.afterLogoutAction(
                userId = "user_1",
                clientId = "client_1",
                call = mockCall,
            )

            verify(oauthClientService, times(1)).findByClientId(any(), any())
            verify(oauthClientDTO, times(1)).postLogoutRedirectUri
            verify(oauth2Config, times(1)).afterLogoutRedirectUrl
        }

    @Test
    fun `afterLogoutAction calls fallback redirect url when client id is null`() =
        runTest {
            val fixture =
                DefaultOauthLogoutActionService(
                    oauth2Config = oauth2Config,
                    oauthClientService = oauthClientService,
                )

            setupCallMocks()

            fixture.afterLogoutAction(
                userId = "user_1",
                clientId = null,
                call = mockCall,
            )

            verify(oauthClientService, times(0)).findByClientId(any(), any())
            verify(oauthClientDTO, times(0)).postLogoutRedirectUri
            verify(oauth2Config, times(1)).afterLogoutRedirectUrl
        }

    @Test
    fun `afterLogoutAction calls fallback redirect url when no client found`() =
        runTest {
            val fixture =
                DefaultOauthLogoutActionService(
                    oauth2Config = oauth2Config,
                    oauthClientService = oauthClientService,
                )

            setupCallMocks()
            given(oauthClientService.findByClientId(any(), any()))
                .willReturn(null)

            fixture.afterLogoutAction(
                userId = "user_1",
                clientId = "client_1",
                call = mockCall,
            )

            verify(oauthClientService, times(1)).findByClientId(any(), any())
            verify(oauthClientDTO, times(0)).postLogoutRedirectUri
            verify(oauth2Config, times(1)).afterLogoutRedirectUrl
        }
}
