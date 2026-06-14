package services.issuer

import com.bittokazi.ktor.auth.services.issuer.DefaultIssuerProvider
import io.ktor.http.RequestConnectionPoint
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.ApplicationRequest
import io.ktor.util.Attributes
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.BDDMockito.given
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import kotlin.test.assertEquals

@RunWith(MockitoJUnitRunner::class)
class DefaultIssuerProviderTest {
    @Mock
    lateinit var call: ApplicationCall

    @Mock
    lateinit var request: ApplicationRequest

    @Mock
    lateinit var origin: RequestConnectionPoint

    @Mock
    lateinit var attributes: Attributes

    lateinit var issuerProvider: DefaultIssuerProvider

    @Before
    fun setUp() {
        issuerProvider = DefaultIssuerProvider()
    }

    // ==================== SUCCESS CASES ====================

    @Test
    fun `getIssuer() returns correct URL for HTTPS with default port 443`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://example.com", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for HTTP with default port 80`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(80)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://example.com", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for HTTP with custom port`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(8080)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://example.com:8080", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for HTTPS with custom port`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(8443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://example.com:8443", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for localhost with HTTP`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("localhost")
        given(origin.serverPort).willReturn(80)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://localhost", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for localhost with custom port`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("localhost")
        given(origin.serverPort).willReturn(8080)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://localhost:8080", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for numeric IP address with custom port`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("192.168.1.1")
        given(origin.serverPort).willReturn(9090)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://192.168.1.1:9090", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for IP address with HTTPS`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("192.168.1.1")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://192.168.1.1", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for subdomain with HTTPS default port`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("auth.example.com")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://auth.example.com", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for subdomain with custom port`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("auth.example.com")
        given(origin.serverPort).willReturn(8443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://auth.example.com:8443", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for HTTP with port 1024`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("api.example.com")
        given(origin.serverPort).willReturn(1024)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://api.example.com:1024", actual)
    }

    @Test
    fun `getIssuer() returns correct URL for HTTPS with port 65535 (max port)`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(65535)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://example.com:65535", actual)
    }

    // ==================== EDGE CASES ====================

    @Test
    fun `getIssuer() handles HTTP with port 443 (non-standard)`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        // Port 443 is only omitted for HTTPS, not HTTP
        assertEquals("http://example.com:443", actual)
    }

    @Test
    fun `getIssuer() handles HTTPS with port 80 (non-standard)`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("example.com")
        given(origin.serverPort).willReturn(80)

        val actual = issuerProvider.getIssuer(call)

        // Port 80 is only omitted for HTTP, not HTTPS
        assertEquals("https://example.com:80", actual)
    }

    @Test
    fun `getIssuer() handles single letter hostname`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("a")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://a", actual)
    }

    @Test
    fun `getIssuer() handles hostname with hyphen`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("my-hostname.example.com")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://my-hostname.example.com", actual)
    }

    @Test
    fun `getIssuer() handles port 8080 with HTTP`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("http")
        given(origin.serverHost).willReturn("dev.example.com")
        given(origin.serverPort).willReturn(8080)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("http://dev.example.com:8080", actual)
    }

    @Test
    fun `getIssuer() handles multiple subdomain levels`() {
        given(call.request).willReturn(request)
        given(request.call).willReturn(call)
        given(call.attributes).willReturn(attributes)
        given(request.origin).willReturn(origin)
        given(origin.scheme).willReturn("https")
        given(origin.serverHost).willReturn("api.v1.oauth.example.com")
        given(origin.serverPort).willReturn(443)

        val actual = issuerProvider.getIssuer(call)

        assertEquals("https://api.v1.oauth.example.com", actual)
    }
}
