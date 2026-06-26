package com.bittokazi.ktor.auth.utils

import com.bittokazi.ktor.auth.services.TemplateCustomizerFactory
import com.bittokazi.ktor.auth.services.issuer.DefaultIssuerProvider
import com.bittokazi.ktor.auth.services.issuer.IssuerProvider
import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.respondText
import java.io.StringWriter

var issuerProvider: IssuerProvider? = null

fun Application.configureIssuerProvider() {
    val issuerProviderObject: IssuerProvider? by dependencies
    issuerProvider =
        if (issuerProviderObject == null) {
            DefaultIssuerProvider()
        } else {
            issuerProviderObject
        }
}

fun ApplicationCall.getBaseUrl(): String =
    issuerProvider?.getIssuer(this)
        ?: run {
            issuerProvider = DefaultIssuerProvider()
            issuerProvider!!.getIssuer(this)
        }

suspend fun ApplicationCall.respondMustache(
    templateCustomizerFactory: TemplateCustomizerFactory,
    template: String,
    model: Any,
) {
    val factory = templateCustomizerFactory.getFactory(this)

    val html =
        StringWriter().also {
            factory.compile(template)
                .execute(it, model)
                .flush()
        }.toString()

    respondText(html, ContentType.Text.Html)
}
