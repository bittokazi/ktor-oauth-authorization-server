package com.bittokazi.ktor.auth.services

import com.github.mustachejava.DefaultMustacheFactory
import com.github.mustachejava.MustacheFactory
import io.ktor.server.application.ApplicationCall

interface TemplateCustomizer {
    fun addExtraData(call: ApplicationCall): Map<String, Any>
}

interface TemplateCustomizerFactory {
    fun getFactory(call: ApplicationCall): MustacheFactory
}

class DefaultTemplateCustomizerFactory : TemplateCustomizerFactory {

    override fun getFactory(call: ApplicationCall): MustacheFactory {
        return DefaultMustacheFactory("templates")
    }
}
