package com.bittokazi.ktor.auth.services

import io.ktor.server.application.ApplicationCall

interface TemplateCustomizer {
    fun addExtraData(call: ApplicationCall): Map<String, Any>
}
