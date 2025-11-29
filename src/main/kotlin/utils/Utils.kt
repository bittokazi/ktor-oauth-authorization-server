package com.bittokazi.ktor.auth.utils

object Utils {

    fun generateUserCode(): String {
        val chars = ('A'..'Z')
        fun block() = (1..4).map { chars.random() }.joinToString("")
        return "${block()}-${block()}"
    }
}
