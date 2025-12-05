package com.bittokazi.ktor.auth.utils

import java.security.MessageDigest
import java.util.Base64

object Utils {

    fun generateUserCode(): String {
        val chars = ('A'..'Z')
        fun block() = (1..4).map { chars.random() }.joinToString("")
        return "${block()}-${block()}"
    }

    fun verifyPkce(codeVerifier: String, codeChallenge: String): Boolean {
        val hashed = MessageDigest.getInstance("SHA-256")
            .digest(codeVerifier.toByteArray(Charsets.UTF_8))

        val computedChallenge = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(hashed)

        return computedChallenge == codeChallenge
    }
}
