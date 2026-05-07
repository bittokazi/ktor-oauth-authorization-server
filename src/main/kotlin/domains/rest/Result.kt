package com.bittokazi.ktor.auth.domains.rest

sealed class Result<T, E> {
    data class Success<T, E>(
        val outcome: T,
    ) : Result<T, E>()

    data class Failure<T, E>(
        val errorBody: E,
    ) : Result<T, E>()
}
