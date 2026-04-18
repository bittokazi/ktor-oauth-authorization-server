plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktor)
    alias(libs.plugins.kotlin.plugin.serialization)
}

group = "com.bittokazi.example.ktor"
version = "0.0.1"

val testKtorOauthAuthLibrary: Boolean = false

application {
    mainClass = "io.ktor.server.netty.EngineMain"
}

dependencies {
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.server.auth)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.apache)
    implementation(libs.ktor.server.netty)
    implementation(libs.logback.classic)

    implementation(libs.ktor.server.auth.jwt)

    implementation(libs.ktor.server.config.yaml)
    implementation(libs.exposed.core)
    implementation(libs.exposed.dao)
    implementation(libs.exposed.jdbc)
    implementation(libs.postgresql)
    implementation(libs.exposed.java.time)
    implementation(libs.hikari.cp)
    implementation(libs.flyway.core)
    implementation(libs.ktor.server.di)
    implementation(libs.ktor.server.mustach)
    implementation(libs.ktor.serialization.gson)
    implementation(libs.ktor.server.forwarded.header)
    implementation(libs.ktor.server.default.headers)
    implementation(libs.bcrypt)
    implementation(libs.nimbus.jose.jwt)

    if(testKtorOauthAuthLibrary) {
        implementation(files("../../build/libs/ktor-oauth-authorization-server-1.1.6.jar"))
    } else {
        implementation("com.bittokazi.sonartype:ktor-oauth-authorization-server:1.1.6")
    }

    implementation(libs.ktor.client.cio)
    implementation(libs.ktor.client.content.negotiation)

    implementation(libs.googleauth)

    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.kotlin.test.junit)
}
