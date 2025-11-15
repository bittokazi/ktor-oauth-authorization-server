plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktor)
    alias(libs.plugins.kotlin.plugin.serialization)
}

group = "com.bittokazi.ktor.auth"
version = "0.0.1"

application {
    mainClass = "io.ktor.server.netty.EngineMain"
}

dependencies {
    implementation(libs.ktor.server.di)
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.postgresql)
    implementation(libs.ktor.server.sessions)
    implementation(libs.ktor.server.forwarded.header)
    implementation(libs.ktor.server.default.headers)
    implementation(libs.ktor.server.netty)
    implementation(libs.logback.classic)
    implementation(libs.ktor.server.config.yaml)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.exposed.java.time)
    implementation(libs.ktor.server.mustach)

    implementation("io.ktor:ktor-utils:${libs.versions.ktor}")
    implementation("io.ktor:ktor-server-auth:${libs.versions.ktor}")
    implementation("io.ktor:ktor-server-auth-jwt:${libs.versions.ktor}")
    implementation("io.ktor:ktor-serialization-gson:${libs.versions.ktor}")
    implementation("at.favre.lib:bcrypt:0.10.2")

    implementation("com.zaxxer:HikariCP:4.0.3")
    implementation("org.flywaydb:flyway-core:9.22.3")

    implementation("com.nimbusds:nimbus-jose-jwt:10.6")

    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.kotlin.test.junit)
}
