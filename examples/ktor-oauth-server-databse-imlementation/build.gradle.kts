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

    implementation("io.ktor:ktor-server-auth:${libs.versions.ktor}")
    implementation("io.ktor:ktor-server-auth-jwt:${libs.versions.ktor}")

    implementation(libs.ktor.server.config.yaml)
    implementation(libs.exposed.core)
    implementation(libs.exposed.jdbc)
    implementation(libs.postgresql)
    implementation("org.jetbrains.exposed:exposed-java-time:0.61.0")
    implementation("com.zaxxer:HikariCP:4.0.3")
    implementation("org.flywaydb:flyway-core:9.22.3")
    implementation("io.ktor:ktor-server-di:${libs.versions.ktor}")
    implementation("io.ktor:ktor-server-mustache:${libs.versions.ktor}")
    implementation("io.ktor:ktor-serialization-gson:${libs.versions.ktor}")
    implementation("at.favre.lib:bcrypt:0.10.2")
    implementation("com.nimbusds:nimbus-jose-jwt:10.6")

    if(testKtorOauthAuthLibrary) {
        implementation(files("../../build/libs/ktor-oauth-authorization-server-1.0.5.jar"))
    } else {
        implementation("com.bittokazi.sonartype:ktor-oauth-authorization-server:1.0.5")
    }

    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.kotlin.test.junit)
}
