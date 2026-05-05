plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktor)
    alias(libs.plugins.kotlin.plugin.serialization)

    // for publishing
    id("signing")
    id("maven-publish")
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
}

group = "com.bittokazi.sonartype"
version = "1.1.6"

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

    implementation(libs.ktor.utils)
    implementation(libs.ktor.server.auth)
    implementation(libs.ktor.server.auth.jwt)
    implementation(libs.ktor.serialization.gson)
    implementation(libs.bcrypt)

    implementation(libs.hikari.cp)
    implementation(libs.flyway.core)

    implementation(libs.nimbus.jose.jwt)

    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.mockito.core)
    testImplementation(libs.testcontainers.postgresql)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")
    testImplementation("io.ktor:ktor-server-test-host-jvm:3.4.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.5.0")

    // JUnit 5 Version
    val junitVersion = "5.10.0"

    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$junitVersion")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:5.10.0")

    // This is often what's missing for the "Could not start Gradle Test Executor" error
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Mockito for JUnit 5
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
}

tasks.test {
    useJUnitPlatform {
        includeEngines("junit-jupiter", "junit-vintage")
    }
}

java {
    withSourcesJar()
    withJavadocJar()
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("Ktor Oauth Authorization Server")
                description.set("Oauth Authorization Server Library for Ktor Framework")
                url.set("https://github.com/bittokazi/ktor-oauth-authorization-server")

                licenses {
                    license {
                        name.set("Apache License 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }

                developers {
                    developer {
                        id.set("bittokazi")
                        name.set("Bitto Kazi")
                        email.set("bitto.kazi@gmail.com")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/bittokazi/ktor-oauth-authorization-server.git")
                    developerConnection.set("scm:git:ssh://github.com/bittokazi/ktor-oauth-authorization-server.git")
                    url.set("github.com/bittokazi/ktor-oauth-authorization-server")
                }
            }
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
            username.set(System.getenv("CENTRAL_PUBLISHER_USERNAME"))
            password.set(System.getenv("CENTRAL_PUBLISHER_PASSWORD"))
        }
    }
}

val signingKey: String? = System.getenv("SIGNING_KEY")

signing {
    useInMemoryPgpKeys(signingKey, "")
    sign(publishing.publications["mavenJava"])
}
