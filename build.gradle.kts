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
version = "1.0.0"

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
