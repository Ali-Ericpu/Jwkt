import org.jetbrains.kotlin.gradle.dsl.ExplicitApiMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.20"
    `java-library`
    `maven-publish`
    signing
}

group = "com.rainccup.jwkt"
version = providers.gradleProperty("version").getOrElse("0.1.0")

repositories {
    mavenCentral()
}

kotlin {
    explicitApi = ExplicitApiMode.Strict
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.22.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.build {
    dependsOn(":jwkt-spring-boot-starter:build")
}

tasks.named("publishToMavenLocal") {
    dependsOn(":jwkt-spring-boot-starter:publishToMavenLocal")
}

tasks.jar {
    from("LICENSE") {
        into("META-INF")
    }
    from("NOTICE") {
        into("META-INF")
    }
    manifest {
        attributes(
            "Automatic-Module-Name" to "com.rainccup.jwkt",
            "Implementation-Title" to "JWKT",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Rainccup",
        )
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("JWKT")
                description.set("A tiny, JSON-framework-agnostic JWT (JWS compact) library for Kotlin/JVM.")
                url.set("https://github.com/rainccup/jwkt")
                scm {
                    connection.set("scm:git:https://github.com/rainccup/jwkt.git")
                    developerConnection.set("scm:git:ssh://git@github.com/rainccup/jwkt.git")
                    url.set("https://github.com/rainccup/jwkt")
                }
                issueManagement {
                    system.set("GitHub")
                    url.set("https://github.com/rainccup/jwkt/issues")
                }
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("rainccup")
                        name.set("Rainccup")
                        email.set("46434286+Ali-Ericpu@users.noreply.github.com")
                    }
                }
            }
        }
    }
}

val signingKey = providers.environmentVariable("SIGNING_KEY").orNull
    ?.takeIf { it.isNotBlank() }
val signingPassword = providers.environmentVariable("SIGNING_PASSWORD").orNull.orEmpty()

signing {
    isRequired = false
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["maven"])
    }
}

tasks.named("publish") {
    dependsOn(":jwkt-spring-boot-starter:publish")
}
