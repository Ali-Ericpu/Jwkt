import org.jetbrains.kotlin.gradle.dsl.ExplicitApiMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    `java-library`
    `maven-publish`
    signing
}

group = "com.rainccup.jwkt"
version = rootProject.version

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

val boot3Version = "3.5.16"
val boot4Version = "4.1.2"

dependencies {
    api(project(":"))

    // The starter is consumed inside a Spring Boot application; do not force a Boot 3
    // compile-scope dependency into the published POM. Boot's BOM supplies the version.
    compileOnly("org.springframework.boot:spring-boot-autoconfigure:$boot3Version")

    // Optional integrations. Neither Jackson version is a runtime dependency of the starter.
    compileOnly("com.fasterxml.jackson.core:jackson-databind:2.21.4")
    compileOnly("tools.jackson.core:jackson-databind:3.1.7")

    testImplementation(platform("org.springframework.boot:spring-boot-dependencies:$boot3Version"))
    testImplementation(kotlin("test"))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-json")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

sourceSets {
    test {
        kotlin.srcDir("src/commonTest/kotlin")
    }

    val boot4Test = create("boot4Test") {
        kotlin.srcDir("src/boot4Test/kotlin")
        kotlin.srcDir("src/commonTest/kotlin")
        resources.srcDir("src/test/resources")
        compileClasspath += sourceSets.main.get().output
        runtimeClasspath += sourceSets.main.get().output
    }
}

configurations["boot4TestImplementation"].extendsFrom(configurations.implementation.get())
configurations["boot4TestRuntimeOnly"].extendsFrom(configurations.runtimeOnly.get())

kotlin {
    target.compilations.getByName("boot4Test")
        .associateWith(target.compilations.getByName("main"))
}

dependencies {
    "boot4TestImplementation"(platform("org.springframework.boot:spring-boot-dependencies:$boot4Version"))
    "boot4TestImplementation"(kotlin("test"))
    "boot4TestImplementation"("org.springframework.boot:spring-boot-starter-test")
    "boot4TestImplementation"("org.springframework.boot:spring-boot-starter-jackson")
    "boot4TestRuntimeOnly"("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

val boot4TestTask = tasks.register<Test>("boot4Test") {
    group = "verification"
    description = "Runs the starter tests against Spring Boot $boot4Version."
    testClassesDirs = sourceSets["boot4Test"].output.classesDirs
    classpath = sourceSets["boot4Test"].runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter(tasks.test)
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.check {
    dependsOn(boot4TestTask)
}

tasks.jar {
    from(rootProject.file("LICENSE")) {
        into("META-INF")
    }
    from(rootProject.file("NOTICE")) {
        into("META-INF")
    }
    manifest {
        attributes(
            "Automatic-Module-Name" to "com.rainccup.jwkt.spring",
            "Implementation-Title" to "JWKT Spring Boot Starter",
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
                name.set("JWKT Spring Boot Starter")
                description.set("Spring Boot auto-configuration for the JWKT JWT library.")
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
