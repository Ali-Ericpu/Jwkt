plugins {
    id("com.gradleup.nmcp.settings") version "1.6.2"
}

rootProject.name = "jwkt"

nmcpSettings {
    val username = providers.environmentVariable("MAVEN_CENTRAL_USERNAME").orNull
    val password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD").orNull
    if (username != null && password != null) {
        centralPortal {
            this.username = username
            this.password = password
            publishingType = "AUTOMATIC"
        }
    }
}

include(":jwkt-spring-boot-starter")
