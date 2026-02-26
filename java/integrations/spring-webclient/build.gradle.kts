plugins {
    `java-library`
}

dependencies {
    api(project(":lib"))
    api(libs.spring.webflux)
    implementation(libs.reactor.core)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(libs.reactor.test)
    testImplementation(libs.reactor.netty)
}
