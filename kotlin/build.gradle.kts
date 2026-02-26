plugins {
    kotlin("jvm") version libs.versions.kotlin apply false
}

subprojects {
    repositories {
        mavenCentral()
    }
}
