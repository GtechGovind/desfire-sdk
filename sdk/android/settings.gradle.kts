pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith("org.jetbrains.kotlin")) {
                useModule("org.jetbrains.kotlin:kotlin-gradle-plugin:${requested.version}")
            }
        }
    }
}
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "desfire-ev3-android"
include(":desfire-kotlin")
project(":desfire-kotlin").projectDir = file("../kotlin")
