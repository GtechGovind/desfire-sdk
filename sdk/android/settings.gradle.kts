pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "org.jetbrains.kotlin.android" ||
                requested.id.id == "org.jetbrains.kotlin.jvm"
            ) {
                useModule("org.jetbrains.kotlin:kotlin-gradle-plugin:${requested.version}")
            }
        }
    }
}
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "desfire-ev3-android"
include(":desfire-kotlin")
project(":desfire-kotlin").projectDir = file("../kotlin")
include(":example-app")
project(":example-app").projectDir = file("../../examples/android-app")
