plugins { kotlin("jvm"); `maven-publish` }
group = "com.desfire"
version = "0.1.0"
repositories { mavenCentral() }
kotlin { jvmToolchain(17) }
dependencies { implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0") }

val examples = sourceSets.create("examples") {
    kotlin.srcDir("../../examples/kotlin")
    compileClasspath += sourceSets.main.get().output + configurations.runtimeClasspath.get()
    runtimeClasspath += output + compileClasspath
}
configurations[examples.implementationConfigurationName]
    .extendsFrom(configurations.implementation.get())
tasks.register("examplesCheck") {
    dependsOn(tasks.named("compileExamplesKotlin"))
}
publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
            pom {
                name.set("DESFire EV3 Kotlin SDK")
                description.set("Typed Kotlin/JVM facade over the DESFire EV3 C ABI")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        distribution.set("repo")
                    }
                }
            }
        }
    }
}
val nativeDirectory = providers.gradleProperty("desfireNativeDirectory")
tasks.test {
    failOnNoDiscoveredTests = false
}
tasks.register<JavaExec>("hostTest") {
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.desfire.ev3.HostTestKt")
    doFirst {
        systemProperty("java.library.path", nativeDirectory.get())
    }
}
