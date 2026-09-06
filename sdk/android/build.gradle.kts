import groovy.json.JsonSlurper
import java.security.MessageDigest

plugins {
    id("com.android.library") version "9.4.0"
    kotlin("jvm") version "2.3.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.21" apply false
}
group = "com.desfire"
version = "0.1.0"
android {
    namespace = "com.desfire.ev3.android"
    compileSdk = 37
    ndkVersion = "29.0.14206865"
    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        disable += setOf("GradleDependency")
    }
    sourceSets {
        getByName("main") {
            resources.directories.add("build/generated/licenseResources")
            jniLibs.directories.add(
                providers.gradleProperty("desfireNativeDirectory")
                    .getOrElse("build/native-jniLibs")
            )
        }
        getByName("androidTest") {
            java.directories.add("../../examples/android")
        }
    }
}
dependencies {
    api(project(":desfire-kotlin"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
kotlin { jvmToolchain(17) }

val verifyNativeRuntime = tasks.register("verifyNativeRuntime") {
    val nativeRoot = layout.projectDirectory.dir(
        providers.gradleProperty("desfireNativeDirectory").getOrElse("build/native-jniLibs")
    )
    val evidenceFile = layout.projectDirectory.file(
        providers.gradleProperty("desfireNativeEvidence")
            .getOrElse("build/native/build-evidence.json")
    )
    inputs.dir(nativeRoot)
    inputs.file(evidenceFile)
    doLast {
        check(evidenceFile.asFile.isFile) {
            "Missing native build evidence: ${evidenceFile.asFile}"
        }
        val evidence = JsonSlurper().parse(evidenceFile.asFile) as Map<*, *>
        check((evidence["api"] as? Number)?.toInt() == 23) {
            "Native build evidence must target Android API 23."
        }
        check(evidence["cxx_standard"] == "26") {
            "Native build evidence must use the production C++26 mode."
        }
        check(evidence["openssl_version"] == "3.5.8" &&
            evidence["openssl_sha256"] ==
            "a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2"
        ) {
            "Native build evidence does not match the pinned OpenSSL source."
        }
        val ndkProperties = evidence["ndk_source_properties"] as? String
            ?: error("Native build evidence has no NDK source properties.")
        check(Regex("(?m)^Pkg\\.Revision = 29\\.0\\.14206865$").containsMatchIn(ndkProperties)) {
            "Native build evidence does not match Android NDK 29.0.14206865."
        }
        val evidenceAbis = evidence["abis"] as? Map<*, *>
            ?: error("Native build evidence has no ABI map.")
        for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86_64")) {
            val evidenceLibraries = evidenceAbis[abi] as? Map<*, *>
                ?: error("Native build evidence is missing ABI $abi.")
            for (library in listOf("libdesfire_c.so", "libdesfire_jni.so", "libc++_shared.so")) {
                val binary = nativeRoot.file("$abi/$library").asFile
                check(binary.isFile) {
                    "Missing $abi/$library: run sdk/android/tools/build_native.py before packaging."
                }
                val header = binary.inputStream().use { it.readNBytes(20) }
                check(header.size == 20 && header.copyOfRange(0, 4).contentEquals(
                    byteArrayOf(0x7F, 0x45, 0x4C, 0x46),
                )) {
                    "$abi/$library is not an ELF binary."
                }
                check(header[5].toInt() == 1) { "$abi/$library is not little-endian ELF." }
                val elfClass = header[4].toInt()
                val machine = (header[18].toInt() and 0xFF) or
                    ((header[19].toInt() and 0xFF) shl 8)
                val expectedArchitecture = when (abi) {
                    "arm64-v8a" -> 2 to 183
                    "armeabi-v7a" -> 1 to 40
                    "x86_64" -> 2 to 62
                    else -> error("Unsupported Android ABI $abi")
                }
                check(elfClass == expectedArchitecture.first &&
                    machine == expectedArchitecture.second
                ) {
                    "$abi/$library ELF architecture does not match its ABI directory."
                }
                val expected = evidenceLibraries[library] as? Map<*, *>
                    ?: error("Native build evidence is missing $abi/$library.")
                val expectedSize = (expected["size"] as? Number)?.toLong()
                    ?: error("Native build evidence has no size for $abi/$library.")
                check(binary.length() == expectedSize) {
                    "$abi/$library size differs from native build evidence."
                }
                val actualDigest = MessageDigest.getInstance("SHA-256").let { digest ->
                    binary.inputStream().use { input ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            digest.update(buffer, 0, count)
                        }
                    }
                    digest.digest().joinToString("") { "%02x".format(it) }
                }
                check(actualDigest == expected["sha256"]) {
                    "$abi/$library SHA-256 differs from native build evidence."
                }
            }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyNativeRuntime) }
