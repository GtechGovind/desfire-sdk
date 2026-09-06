plugins { id("com.android.library") version "8.13.2"; kotlin("android") version "2.3.21" }
group = "com.desfire"
version = "0.1.0"
android {
    namespace = "com.desfire.ev3.android"
    compileSdk = 36
    ndkVersion = "29.0.14206865"
    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].resources.srcDir("build/generated/licenseResources")
    sourceSets["main"].jniLibs.srcDir(
        providers.gradleProperty("desfireNativeDirectory").getOrElse("build/native-jniLibs")
    )
    sourceSets["androidTest"].java.srcDir("../../examples/android")
}
dependencies {
    api(project(":desfire-kotlin"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
kotlin { jvmToolchain(17) }

val verifyNativeRuntime by tasks.registering {
    val nativeRoot = layout.projectDirectory.dir(
        providers.gradleProperty("desfireNativeDirectory").getOrElse("build/native-jniLibs")
    )
    inputs.dir(nativeRoot)
    doLast {
        for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86_64")) {
            for (library in listOf("libdesfire_c.so", "libdesfire_jni.so", "libc++_shared.so")) {
                check(nativeRoot.file("$abi/$library").asFile.isFile) {
                    "Missing $abi/$library: run sdk/android/tools/build_native.py before packaging."
                }
            }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyNativeRuntime) }
