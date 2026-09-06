package com.desfire.ev3

import com.desfire.ev3.raw.ABI_VERSION
import com.desfire.ev3.raw.MANIFEST_SHA256

/** Load native code once and reject a C ABI whose identity differs from this Kotlin package. */
internal object NativeRuntime {
    init {
        System.loadLibrary("desfire_jni")
        check(abiVersion() == ABI_VERSION) { "DESFire native ABI version does not match Kotlin" }
        check(manifestSha256() == MANIFEST_SHA256) {
            "DESFire native operation manifest does not match Kotlin"
        }
    }

    /** Trigger object initialization from each private JNI facade. */
    fun ensureLoaded(): Unit = Unit

    @JvmStatic private external fun abiVersion(): Int
    @JvmStatic private external fun manifestSha256(): String
}
