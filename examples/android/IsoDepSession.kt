package com.example

import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.desfire.ev3.ApplicationId
import com.desfire.ev3.android.AndroidCardSession
import com.desfire.ev3.getVersion
import com.desfire.ev3.selectApplication

/** Inspect a discovered tag without retrying or reconnecting a failed exchange. */
suspend fun readVersion(tag: Tag): ByteArray {
    val isoDep = requireNotNull(IsoDep.get(tag)) { "Tag does not expose ISO-DEP" }
    isoDep.connect()
    val session = AndroidCardSession.open(isoDep)
    return try {
        session.card.selectApplication(ApplicationId(0))
        session.card.getVersion()
    } finally {
        session.close()
    }
}
