package com.desfire.ev3.example.app

import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.desfire.ev3.example.presentation.ShowcaseViewModel
import com.desfire.ev3.example.presentation.screen.ShowcaseApp
import com.desfire.ev3.example.presentation.theme.DesfireShowcaseTheme

/** Android lifecycle and foreground-dispatch entry point for the Compose showcase. */
public class MainActivity : ComponentActivity() {
    private val viewModel: ShowcaseViewModel by viewModels()
    private var nfcAdapter: NfcAdapter? = null
    private lateinit var foregroundIntent: PendingIntent

    /** Configure screenshot protection, foreground NFC dispatch, and lifecycle-aware Compose UI. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        val mutabilityFlag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE
        } else {
            0
        }
        foregroundIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or mutabilityFlag,
        )
        setContent {
            val state by viewModel.state.collectAsStateWithLifecycle()
            DesfireShowcaseTheme {
                ShowcaseApp(state = state, actions = viewModel)
            }
        }
    }

    /** Deliver a foreground-dispatch NFC intent to the exclusive session owner. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleNfcIntent(intent)
        setIntent(Intent(this, javaClass))
    }

    /** Enable ISO-DEP foreground dispatch and process any initial NFC launch intent once. */
    override fun onResume() {
        super.onResume()
        val adapter = nfcAdapter
        val enabled = adapter?.isEnabled == true
        viewModel.updateNfcState(available = adapter != null, enabled = enabled)
        if (enabled) {
            adapter.enableForegroundDispatch(
                this,
                foregroundIntent,
                null,
                arrayOf(arrayOf(IsoDep::class.java.name)),
            )
            val launchIntent = intent
            setIntent(Intent(this, javaClass))
            handleNfcIntent(launchIntent)
        }
    }

    /** Disable discovery, cancel active card work, close ownership, and clear session keys. */
    override fun onPause() {
        nfcAdapter?.disableForegroundDispatch(this)
        viewModel.onHostPaused()
        super.onPause()
    }

    /** Accept only Android NFC discovery intents containing an ISO-DEP Tag. */
    private fun handleNfcIntent(intent: Intent?) {
        val action = intent?.action ?: return
        if (action != NfcAdapter.ACTION_TECH_DISCOVERED) {
            return
        }
        readTag(intent)?.let(viewModel::acceptTag)
    }

    /** Resolve a typed Tag extra on current Android and the legacy form on API 23-32. */
    @Suppress("DEPRECATION")
    private fun readTag(intent: Intent): Tag? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
        } else {
            intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        }
}
