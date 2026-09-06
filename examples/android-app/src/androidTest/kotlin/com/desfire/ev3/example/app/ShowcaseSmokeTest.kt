package com.desfire.ev3.example.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Launch the packaged showcase and verify its card-free expert confirmation path. */
@RunWith(AndroidJUnit4::class)
class ShowcaseSmokeTest {
    /** Navigate Compose, review exact raw input, and arm it without performing NFC I/O. */
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    /** Prove the APK launches and preserves the explicit raw review before admission. */
    @Test
    fun launchNavigateAndArmReviewedRawRequest() {
        compose.onNodeWithText("DESFire EV3 Showcase").assertIsDisplayed()
        compose.onNodeWithText("Raw").performClick()
        compose.onNodeWithText("Review raw request").performScrollTo().performClick()
        compose.onNodeWithText("EXPERT RAW REVIEW").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Confirm and arm").performClick()

        compose.waitUntil(timeoutMillis = 5_000) {
            compose.onAllNodesWithText("Raw request armed").fetchSemanticsNodes().isNotEmpty()
        }
    }
}
