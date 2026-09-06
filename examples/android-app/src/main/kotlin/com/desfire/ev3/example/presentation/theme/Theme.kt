package com.desfire.ev3.example.presentation.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val ShowcaseColors = darkColorScheme(
    primary = Color(0xFF58D6B2),
    onPrimary = Color(0xFF00382D),
    primaryContainer = Color(0xFF164D42),
    onPrimaryContainer = Color(0xFFA9F2DB),
    secondary = Color(0xFF9CCAFF),
    onSecondary = Color(0xFF003258),
    background = Color(0xFF07131F),
    onBackground = Color(0xFFE4EEF5),
    surface = Color(0xFF0D1D2B),
    onSurface = Color(0xFFE4EEF5),
    surfaceVariant = Color(0xFF173047),
    onSurfaceVariant = Color(0xFFBAC9D5),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
)

/** Apply the showcase's high-contrast, developer-tool visual system. */
@Composable
internal fun DesfireShowcaseTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ShowcaseColors,
        typography = Typography(),
        content = content,
    )
}
