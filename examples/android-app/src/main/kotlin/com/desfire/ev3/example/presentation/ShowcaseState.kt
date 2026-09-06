package com.desfire.ev3.example.presentation

import com.desfire.ev3.example.domain.model.CatalogOperation
import com.desfire.ev3.example.domain.model.FeatureSection
import com.desfire.ev3.example.domain.model.OperationSnapshot
import com.desfire.ev3.example.domain.model.RawReview
import com.desfire.ev3.example.domain.model.TransactionReview

/** Immutable state rendered by the Compose showcase. Secret values are never stored here. */
internal data class ShowcaseState(
    val section: FeatureSection = FeatureSection.DISCOVER,
    val nfcAvailable: Boolean = true,
    val nfcEnabled: Boolean = false,
    val connected: Boolean = false,
    val selectedApplication: Int? = null,
    val unknownLocked: Boolean = false,
    val keySource: String = "NONE",
    val inputClearEpoch: Long = 0,
    val snapshot: OperationSnapshot = OperationSnapshot(
        title = "Ready",
        detail = "Open the showcase and present one ISO-DEP card.",
    ),
    val transactionReview: TransactionReview? = null,
    val rawReview: RawReview? = null,
    val history: List<OperationSnapshot> = emptyList(),
    val catalogQuery: String = "",
    val catalog: List<CatalogOperation> = emptyList(),
    val catalogMatches: List<CatalogOperation> = emptyList(),
)
