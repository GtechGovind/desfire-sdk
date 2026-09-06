package com.desfire.ev3.example.presentation.screen

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.desfire.ev3.Communication
import com.desfire.ev3.example.domain.model.ExampleAuthenticationProfile
import com.desfire.ev3.example.domain.model.ExampleKeyMode
import com.desfire.ev3.example.domain.model.FeatureSection
import com.desfire.ev3.example.domain.model.RawKind
import com.desfire.ev3.example.domain.model.TransactionKind
import com.desfire.ev3.example.presentation.ShowcaseState
import com.desfire.ev3.example.presentation.ShowcaseViewModel

/** Render the complete six-section SDK showcase and canonical operation catalog. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ShowcaseApp(state: ShowcaseState, actions: ShowcaseViewModel) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("DESFire EV3 Showcase", fontWeight = FontWeight.SemiBold)
                        Text(
                            "Typed SDK · exact delivery evidence",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
            )
        },
    ) { contentPadding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(contentPadding),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item { StatusCard(state, actions::disconnect) }
            item { SectionNavigation(state.section, actions::selectSection) }
            item {
                Text(
                    state.section.summary,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            item {
                when (state.section) {
                    FeatureSection.DISCOVER -> DiscoverScreen(state, actions)
                    FeatureSection.AUTHENTICATE -> AuthenticationScreen(state, actions)
                    FeatureSection.FILES -> FilesScreen(state, actions)
                    FeatureSection.TRANSACTIONS -> TransactionsScreen(state, actions)
                    FeatureSection.RAW -> RawScreen(state, actions)
                    FeatureSection.OFFLINE -> OfflineScreen(state, actions)
                }
            }
            item { EvidenceCard(state) }
            item { HistoryAndSettingsCard(state) }
            item { OperationCatalogCard(state, actions::searchCatalog) }
        }
    }
}

/** Present NFC, card, application, key-source, and recovery-lock ownership. */
@Composable
private fun StatusCard(state: ShowcaseState, disconnect: () -> Unit) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("SESSION", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
            Text(
                when {
                    !state.nfcAvailable -> "NFC hardware unavailable"
                    !state.nfcEnabled -> "Enable NFC in Android settings"
                    state.unknownLocked -> "Locked after UNKNOWN delivery — rediscover card"
                    state.connected -> "Card connected"
                    else -> "Ready — present an ISO-DEP card"
                },
                style = MaterialTheme.typography.titleMedium,
                color = if (state.unknownLocked) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.primary,
            )
            Text(
                "AID ${state.selectedApplication?.let { "%06X".format(it) } ?: "—"}  ·  " +
                    "Key ${state.keySource}",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (state.connected || state.keySource != "NONE") {
                OutlinedButton(onClick = disconnect) { Text("Disconnect and clear keys") }
            }
        }
    }
}

/** Render six stable, horizontally scrollable feature destinations. */
@Composable
private fun SectionNavigation(selected: FeatureSection, select: (FeatureSection) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FeatureSection.entries.forEach { section ->
            FilterChip(
                selected = section == selected,
                onClick = { select(section) },
                label = { Text(section.title) },
            )
        }
    }
}

/** Card discovery and selection workflows that never mutate card contents. */
@Composable
private fun DiscoverScreen(state: ShowcaseState, actions: ShowcaseViewModel) {
    var aid by remember { mutableStateOf("000000") }
    FeatureCard("Card discovery", "Prerequisite: connected ISO-DEP card; no key for public data.") {
        ActionRow {
            Button(onClick = actions::readVersion, enabled = state.connected) { Text("Get version") }
            OutlinedButton(onClick = actions::readApplications, enabled = state.connected) {
                Text("Applications")
            }
            OutlinedButton(onClick = actions::readFreeMemory, enabled = state.connected) {
                Text("Free memory")
            }
        }
        InputField("Application ID", aid, { aid = it }, "000000 or 0x000000")
        Button(onClick = { actions.selectApplication(aid) }, enabled = state.connected) {
            Text("Select application")
        }
        CapabilityNote(
            "Applications and card management",
            "This group includes application create/delete, DF names, delegated application, UID, " +
                "originality, free memory, configuration, ATS, and ATQA APIs. High-risk forms stay " +
                "in the catalog until a deployment supplies its exact card-profile policy.",
        )
    }
}

/** Session-only Direct, Derived, and Provider key paths plus four AES profiles. */
@Composable
private fun AuthenticationScreen(state: ShowcaseState, actions: ShowcaseViewModel) {
    var mode by remember { mutableStateOf(ExampleKeyMode.DIRECT) }
    var profile by remember { mutableStateOf(ExampleAuthenticationProfile.EV2_FIRST) }
    var secret by remember { mutableStateOf("") }
    var diversification by remember { mutableStateOf("") }
    var reference by remember { mutableStateOf("") }
    var keyNumber by remember { mutableStateOf("0") }
    var applicationId by remember { mutableStateOf("") }

    LaunchedEffect(state.keySource, state.inputClearEpoch) {
        secret = ""
        if (state.inputClearEpoch > 0) {
            diversification = ""
            reference = ""
        }
    }
    FeatureCard(
        "Authentication and keys",
        "No default key. Values stay in this process only and are cleared on pause or disconnect.",
    ) {
        ChoiceField("Key source", mode.name) { mode = mode.next() }
        SecretField("AES-128 key or master key", secret) { secret = it }
        if (mode != ExampleKeyMode.DIRECT) {
            InputField(
                if (mode == ExampleKeyMode.GKEY_PROVIDER) "Card UID diversification"
                else "Diversification input",
                diversification,
                { diversification = it },
                if (mode == ExampleKeyMode.GKEY_PROVIDER) "At least six UID bytes, hex"
                else "Hex",
            )
        }
        if (mode == ExampleKeyMode.PROVIDER || mode == ExampleKeyMode.GKEY_PROVIDER) {
            InputField("Provider reference", reference, { reference = it }, "Non-secret hex ID")
        }
        ActionRow {
            Button(
                onClick = { actions.loadKey(mode, secret, diversification, reference) },
                enabled = secret.isNotBlank(),
            ) { Text("Load session key") }
            OutlinedButton(onClick = actions::clearKey, enabled = state.keySource != "NONE") {
                Text("Clear key")
            }
        }
        Spacer(Modifier.height(4.dp))
        ChoiceField("Authentication profile", profile.name) { profile = profile.next() }
        InputField("Key number", keyNumber, { keyNumber = it }, "0–63")
        InputField(
            "Expected selected application (optional)",
            applicationId,
            { applicationId = it },
            "Must match the active AID; blank uses it automatically",
        )
        Button(
            onClick = { actions.authenticate(profile, keyNumber, applicationId) },
            enabled = state.connected && state.keySource != "NONE" && !state.unknownLocked,
        ) { Text("Authenticate") }
        CapabilityNote(
            "Keys",
            "The SDK also exposes key versions, key sets, default AES key, key changes, and " +
                "transaction-MAC key providers. These mutations require deployment-specific key " +
                "authorization and are intentionally not prefilled.",
        )
    }
}

/** Typed file discovery, settings, and bounded data reads. */
@Composable
private fun FilesScreen(state: ShowcaseState, actions: ShowcaseViewModel) {
    var file by remember { mutableStateOf("0") }
    var offset by remember { mutableStateOf("0") }
    var length by remember { mutableStateOf("16") }
    var communication by remember { mutableStateOf(Communication.PLAIN) }
    FeatureCard(
        "Files",
        "Prerequisite: select an application; protected files also require the matching AES session.",
    ) {
        InputField("File number", file, { file = it }, "0–31")
        InputField("Offset", offset, { offset = it }, "Bytes")
        InputField("Length", length, { length = it }, "Bounded byte count")
        ChoiceField("Communication", communication.name) { communication = communication.next() }
        ActionRow {
            Button(onClick = actions::readFileIds, enabled = state.connected) { Text("List files") }
            OutlinedButton(
                onClick = { actions.readFileSettings(file) },
                enabled = state.connected,
            ) { Text("Settings") }
            OutlinedButton(
                onClick = { actions.readFile(file, offset, length, communication) },
                enabled = state.connected,
            ) { Text("Read data") }
        }
        CapabilityNote(
            "ISO files",
            "Typed ISO select, read binary, read records, challenge, and authentication operations " +
                "are discoverable in the catalog. True ISO expert exchange is available under Raw.",
        )
    }
}

/** Reviewed, twice-confirmed atomic mutation with UNKNOWN reconciliation guard. */
@Composable
private fun TransactionsScreen(state: ShowcaseState, actions: ShowcaseViewModel) {
    var aid by remember { mutableStateOf("000000") }
    var kind by remember { mutableStateOf(TransactionKind.CREDIT) }
    var file by remember { mutableStateOf("0") }
    var offset by remember { mutableStateOf("0") }
    var recordNumber by remember { mutableStateOf("0") }
    var amount by remember { mutableStateOf("1") }
    var data by remember { mutableStateOf("") }
    var communication by remember { mutableStateOf(Communication.FULL) }
    LaunchedEffect(state.inputClearEpoch) {
        if (state.inputClearEpoch > 0) data = ""
    }
    FeatureCard(
        "Reviewed transaction",
        "Prerequisite: matching selected AID, file policy, and authentication. No automatic retry.",
    ) {
        InputField("Application ID", aid, { aid = it }, "Must match active selection")
        ChoiceField("Operation", kind.name) { kind = kind.next() }
        InputField("File number", file, { file = it }, "0–31")
        if (kind == TransactionKind.WRITE_DATA || kind == TransactionKind.WRITE_RECORD ||
            kind == TransactionKind.UPDATE_RECORD
        ) {
            InputField("Offset", offset, { offset = it }, "Bytes")
            if (kind == TransactionKind.UPDATE_RECORD) {
                InputField("Record number", recordNumber, { recordNumber = it }, "0–16777215")
            }
            InputField("Data", data, { data = it }, "Hex bytes")
        } else if (kind != TransactionKind.CLEAR_RECORD_FILE) {
            InputField("Amount", amount, { amount = it }, "Unsigned 32-bit")
        }
        ChoiceField("Communication", communication.name) { communication = communication.next() }
        Button(
            onClick = {
                actions.reviewTransaction(
                    aid,
                    kind,
                    file,
                    offset,
                    recordNumber,
                    amount,
                    data,
                    communication,
                )
            },
            enabled = state.connected && !state.unknownLocked,
        ) { Text("Review transaction") }
        state.transactionReview?.let { review ->
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = MaterialTheme.shapes.medium,
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("FINAL REVIEW", fontWeight = FontWeight.Bold)
                    Text(review.description)
                    Text("This is the second and final dispatch confirmation.")
                    ActionRow {
                        Button(onClick = actions::confirmTransaction) { Text("Confirm and send") }
                        TextButton(onClick = actions::cancelTransactionReview) { Text("Cancel") }
                    }
                }
            }
        }
    }
}

/** Expert raw requests armed before a fresh, separately owned NFC session. */
@Composable
private fun RawScreen(state: ShowcaseState, actions: ShowcaseViewModel) {
    var kind by remember { mutableStateOf(RawKind.NATIVE) }
    var header by remember { mutableStateOf("60") }
    var data by remember { mutableStateOf("") }
    var maximum by remember { mutableStateOf("65536") }
    LaunchedEffect(state.rawReview, state.inputClearEpoch) {
        if (state.rawReview != null || state.inputClearEpoch > 0) data = ""
    }
    FeatureCard(
        "Raw channel",
        "Arming closes managed ownership. Present the card again; the exact request runs once.",
    ) {
        ChoiceField("Request type", kind.name) {
            kind = kind.next()
            header = if (kind == RawKind.NATIVE) "60" else "90600000"
        }
        InputField(
            if (kind == RawKind.NATIVE) "Command byte" else "CLA INS P1 P2",
            header,
            { header = it },
            "Hex",
        )
        InputField("Command data", data, { data = it }, "Optional hex")
        InputField("Maximum response", maximum, { maximum = it }, "Bytes")
        Button(onClick = { actions.reviewRaw(kind, header, data, maximum) }) {
            Text("Review raw request")
        }
        state.rawReview?.let { review ->
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = MaterialTheme.shapes.medium,
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("EXPERT RAW REVIEW", fontWeight = FontWeight.Bold)
                    Text(review.description)
                    Text("The opcode may mutate card state. Unknown delivery requires reconciliation.")
                    ActionRow {
                        Button(onClick = actions::confirmRaw) { Text("Confirm and arm") }
                        TextButton(onClick = actions::cancelRawReview) { Text("Cancel") }
                    }
                }
            }
        }
        Text(
            "Unknown opcodes require the caller to know command semantics. Secure raw messaging " +
                "requires explicit profile and layout and is available in the operation catalog.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        CapabilityNote(
            "Secure raw descriptors",
            "Standard AES, EV2, and ISO AES raw-session establishment plus explicit secure native " +
                "header/data/response policies are supported by the SDK. This form executes only " +
                "unprotected requests because secure layouts are command-specific.",
        )
    }
}

/** Show bounded in-memory operation history and fixed safety settings. */
@Composable
private fun HistoryAndSettingsCard(state: ShowcaseState) {
    FeatureCard(
        "History and safeguards",
        "In-memory only. Secret inputs and command payloads are excluded from history.",
    ) {
        Text(
            "Auto retry OFF · Screenshots OFF · Keys cleared on pause · Default timeout 5 s",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (state.history.isEmpty()) {
            Text("No operations recorded.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            state.history.take(6).forEach { snapshot ->
                Text(
                    "${snapshot.outcome.padEnd(9)}  ${snapshot.title}",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

/** Card-free AES derivation and transaction-MAC workflows. */
@Composable
private fun OfflineScreen(state: ShowcaseState, actions: ShowcaseViewModel) {
    var diversification by remember { mutableStateOf("") }
    var counter by remember { mutableStateOf("0") }
    var uid by remember { mutableStateOf("") }
    var tmi by remember { mutableStateOf("") }
    LaunchedEffect(state.inputClearEpoch) {
        if (state.inputClearEpoch > 0) {
            diversification = ""
            uid = ""
            tmi = ""
        }
    }
    FeatureCard(
        "Offline AES",
        "Load a session key first. Derived keys stay redacted; transaction input must be authoritative.",
    ) {
        InputField("Diversification input", diversification, { diversification = it }, "1–31 bytes hex")
        Button(
            onClick = { actions.deriveOffline(diversification) },
            enabled = state.keySource != "NONE",
        ) { Text("Derive and replace session key") }
        Spacer(Modifier.height(4.dp))
        Text("Transaction MAC", style = MaterialTheme.typography.titleSmall)
        InputField("Transaction counter", counter, { counter = it }, "Unsigned 32-bit")
        InputField("UID", uid, { uid = it }, "Complete hex UID")
        InputField("Transaction MAC input", tmi, { tmi = it }, "Complete authoritative TMI hex")
        Button(
            onClick = { actions.calculateTransactionMac(counter, uid, tmi) },
            enabled = state.keySource != "NONE" && uid.isNotBlank() && tmi.isNotBlank(),
        ) { Text("Calculate MAC") }
        Text(
            "The SDK does not construct EV3 transaction input automatically.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        CapabilityNote(
            "Complete offline family",
            "The catalog covers originality verification; delegated default-key encryption and " +
                "create/delete/configuration MACs; MIFARE Classic license MAC; transaction session " +
                "keys, MAC calculation/verification, and reader-ID decryption.",
        )
    }
}

/** Present exact operation result and delivery/reconciliation evidence together. */
@Composable
private fun EvidenceCard(state: ShowcaseState) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = if (state.snapshot.requiresReconciliation) {
                MaterialTheme.colorScheme.errorContainer
            } else {
                MaterialTheme.colorScheme.surface
            },
        ),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("LAST OPERATION", style = MaterialTheme.typography.labelMedium)
            Text(state.snapshot.title, style = MaterialTheme.typography.titleMedium)
            Text(state.snapshot.detail, fontFamily = FontFamily.Monospace)
            Text(state.snapshot.evidence(), fontFamily = FontFamily.Monospace)
        }
    }
}

/** Search stable operation IDs and prerequisites from the canonical binding manifest. */
@Composable
private fun OperationCatalogCard(state: ShowcaseState, search: (String) -> Unit) {
    FeatureCard(
        "Complete operation catalog",
        "${state.catalog.size} canonical SDK operations. Forms above cover common safe workflows; " +
            "the catalog identifies every expert capability and required input.",
    ) {
        InputField("Search operations", state.catalogQuery, search, "ID, name, domain, or input")
        Text(
            "${state.catalogMatches.size} match(es) · showing ${minOf(12, state.catalogMatches.size)}",
            style = MaterialTheme.typography.labelMedium,
        )
        state.catalogMatches.take(12).forEach { operation ->
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.small,
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(
                        "${operation.id} · ${operation.name}",
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "${operation.domain} · ${operation.surface} · " +
                            if (operation.mutation) "MUTATION" else "READ/LIFECYCLE",
                    )
                    Text(operation.summary, style = MaterialTheme.typography.bodySmall)
                    Text(
                        "Authentication: ${operation.authentication} · " +
                            "session: ${operation.sessionEffect}",
                        style = MaterialTheme.typography.labelSmall,
                    )
                    Text(
                        operation.prerequisites,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        operation.recovery,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** Shared elevated surface for one feature workflow. */
@Composable
private fun FeatureCard(
    title: String,
    prerequisite: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text(
                prerequisite,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            content()
        }
    }
}

/** Responsive horizontal action group that can wrap through its scroll container. */
@Composable
private fun ActionRow(content: @Composable RowScope.() -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        content = content,
    )
}

/** Standard non-secret text input. */
@Composable
private fun InputField(
    label: String,
    value: String,
    update: (String) -> Unit,
    supporting: String,
) {
    OutlinedTextField(
        value = value,
        onValueChange = update,
        modifier = Modifier.fillMaxWidth(),
        label = { Text(label) },
        supportingText = { Text(supporting) },
        singleLine = true,
    )
}

/** Password-masked, non-saveable secret input cleared after vault admission. */
@Composable
private fun SecretField(label: String, value: String, update: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = update,
        modifier = Modifier.fillMaxWidth(),
        label = { Text(label) },
        supportingText = { Text("Exactly 16 bytes (32 hex characters); never displayed or logged") },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
    )
}

/** Compact choice control that cycles a small enum without another dependency. */
@Composable
private fun ChoiceField(label: String, value: String, chooseNext: () -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Column {
            Text(label, style = MaterialTheme.typography.labelMedium)
            Text(value, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.width(12.dp))
        OutlinedButton(onClick = chooseNext) { Text("Change") }
    }
}

/** Describe grouped SDK coverage that needs deployment-specific inputs beyond the common form. */
@Composable
private fun CapabilityNote(title: String, detail: String) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Select the next key-source option. */
private fun ExampleKeyMode.next(): ExampleKeyMode =
    ExampleKeyMode.entries[(ordinal + 1) % ExampleKeyMode.entries.size]

/** Select the next authentication profile. */
private fun ExampleAuthenticationProfile.next(): ExampleAuthenticationProfile =
    ExampleAuthenticationProfile.entries[
        (ordinal + 1) % ExampleAuthenticationProfile.entries.size
    ]

/** Select the next communication policy. */
private fun Communication.next(): Communication =
    Communication.entries[(ordinal + 1) % Communication.entries.size]

/** Select the next transaction kind. */
private fun TransactionKind.next(): TransactionKind =
    TransactionKind.entries[(ordinal + 1) % TransactionKind.entries.size]

/** Select the next raw request family. */
private fun RawKind.next(): RawKind = RawKind.entries[(ordinal + 1) % RawKind.entries.size]
