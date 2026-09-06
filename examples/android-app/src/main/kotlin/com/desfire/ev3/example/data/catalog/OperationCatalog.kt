package com.desfire.ev3.example.data.catalog

import com.desfire.ev3.example.domain.model.CatalogOperation
import org.json.JSONObject

/** Loads and searches the packaged canonical operation manifest. */
internal object OperationCatalog {
    /** Parse the Gradle-bundled manifest and preserve stable operation IDs. */
    fun load(): List<CatalogOperation> {
        val stream = checkNotNull(javaClass.classLoader?.getResourceAsStream("operation-catalog.json")) {
            "Packaged operation catalog is missing."
        }
        val root = stream.bufferedReader(Charsets.UTF_8).use { JSONObject(it.readText()) }
        val operations = root.getJSONArray("operations")
        return buildList(operations.length()) {
            for (index in 0 until operations.length()) {
                val operation = operations.getJSONObject(index)
                val parameters = operation.optJSONArray("parameters")
                val inputs = buildList {
                    if (parameters != null) {
                        for (parameterIndex in 0 until parameters.length()) {
                            val parameter = parameters.getJSONObject(parameterIndex)
                            val semantic = parameter.optString("semanticType")
                            if (semantic != "card_handle" && semantic != "output" &&
                                semantic != "error"
                            ) {
                                add(parameterDescription(parameter))
                            }
                        }
                    }
                }
                val mutation = operation.getBoolean("mutation")
                val sessionEffect = operation.getString("sessionEffect")
                val deliveryRules = operation.getJSONArray("deliveryRules")
                val rules = buildList(deliveryRules.length()) {
                    for (ruleIndex in 0 until deliveryRules.length()) {
                        add(deliveryRules.getString(ruleIndex))
                    }
                }
                add(
                    CatalogOperation(
                        id = operation.getInt("id"),
                        name = operation.getString("name"),
                        domain = operation.getString("domain"),
                        summary = operation.getString("summary"),
                        mutation = mutation,
                        surface = operation.getString("surface"),
                        authentication = operation.optString("authentication")
                            .ifEmpty { "Not required or deployment-defined" },
                        sessionEffect = sessionEffect,
                        prerequisites = if (inputs.isEmpty()) {
                            "No operation-specific input"
                        } else {
                            "Inputs: ${inputs.joinToString()}"
                        },
                        recovery = recoveryDescription(mutation, sessionEffect, rules),
                    ),
                )
            }
        }
    }

    /** Match IDs, names, domains, summaries, and prerequisite names case-insensitively. */
    fun search(operations: List<CatalogOperation>, query: String): List<CatalogOperation> {
        val term = query.trim()
        if (term.isEmpty()) return operations
        return operations.filter { operation ->
            operation.id.toString().contains(term) || operation.name.contains(term, true) ||
                operation.domain.contains(term, true) || operation.summary.contains(term, true) ||
                operation.prerequisites.contains(term, true) ||
                operation.surface.contains(term, true) ||
                operation.authentication.contains(term, true) ||
                operation.sessionEffect.contains(term, true) ||
                operation.recovery.contains(term, true)
        }
    }

    /** Format manifest-declared type, range, units, and optionality for one public input. */
    private fun parameterDescription(parameter: JSONObject): String = buildString {
        append(parameter.getString("name"))
        append(" [${parameter.optString("semanticType", "value")}")
        if (parameter.has("minimum")) append(", min ${parameter.get("minimum")}")
        if (parameter.has("maximum")) append(", max ${parameter.get("maximum")}")
        parameter.optString("units").takeIf(String::isNotEmpty)?.let { append(", $it") }
        if (parameter.optBoolean("optional", false)) append(", optional")
        append(']')
    }

    /** Translate mutation, session, and delivery rules into operator-facing recovery guidance. */
    private fun recoveryDescription(
        mutation: Boolean,
        sessionEffect: String,
        rules: List<String>,
    ): String = buildString {
        if (mutation && "reconciliation_on_unknown" in rules) {
            append("UNKNOWN delivery requires reconciliation; never retry after send.")
        } else {
            append("Preserve the reported outcome and status; no automatic retry.")
        }
        if (sessionEffect != "none") append(" Session effect: $sessionEffect.")
    }
}
