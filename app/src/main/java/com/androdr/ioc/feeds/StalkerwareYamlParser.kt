package com.androdr.ioc.feeds

/**
 * Shared line-based YAML parser for the AssoEchap/stalkerware-indicators
 * `ioc.yaml` format. Used by [StalkerwareIndicatorsFeed] (which filters to
 * the `packages:` block) and [StalkerwareCertHashFeed] (which filters to the
 * `certificates:` block).
 *
 * The upstream schema is regular enough that a minimal state machine beats
 * pulling in a full YAML library:
 *
 *   - name: TheTruthSpy
 *     type: stalkerware
 *     packages:
 *     - com.apspy.app
 *     certificates:
 *     - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
 *     websites:
 *     - copy9.com
 *     c2:
 *       ips:
 *       - 1.2.3.4
 */
internal object StalkerwareYamlParser {

    /** One family's parsed record. */
    internal data class FamilyEntry(
        val name: String,
        val type: String,
        val packages: List<String>,
        val certificates: List<String>,
    )

    /**
     * Parses [yaml] into a list of [FamilyEntry]. Each `- name:` at column 0
     * opens a new family; subsequent lines populate that family until the
     * next `- name:`. Unknown blocks (c2, websites, distribution, …) are
     * skipped without disrupting state.
     *
     * Cert fingerprints are normalized to lowercase hex (colons and spaces
     * stripped) but **not** validated — callers decide whether to accept a
     * given cert string.
     */
    @Suppress("LoopWithTooManyJumpStatements", "NestedBlockDepth")
    internal fun parse(yaml: String): List<FamilyEntry> {
        val results = mutableListOf<FamilyEntry>()
        var currentName = ""
        // Default to "stalkerware" until the family declares its type.
        var currentType = "stalkerware"
        var currentPackages = mutableListOf<String>()
        var currentCerts = mutableListOf<String>()
        var inBlock: Block = Block.NONE

        fun flush() {
            if (currentName.isNotBlank() || currentPackages.isNotEmpty() || currentCerts.isNotEmpty()) {
                results += FamilyEntry(
                    name = currentName,
                    type = currentType,
                    packages = currentPackages.toList(),
                    certificates = currentCerts.toList(),
                )
            }
            currentName = ""
            // Reset type per family — otherwise an entry without `type:` would
            // inherit the previous family's classification.
            currentType = "stalkerware"
            currentPackages = mutableListOf()
            currentCerts = mutableListOf()
            inBlock = Block.NONE
        }

        for (line in yaml.lines()) {
            val trimmed = line.trimStart()
            when {
                line.startsWith("- name:") -> {
                    flush()
                    currentName = line.removePrefix("- name:").trim()
                }
                trimmed.startsWith("type:") -> {
                    currentType = trimmed.removePrefix("type:").trim()
                    inBlock = Block.NONE
                }
                trimmed == "packages:" -> inBlock = Block.PACKAGES
                trimmed == "certificates:" -> inBlock = Block.CERTIFICATES
                // Any other block-header ("websites:", "c2:", "distribution:",
                // "ips:", etc.) exits both packages and certificates blocks.
                trimmed.endsWith(":") && !trimmed.startsWith("- ") -> inBlock = Block.NONE
                // List item inside a tracked block.
                trimmed.startsWith("- ") && !line.startsWith("- name:") -> {
                    val value = trimmed.removePrefix("- ").trim()
                    when (inBlock) {
                        Block.PACKAGES -> if (value.contains('.') && !value.contains(' ')) {
                            currentPackages += value
                        }
                        Block.CERTIFICATES -> {
                            val normalized = value.lowercase().replace(":", "").replace(" ", "")
                            currentCerts += normalized
                        }
                        Block.NONE -> Unit
                    }
                }
                // Reset tracked block on a non-list, non-blank line at column 0
                // or lower indent — prevents a stray line between entries from
                // re-opening the previous block.
                line.isNotBlank() && !trimmed.startsWith("- ") -> inBlock = Block.NONE
            }
        }
        flush()
        return results
    }

    private enum class Block { NONE, PACKAGES, CERTIFICATES }
}
