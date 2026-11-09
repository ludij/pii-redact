"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.escapeRegExp = escapeRegExp;
exports.buildPlaceholder = buildPlaceholder;
exports.redact = redact;
exports.validatePlaceholders = validatePlaceholders;
// ---------------------------------------------------------------------------
// Placeholder helpers
// ---------------------------------------------------------------------------
/** Escape special regex characters in a literal string. */
function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
/**
 * Build the placeholder string for a given identifier.
 * Format: [[[TYPE_N]]]
 */
function buildPlaceholder(identifier) {
    return `[[[${identifier}]]]`;
}
/**
 * Build a deterministic identifier key for a (type, counter) pair.
 * e.g. ("GIVEN_NAME", 1) → "GIVEN_NAME_1"
 */
function buildIdentifier(type, n) {
    return `${type}_${n}`;
}
// ---------------------------------------------------------------------------
// Redactor
// ---------------------------------------------------------------------------
/**
 * Build the starting counter per type so that new identifiers continue after
 * the highest number already assigned (avoids collisions across turns).
 */
function startingCounters(existing) {
    const maxima = new Map();
    for (const identifier of existing.values()) {
        // Labels may contain underscores (e.g. "GIVEN_NAME_1"), so the type part
        // is matched with [A-Z_]+ and the trailing counter with _\d+.
        const match = /^([A-Z_]+)_(\d+)$/.exec(identifier);
        if (match === null) {
            continue;
        }
        const type = match[1];
        const n = parseInt(match[2], 10);
        maxima.set(type, Math.max(maxima.get(type) ?? 0, n));
    }
    return [...maxima];
}
/**
 * Given the original text and a list of raw detected entities (ordered by
 * first appearance), assign unique identifiers, resolve coreferences, and
 * substitute all occurrences in the text.
 *
 * Rules:
 * - Entities are numbered per-type starting at 1.
 * - Coreference: if two raw entities have the same `original` value (case-
 *   insensitive), they share the same identifier.
 * - If `existing` is provided (normalized original → identifier), entities
 *   seen in earlier turns reuse their previous identifier, and new counters
 *   continue after the highest existing number per type.
 * - Substitution is performed longest-match-first to avoid partial overlaps
 *   (e.g. "John Smith" before "John").
 * - Placeholders are triple-bracket wrapped so downstream models are unlikely
 *   to alter them.
 */
function redact(text, rawEntities, existing) {
    // Step 1: Deduplicate and assign identifiers.
    // We preserve first-appearance order and merge identical originals.
    const counters = new Map(existing ? startingCounters(existing) : []);
    // Map from normalised original text → assigned identifier
    const canonicalMap = new Map();
    // Final ordered entity list (no duplicates)
    const entities = [];
    for (const raw of rawEntities) {
        const key = raw.original.toLowerCase().trim();
        if (canonicalMap.has(key)) {
            // Already assigned — coreference resolved
            continue;
        }
        const existingIdentifier = existing?.get(key);
        if (existingIdentifier !== undefined) {
            // Seen in an earlier turn — reuse the previous identifier
            canonicalMap.set(key, existingIdentifier);
            entities.push({ identifier: existingIdentifier, type: raw.type, original: raw.original });
            continue;
        }
        const n = (counters.get(raw.type) ?? 0) + 1;
        counters.set(raw.type, n);
        const identifier = buildIdentifier(raw.type, n);
        canonicalMap.set(key, identifier);
        entities.push({ identifier, type: raw.type, original: raw.original });
    }
    // Step 2: Build replacement pairs sorted by length descending (longest first)
    // to avoid replacing substrings of longer matches.
    const replacements = entities
        .map(e => ({
        original: e.original,
        placeholder: buildPlaceholder(e.identifier),
    }))
        .sort((a, b) => b.original.length - a.original.length);
    // Step 3: Perform substitutions.
    // We use a single-pass approach: scan the text left-to-right, greedily
    // matching the longest entity at each position.
    let redacted = text;
    for (const { original, placeholder } of replacements) {
        // Replace all occurrences (case-sensitive — the LLM returns exact spans).
        // We escape special regex characters in the original text.
        const escaped = escapeRegExp(original);
        redacted = redacted.replace(new RegExp(escaped, "g"), placeholder);
    }
    return { redacted_text: redacted, entities };
}
/**
 * Validate that no placeholder has been altered in the redacted text.
 * Returns true if all placeholders are intact.
 */
function validatePlaceholders(result) {
    for (const entity of result.entities) {
        const placeholder = buildPlaceholder(entity.identifier);
        if (!result.redacted_text.includes(placeholder)) {
            return false;
        }
    }
    return true;
}
