"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.addEntities = addEntities;
exports.existingIdentifiers = existingIdentifiers;
exports.unredactText = unredactText;
exports.redactText = redactText;
const redactor_1 = require("./redactor");
// ---------------------------------------------------------------------------
// Shared entity map
// ---------------------------------------------------------------------------
/**
 * Module-level entity map, persisted for the lifetime of the plugin process.
 *
 * The preprocessor registers entities as they are detected; the generator
 * uses the same map to:
 * - re-redact the chat history before sending it to the third-party API
 *   (earlier turns may still contain original values),
 * - un-redact the model's response before showing it to the user.
 *
 * The map never leaves this process — the third-party API only ever sees
 * placeholders.
 */
const entities = new Map();
/** Normalised lookup key for an original value (case-insensitive, trimmed). */
function normalize(text) {
    return text.toLowerCase().trim();
}
/**
 * Register entities detected by the preprocessor. Entities already present
 * (same normalised original) are kept as-is, so identifiers stay stable
 * across turns.
 */
function addEntities(newEntities) {
    for (const entity of newEntities) {
        const key = normalize(entity.original);
        if (!entities.has(key)) {
            entities.set(key, entity);
        }
    }
}
/**
 * Map from normalised original → identifier, used by the redactor to reuse
 * identifiers assigned in earlier turns.
 */
function existingIdentifiers() {
    const map = new Map();
    for (const [key, entity] of entities) {
        map.set(key, entity.identifier);
    }
    return map;
}
/**
 * Replace every placeholder in `text` with its original value.
 * Used to un-redact the assistant's response before showing it to the user.
 * Tolerates extra surrounding brackets the model may have added
 * (e.g. "[[[[EMAIL_1]]]]").
 */
function unredactText(text) {
    let result = text;
    for (const entity of entities.values()) {
        const placeholder = (0, redactor_1.escapeRegExp)((0, redactor_1.buildPlaceholder)(entity.identifier));
        const pattern = new RegExp(`\\[*${placeholder}\\]*`, "g");
        result = result.replace(pattern, entity.original);
    }
    return result;
}
/**
 * Replace every known original value in `text` with its placeholder.
 * Used to re-redact the chat history before sending it to the API.
 * Substitutions are longest-match-first to avoid partial overlaps.
 */
function redactText(text) {
    const sorted = [...entities.values()].sort((a, b) => b.original.length - a.original.length);
    let result = text;
    for (const entity of sorted) {
        const pattern = new RegExp((0, redactor_1.escapeRegExp)(entity.original), "g");
        result = result.replace(pattern, (0, redactor_1.buildPlaceholder)(entity.identifier));
    }
    return result;
}
