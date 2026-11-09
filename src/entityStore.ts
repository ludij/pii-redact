import { buildPlaceholder, escapeRegExp } from "./redactor";
import type { PiiEntity } from "./types";

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
const entities = new Map<string, PiiEntity>();

/** Normalised lookup key for an original value (case-insensitive, trimmed). */
function normalize(text: string): string {
  return text.toLowerCase().trim();
}

/**
 * Register entities detected by the preprocessor. Entities already present
 * (same normalised original) are kept as-is, so identifiers stay stable
 * across turns.
 */
export function addEntities(newEntities: PiiEntity[]): void {
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
export function existingIdentifiers(): Map<string, string> {
  const map = new Map<string, string>();
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
export function unredactText(text: string): string {
  let result = text;
  for (const entity of entities.values()) {
    const placeholder = escapeRegExp(buildPlaceholder(entity.identifier));
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
export function redactText(text: string): string {
  const sorted = [...entities.values()].sort(
    (a, b) => b.original.length - a.original.length,
  );
  let result = text;
  for (const entity of sorted) {
    const pattern = new RegExp(escapeRegExp(entity.original), "g");
    result = result.replace(pattern, buildPlaceholder(entity.identifier));
  }
  return result;
}
