import type { LLMDynamicHandle } from "@lmstudio/sdk";
import { z } from "zod";
import { ALL_LABELS, Redact } from "@desert-ant-labs/redact/native";
import { detectViaSidecar, warmSidecar } from "./sidecar";
import {
  llmDetectionResponseSchema,
  type LlmDetectionResponse,
  type PiiType,
  type RawSpan,
} from "./types";

/** Every Redact label, including ORG — the plugin redacts organisations too. */
const ALL_LABELS_SET = new Set(ALL_LABELS);

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a privacy-focused PII (Personally Identifiable Information) detector.

Your task: analyse the user's text and return a JSON object listing every PII entity found.

Rules:
1. Detect the following entity types:
   - GIVEN_NAME        — first names, given names
   - SURNAME           — last names, family names
   - STREET_NAME       — street names
   - BUILDING_NUMBER   — house or building numbers
   - SECONDARY_ADDRESS — apartment, suite, floor, PO box
   - CITY              — cities and towns
   - STATE             — states, provinces, regions
   - ZIP_CODE          — postal codes
   - EMAIL             — email addresses
   - PHONE             — phone numbers (any format)
   - CREDIT_CARD       — credit card numbers
   - BANK_ACCOUNT      — bank account numbers, IBANs
   - ROUTING_NUMBER    — bank routing numbers
   - IP_ADDRESS        — IP addresses
   - URL               — URLs
   - GOVERNMENT_ID     — national ID numbers
   - PASSPORT          — passport numbers
   - DRIVERS_LICENSE   — driver's license numbers
   - TAX_ID            — tax identification numbers
   - SSN               — social security numbers
   - IMEI              — device identifiers
   - ORG               — company, organisation, institution names

2. For each entity return the EXACT substring as it appears in the text (preserve case and spacing).

3. Do NOT invent entities. Only return entities that are actually present in the text.

4. Return ONLY valid JSON matching this schema — no markdown, no extra keys:
{
  "entities": [
    { "original": "<exact text span>", "type": "<TYPE>" },
    ...
  ]
}

If no PII is found, return: { "entities": [] }`;

// ---------------------------------------------------------------------------
// Redact-based detector (on-device model)
// ---------------------------------------------------------------------------

/** Lazily-loaded Redact instance — the model downloads on first use and caches. */
let redactInstance: Redact | null = null;
let redactLoadPromise: Promise<Redact> | null = null;

/**
 * Whether detection is routed through the sidecar worker. Set once the
 * in-process load fails with a macOS library-validation error — the sidecar
 * is then used for the lifetime of the plugin.
 */
let useSidecar = false;

/**
 * Load the Redact model once and reuse it for the lifetime of the plugin.
 * Weights download from Hugging Face on first use and are cached locally.
 */
async function getRedact(): Promise<Redact> {
  if (redactInstance !== null) {
    return redactInstance;
  }
  if (redactLoadPromise === null) {
    redactLoadPromise = Redact.load().then(instance => {
      redactInstance = instance;
      return instance;
    });
    // On failure, clear the cached promise so a later call can retry the
    // load (e.g. after a transient network error during the first-use
    // weights download).
    redactLoadPromise.catch(() => {
      redactLoadPromise = null;
    });
  }
  return redactLoadPromise;
}

/**
 * Kick off the Redact model load at plugin startup. Called fire-and-forget
 * from main() so the first-use weights download does not block the first
 * preprocessor request. Errors are handled by the caller.
 */
export async function preloadRedact(): Promise<void> {
  if (!useSidecar) {
    try {
      await getRedact();
      return;
    } catch (err) {
      if (isDlopenError(err)) {
        useSidecar = true;
      } else {
        throw err;
      }
    }
  }
  await warmSidecar();
}

/**
 * Detect PII using the on-device Redact model.
 * Returns spans in document order, using Redact's own labels.
 *
 * Tries the in-process path first. On macOS, LM Studio's plugin runner
 * enforces library validation, so the native core (koffi) cannot be loaded
 * in-process (lmstudio-bug-tracker#1494) — in that case detection falls back
 * to the sidecar worker running under a re-signed copy of the runner binary.
 */
export async function redactDetect(text: string): Promise<RawSpan[]> {
  if (!useSidecar) {
    try {
      const redact = await getRedact();
      // ALL_LABELS includes ORG — the plugin redacts organisations as well.
      const result = await redact.redaction(text, { labels: [...ALL_LABELS_SET] });
      return result.items.map(item => ({
        original: item.original,
        type: item.label as PiiType,
      }));
    } catch (err) {
      if (isDlopenError(err)) {
        useSidecar = true;
      } else {
        throw err;
      }
    }
  }
  return detectViaSidecar(text);
}

/**
 * Recognise the macOS library-validation failure: the plugin runner refuses
 * to dlopen native addons signed with a different Team ID.
 */
function isDlopenError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return (
    (err as NodeJS.ErrnoException)?.code === "ERR_DLOPEN_FAILED" ||
    message.includes("different Team IDs") ||
    message.includes("code signature")
  );
}

// ---------------------------------------------------------------------------
// Regex fallback patterns
// ---------------------------------------------------------------------------

const EMAIL_REGEX = /[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}/g;

// Covers international and local formats: +1 (555) 123-4567, 07911 123 4567.
const PHONE_REGEX =
  /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,4}(?:[\s\-.]?\d{1,4})*/g;

// Minimum digit count to avoid matching lone numbers like "42"
const MIN_PHONE_DIGITS = 7;

function countDigits(s: string): number {
  return (s.match(/\d/g) ?? []).length;
}

// ---------------------------------------------------------------------------
// Regex-based fallback detector
// ---------------------------------------------------------------------------

/**
 * Extract EMAIL and PHONE entities from text using regex.
 * Returns spans in order of first appearance.
 */
export function regexDetect(text: string): RawSpan[] {
  const spans: RawSpan[] = [];
  const seen = new Set<string>();

  for (const match of text.matchAll(EMAIL_REGEX)) {
    const original = match[0];
    if (!seen.has(original)) {
      seen.add(original);
      spans.push({ original, type: "EMAIL" });
    }
  }

  for (const match of text.matchAll(PHONE_REGEX)) {
    const original = match[0].trim();
    if (countDigits(original) >= MIN_PHONE_DIGITS && !seen.has(original)) {
      seen.add(original);
      spans.push({ original, type: "PHONE" });
    }
  }

  return spans;
}

// ---------------------------------------------------------------------------
// LLM-based detector
// ---------------------------------------------------------------------------

/**
 * Ask the model to detect PII in `text`.
 * Returns a parsed, validated `LlmDetectionResponse` or throws on failure.
 */
export async function llmDetect(
  model: LLMDynamicHandle,
  text: string,
  abortSignal: AbortSignal,
): Promise<LlmDetectionResponse> {
  const result = await model.respond(
    [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: text },
    ],
    {
      structured: llmDetectionResponseSchema,
      // Generous but bounded — prevents the model getting stuck on large inputs
      maxTokens: 2048,
      temperature: 0,
      signal: abortSignal,
    },
  );

  // `result.parsed` is already validated by the SDK when a zod schema is used
  return result.parsed;
}

// ---------------------------------------------------------------------------
// Merged detector
// ---------------------------------------------------------------------------

/**
 * Run LLM detection and merge with regex fallback results.
 *
 * - LLM results take precedence; regex results are only added if their
 *   original text is not already covered by an LLM entity (case-insensitive).
 * - Order: LLM entities first, then any additional regex-only entities in
 *   order of appearance in the text.
 */
export function mergeDetections(
  llmEntities: LlmDetectionResponse["entities"],
  regexSpans: RawSpan[],
): RawSpan[] {
  const covered = new Set(llmEntities.map(e => e.original.toLowerCase()));
  const merged: RawSpan[] = [...llmEntities];
  for (const span of regexSpans) {
    if (!covered.has(span.original.toLowerCase())) {
      covered.add(span.original.toLowerCase());
      merged.push(span);
    }
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Zod schema for structured output (re-exported for use in promptPreprocessor)
// ---------------------------------------------------------------------------
export { llmDetectionResponseSchema };
export type { LlmDetectionResponse };
