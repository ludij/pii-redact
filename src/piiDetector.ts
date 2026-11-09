import type { LLMDynamicHandle } from "@lmstudio/sdk";
import { z } from "zod";
import { llmDetectionResponseSchema, type LlmDetectionResponse, type PiiType } from "./types";

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a privacy-focused PII (Personally Identifiable Information) detector.

Your task: analyse the user's text and return a JSON object listing every PII entity found.

Rules:
1. Detect the following entity types:
   - PERSON   — full names, first names, last names, nicknames
   - EMAIL    — email addresses
   - PHONE    — phone numbers (any format)
   - ORG      — company, organisation, institution names
   - LOCATION — street addresses, cities, countries, postcodes
   - OTHER    — any other PII not covered above (e.g. national ID, passport, credit card)

2. For each entity return the EXACT substring as it appears in the text (preserve case and spacing).

3. Coreference resolution: if a shortened or repeated reference (e.g. "Micky" after "Mickey Mouse")
   unambiguously refers to the same entity, include it as a SEPARATE entry with the same type so the
   caller can merge them. Only do this when the reference is unambiguous.

4. Do NOT invent entities. Only return entities that are actually present in the text.

5. Return ONLY valid JSON matching this schema — no markdown, no explanation:
{
  "entities": [
    { "original": "<exact text span>", "type": "<TYPE>" },
    ...
  ]
}

If no PII is found, return: { "entities": [] }`;

// ---------------------------------------------------------------------------
// Regex fallback patterns
// ---------------------------------------------------------------------------

const EMAIL_REGEX = /[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}/g;

// Covers international and local formats: +1 (555) 123-4567, 07911 123456, etc.
const PHONE_REGEX =
  /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,9}(?:[\s\-.]?\d{1,4})?/g;

// Minimum digit count to avoid matching lone numbers like "42"
const MIN_PHONE_DIGITS = 7;

function countDigits(s: string): number {
  return (s.match(/\d/g) ?? []).length;
}

// ---------------------------------------------------------------------------
// Regex-based fallback detector
// ---------------------------------------------------------------------------

interface RawSpan {
  original: string;
  type: PiiType;
}

/**
 * Extract EMAIL and PHONE entities from text using regex.
 * Returns spans in order of first appearance.
 */
export function regexDetect(text: string): RawSpan[] {
  const spans: RawSpan[] = [];
  const seen = new Set<string>();

  // Emails
  for (const match of text.matchAll(EMAIL_REGEX)) {
    const original = match[0];
    if (!seen.has(original)) {
      seen.add(original);
      spans.push({ original, type: "EMAIL" });
    }
  }

  // Phones — only include matches with enough digits to be plausible
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
 * - Order: LLM entities first (in LLM response order), then any additional
 *   regex-only entities in order of appearance in the text.
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

// Re-export the raw span type for use in redactor
export type { RawSpan };
