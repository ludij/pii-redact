import { z } from "zod";

// ---------------------------------------------------------------------------
// PII entity types
// ---------------------------------------------------------------------------

export const PII_TYPES = ["PERSON", "EMAIL", "PHONE", "ORG", "LOCATION", "OTHER"] as const;
export type PiiType = (typeof PII_TYPES)[number];

/** A single detected PII entity returned by the detector. */
export interface PiiEntity {
  /** Unique placeholder identifier, e.g. "PERSON_1" */
  identifier: string;
  /** Semantic category of the entity */
  type: PiiType;
  /** The original text that was redacted */
  original: string;
}

/** The structured output produced after redacting a prompt. */
export interface RedactionResult {
  redacted_text: string;
  entities: PiiEntity[];
}

// ---------------------------------------------------------------------------
// Zod schemas — used both for structured LLM output and for validation
// ---------------------------------------------------------------------------

export const piiTypeSchema = z.enum(PII_TYPES);

export const piiEntitySchema = z.object({
  /** The raw text span found in the prompt */
  original: z.string().min(1),
  /** Semantic category */
  type: piiTypeSchema,
});

/**
 * Schema for the raw LLM response.
 * The LLM only returns (original, type) pairs — identifiers are assigned
 * deterministically by the redactor after deduplication.
 */
export const llmDetectionResponseSchema = z.object({
  entities: z.array(piiEntitySchema),
});

export type LlmDetectionResponse = z.infer<typeof llmDetectionResponseSchema>;

/** Full redaction result schema (used for final validation). */
export const redactionResultSchema = z.object({
  redacted_text: z.string(),
  entities: z.array(
    z.object({
      identifier: z.string().regex(/^[A-Z]+_\d+$/),
      type: piiTypeSchema,
      original: z.string().min(1),
    }),
  ),
});

// ---------------------------------------------------------------------------
// Confirmation sentinel
// ---------------------------------------------------------------------------

/** Suffix the user appends to confirm they accept the redacted prompt. */
export const CONFIRM_SUFFIX = "--c";
