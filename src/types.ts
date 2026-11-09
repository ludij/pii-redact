import { z } from "zod";
import { ALL_LABELS, type RedactLabel } from "@desert-ant-labs/redact/native";

// ---------------------------------------------------------------------------
// PII entity types — Redact's labels, shared by both detection engines
// ---------------------------------------------------------------------------

/**
 * The PII categories used throughout the plugin. Taken directly from the
 * Desert Ant Redact model so placeholders are consistent regardless of
 * whether the on-device Redact model or an LLM performed the detection.
 */
export const PII_TYPES = ALL_LABELS;
export type PiiType = RedactLabel;

/** A single detected PII entity returned by the detector. */
export interface PiiEntity {
  /** Unique placeholder identifier, e.g. "EMAIL_1" */
  identifier: string;
  /** Semantic category of the entity */
  type: PiiType;
  /** The original text that was redacted */
  original: string;
}

/** A raw detection span, before identifier assignment. */
export interface RawSpan {
  original: string;
  type: PiiType;
}

/** The structured output produced after redacting a prompt. */
export interface RedactionResult {
  redacted_text: string;
  entities: PiiEntity[];
}

// ---------------------------------------------------------------------------
// Zod schemas — used both for structured LLM output and for validation
// ---------------------------------------------------------------------------

export const piiTypeSchema = z.enum([...PII_TYPES] as [PiiType, ...PiiType[]]);

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
      // Labels may contain underscores (e.g. "GIVEN_NAME_1"), so the type
      // part is matched with [A-Z_]+ and the trailing counter with _\d+.
      identifier: z.string().regex(/^[A-Z_]+_\d+$/),
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
