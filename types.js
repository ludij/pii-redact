"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONFIRM_SUFFIX = exports.redactionResultSchema = exports.llmDetectionResponseSchema = exports.piiEntitySchema = exports.piiTypeSchema = exports.PII_TYPES = void 0;
const zod_1 = require("zod");
const native_1 = require("@desert-ant-labs/redact/native");
// ---------------------------------------------------------------------------
// PII entity types — Redact's labels, shared by both detection engines
// ---------------------------------------------------------------------------
/**
 * The PII categories used throughout the plugin. Taken directly from the
 * Desert Ant Redact model so placeholders are consistent regardless of
 * whether the on-device Redact model or an LLM performed the detection.
 */
exports.PII_TYPES = native_1.ALL_LABELS;
// ---------------------------------------------------------------------------
// Zod schemas — used both for structured LLM output and for validation
// ---------------------------------------------------------------------------
exports.piiTypeSchema = zod_1.z.enum([...exports.PII_TYPES]);
exports.piiEntitySchema = zod_1.z.object({
    /** The raw text span found in the prompt */
    original: zod_1.z.string().min(1),
    /** Semantic category */
    type: exports.piiTypeSchema,
});
/**
 * Schema for the raw LLM response.
 * The LLM only returns (original, type) pairs — identifiers are assigned
 * deterministically by the redactor after deduplication.
 */
exports.llmDetectionResponseSchema = zod_1.z.object({
    entities: zod_1.z.array(exports.piiEntitySchema),
});
/** Full redaction result schema (used for final validation). */
exports.redactionResultSchema = zod_1.z.object({
    redacted_text: zod_1.z.string(),
    entities: zod_1.z.array(zod_1.z.object({
        // Labels may contain underscores (e.g. "GIVEN_NAME_1"), so the type
        // part is matched with [A-Z_]+ and the trailing counter with _\d+.
        identifier: zod_1.z.string().regex(/^[A-Z_]+_\d+$/),
        type: exports.piiTypeSchema,
        original: zod_1.z.string().min(1),
    })),
});
// ---------------------------------------------------------------------------
// Confirmation sentinel
// ---------------------------------------------------------------------------
/** Suffix the user appends to confirm they accept the redacted prompt. */
exports.CONFIRM_SUFFIX = "--c";
