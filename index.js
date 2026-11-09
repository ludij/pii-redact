"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.main = main;
const config_1 = require("./config");
const generator_1 = require("./generator");
const promptPreprocessor_1 = require("./promptPreprocessor");
/**
 * Plugin entry point.
 *
 * Registers:
 * - Global configuration schema (detection/assistant models, confirmation
 *   gate, API key, base URL — shared across all chats)
 * - Prompt preprocessor (PII detection + redaction + confirmation gate)
 * - Generator (sends the redacted history to the third-party API and
 *   un-redacts the response locally)
 *
 * Because the plugin contains a generator, it appears in the model dropdown
 * (instead of the plugins list) and acts as a model. The preprocessor runs
 * whenever this plugin-model is selected.
 */
async function main(context) {
    context.withGlobalConfigSchematics(config_1.globalConfigSchematics);
    context.withPromptPreprocessor(promptPreprocessor_1.preprocess);
    context.withGenerator(generator_1.generate);
}
