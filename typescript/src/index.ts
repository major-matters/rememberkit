/**
 * RememberKit v0 (TypeScript) - governed, portable memory for AI agents.
 * Wire-compatible with the Python SDK. See the README.
 */

export { Memory, buildRecord, recordId, VERSION, CONSENT_LEVELS } from "./memory.ts";
export type { Record, Pack } from "./memory.ts";
export { verifyRecord, verifyPack } from "./verify.ts";
export type { RecordVerdict, PackVerdict, VerifyOptions, TrustedKeys } from "./verify.ts";
export { generateKeypair, publicKeyFromSeed, b64 } from "./signing.ts";

export const __version__ = "0.0.1";
