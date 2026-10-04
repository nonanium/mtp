/**
 * Public SDK compatibility facade.
 *
 * Implementation lives in private SDK modules. This entry point intentionally
 * keeps the package's historical exports stable.
 */
export * from "./client.js";
export * from "./schema.js";
export * from "./subscription.js";
export * from "./protected.js";
export {
  mergeDataValues,
  mergeDataValuesDetailed,
  mergePayloadFrom,
  mergePayloadFromDetailed,
} from "./codec.js";
export type {
  MTPMergeOptions,
  MTPMergePath,
  MTPMergeReport,
  MTPMergeResult,
} from "./codec.js";
