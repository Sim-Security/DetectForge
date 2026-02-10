/**
 * Extraction module — IOC and TTP extraction from threat reports.
 */

export {
  extractIocsFromText,
  extractIocs,
  inferRelationships,
  type IocExtractionOptions,
} from './ioc-extractor.js';

export {
  enrichIOCs,
  classifyIOC,
  normalizeIOC,
  deduplicateIOCs,
  adjustConfidence,
  type EnrichedIOC,
  type IOCClassification,
} from './ioc-enrichment.js';

export {
  extractTtps,
  type TtpExtractionOptions,
} from './ttp-extractor.js';

export {
  mapToAttack,
  type AttackMapperOptions,
} from './attack-mapper.js';
