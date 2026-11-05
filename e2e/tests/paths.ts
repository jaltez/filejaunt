import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repository root (the e2e suite lives in <root>/e2e/tests). */
export const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
