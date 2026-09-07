/**
 * Marks the two build outputs with the module system each one uses.
 *
 * The root package.json has no `"type"` field, so Node treats every `.js` file
 * as CommonJS. The ESM build needs the opposite, and saying so per-directory is
 * what lets one package serve both `require()` and `import` without renaming a
 * single file.
 */

import { writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const targets = [
  ['dist/cjs', 'commonjs'],
  ['dist/esm', 'module'],
];

for (const [dir, type] of targets) {
  if (!existsSync(dir)) {
    console.error(`postbuild: ${dir} is missing — did the build run?`);
    process.exit(1);
  }
  writeFileSync(
    join(dir, 'package.json'),
    `${JSON.stringify({ type }, null, 2)}\n`
  );
  console.log(`postbuild: marked ${dir} as ${type}`);
}
