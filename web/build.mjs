// Build outputs:
//   dist/fj.js        — the DOM-free library (ESM, wasm inlined as base64)
//   dist/filejaunt.html — the single-file example app (library + minimal DOM)
//
// The library is what filejaunt.com's app consumes; the example is the
// copy-paste reference for anyone embedding filejaunt in their own page.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const pkg = join(root, 'crates/fj-wasm/pkg');

if (!existsSync(join(pkg, 'filejaunt_wasm_bg.wasm'))) {
  console.log('wasm package missing; running wasm-pack…');
  const r = spawnSync(
    'wasm-pack',
    ['build', join(root, 'crates/fj-wasm'), '--target', 'web', '--out-dir', 'pkg', '--out-name', 'filejaunt_wasm'],
    { stdio: 'inherit' },
  );
  if (r.status !== 0) {
    console.error('wasm-pack failed');
    process.exit(1);
  }
}

// The glue's default fetch path is never used (we always pass bytes); drop the
// import.meta.url reference so bundles stay CSP-clean (no fetch).
const glue = readFileSync(join(pkg, 'filejaunt_wasm.js'), 'utf8').replace(
  /new URL\('filejaunt_wasm_bg\.wasm', import\.meta\.url\)/,
  'undefined',
);
const wasmB64 = readFileSync(join(pkg, 'filejaunt_wasm_bg.wasm')).toString('base64');

const fjWasmPlugin = {
  name: 'fj-wasm',
  setup(builder) {
    builder.onResolve({ filter: /^fj-wasm$/ }, () => ({ path: 'fj-wasm', namespace: 'fjw' }));
    builder.onLoad({ filter: /.*/, namespace: 'fjw' }, () => ({
      contents: `${glue}\nexport const WASM_B64 = ${JSON.stringify(wasmB64)};\n`,
      loader: 'js',
    }));
  },
};

const shared = {
  bundle: true,
  target: 'es2022',
  write: false,
  plugins: [fjWasmPlugin],
  legalComments: 'none',
};

mkdirSync(join(here, 'dist'), { recursive: true });

// 1. Library: ESM, all exports intact, importable as `import { Jaunt } from './fj.js'`.
const lib = await build({ ...shared, entryPoints: [join(here, 'src/library.ts')], format: 'esm' });
const libOut = join(here, 'dist', 'fj.js');
writeFileSync(libOut, lib.outputFiles[0].text);
console.log(`wrote ${libOut} (${(lib.outputFiles[0].text.length / 1024 / 1024).toFixed(2)} MiB)`);

// 2. Example app: IIFE inlined into the reference HTML.
const example = await build({ ...shared, entryPoints: [join(here, 'src/main.ts')], format: 'iife' });
const js = example.outputFiles[0].text.replace(/<\/script>/g, '<\\/script>');
const html = readFileSync(join(here, 'index.html'), 'utf8').replace(
  '<!--FJ_SCRIPT-->',
  () => `<script type="module">\n${js}\n</script>`,
);
const htmlOut = join(here, 'dist', 'filejaunt.html');
writeFileSync(htmlOut, html);
const mib = html.length / (1024 * 1024);
console.log(`wrote ${htmlOut} (${mib.toFixed(2)} MiB${mib > 5 ? ' — single file kept despite >5 MiB' : ''})`);
