// Single-file build: bundles src/main.ts with the wasm-bindgen glue and the
// WASM binary inlined as base64, then inlines everything into dist/filejaunt.html.
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
// import.meta.url reference so the iife bundle stays CSP-clean (no fetch).
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

const result = await build({
  entryPoints: [join(here, 'src/main.ts')],
  bundle: true,
  format: 'iife',
  target: 'es2022',
  write: false,
  plugins: [fjWasmPlugin],
  legalComments: 'none',
});

const js = result.outputFiles[0].text.replace(/<\/script>/g, '<\\/script>');
const html = readFileSync(join(here, 'index.html'), 'utf8').replace(
  '<!--FJ_SCRIPT-->',
  () => `<script type="module">\n${js}\n</script>`,
);
mkdirSync(join(here, 'dist'), { recursive: true });
const out = join(here, 'dist', 'filejaunt.html');
writeFileSync(out, html);
const mib = html.length / (1024 * 1024);
console.log(`wrote ${out} (${mib.toFixed(2)} MiB${mib > 5 ? ' — single file kept despite >5 MiB' : ''})`);
