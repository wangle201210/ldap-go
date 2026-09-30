import fs from 'node:fs';
import path from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

const root = '/var/tmp/ldap-go-perf-20260930-r21';
const source = '/var/tmp/ldap-go-normalized-prefix-20260930';
const dest = '/Users/wanna/mine/github/ldap-go/docs/evidence/performance-20260930-r21';
fs.mkdirSync(dest, {recursive: true});
const copy = (from, to = from) => {
  const output = path.join(dest, to);
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.copyFileSync(path.join(root, from), output);
};
for (const mode of ['default', 'explicit', 'swap', 'final-default', 'final-explicit', 'final-swap']) {
  const dir = `network-${mode}`;
  for (const name of ['groups', 'hot']) {
    const data = fs.readFileSync(path.join(root, dir, `${name}.json`));
    const parsed = JSON.parse(data);
    if (parsed.error || parsed.cleanup_done.length !== 3) throw new Error(`Incomplete ${dir}/${name}`);
    fs.mkdirSync(path.join(dest, dir), {recursive: true});
    fs.writeFileSync(path.join(dest, dir, `${name}.json.gz`), gzipSync(data));
  }
  copy(`${dir}/validation.tsv`);
  copy(`${dir}.log`);
}
const files = fs.readdirSync(root).filter(name =>
  /^(?:group-|name-group-|final-group-).+\.txt$/.test(name) ||
  ['README.md', 'network.sh', 'validate.sh', 'summarize.mjs', 'archive.mjs',
    'summary.json', 'tables.md', 'prefix-tests.txt', 'schema-all.txt',
    'prefix-simple-1000.txt', 'prefix-fill-and-reset.txt', 'cache-tests.txt',
    'prefix-single-fill-tests.txt', 'single-fill-reset-episode.txt',
    'handler-full-warm-tests.txt', 'go-test-final.txt', 'go-vet-final.txt',
    'openldap-differential-final.txt', 'validate-final.log',
    'prefix-before-name-lookup.go'].includes(name));
for (const name of files) copy(name, name.endsWith('.go') ? `prototype/${name}.txt` : name);
for (const name of fs.readdirSync(path.join(root, 'fill-eight-source'))) {
  copy(`fill-eight-source/${name}`, `prototype/fill-eight/${name}.txt`);
}
const sourceFiles = [
  'internal/schema/compare_entry_prefix.go', 'internal/schema/compare_entry_prefix_test.go',
  'internal/schema/compare_entry_prefix_bench_test.go', 'internal/schema/compare_entry_prefix_names_test.go',
  'internal/server/compare_dn_prefix_cache.go', 'internal/server/compare_dn_prefix_cache_test.go',
  'internal/server/compare_dn_prefix_integration_test.go', 'internal/server/runtime.go', 'internal/server/write.go',
];
let patch = '';
for (const file of sourceFiles) {
  let tracked = true;
  try {execFileSync('git', ['cat-file', '-e', `17e0390:${file}`], {cwd: source, stdio: 'pipe'});} catch {tracked = false;}
  if (tracked) {
    patch += execFileSync('git', ['diff', '17e0390', '--', file], {cwd: source, encoding: 'utf8'});
  } else {
    try {execFileSync('git', ['diff', '--no-index', '--', '/dev/null', file], {cwd: source, encoding: 'utf8'});}
    catch (error) {
      if (error.status !== 1) throw error;
      patch += error.stdout;
    }
  }
}
fs.writeFileSync(path.join(dest, 'source-from-17e0390.patch'), patch);
const binaries = {
  before: '/var/tmp/ldap-go-perf-20260930-r20-request/before',
  current: path.join(root, 'current'),
  prototype: path.join(root, 'current-before-name-lookup'),
};
const hashes = [];
for (const [label, file] of Object.entries(binaries)) {
  hashes.push(`${createHash('sha256').update(fs.readFileSync(file)).digest('hex')}  ${label}`);
  fs.writeFileSync(path.join(dest, `build-${label}.txt`), execFileSync('go', ['version', '-m', file]));
}
fs.writeFileSync(path.join(dest, 'executable-sha256.txt'), hashes.join('\n') + '\n');
function* walk(dir) {
  for (const name of fs.readdirSync(dir).sort()) {
    const file = path.join(dir, name);
    if (fs.statSync(file).isDirectory()) yield* walk(file);
    else if (name !== 'SHA256SUMS') yield file;
  }
}
const manifest = [...walk(dest)].map(file => `${createHash('sha256').update(fs.readFileSync(file)).digest('hex')}  ${path.relative(dest, file)}`);
fs.writeFileSync(path.join(dest, 'SHA256SUMS'), manifest.join('\n') + '\n');
console.log(`Archived ${manifest.length} evidence files; ${sourceFiles.length} source files reconstructed.`);
