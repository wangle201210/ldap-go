import fs from 'node:fs';
import path from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

const root = '/var/tmp/ldap-go-perf-20260930-r22';
const source = '/var/tmp/ldap-go-base-identity-20260930';
const dest = '/Users/wanna/mine/github/ldap-go/docs/evidence/performance-20260930-r22';
fs.mkdirSync(dest, {recursive: true});
const copy = (from, to = from) => {
  const output = path.join(dest, to);
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.copyFileSync(path.join(root, from), output);
};
for (const mode of ['preliminary-default', 'final-default', 'final-explicit', 'final-swap']) {
  const dir = `network-${mode}`;
  for (const name of ['groups', 'hot']) {
    const data = fs.readFileSync(path.join(root, dir, `${name}.json`));
    const parsed = JSON.parse(data);
    if (parsed.error || parsed.cleanup_done.length !== 3) throw new Error(`Incomplete ${dir}/${name}`);
    fs.mkdirSync(path.join(dest, dir), {recursive: true});
    fs.writeFileSync(path.join(dest, dir, `${name}.json.gz`), gzipSync(data));
  }
  copy(`${dir}/validation.tsv`);
  copy(`${dir}.log`, `${dir}.log.txt`);
}
for (const name of fs.readdirSync(root)) {
  if (/^(component-|network-(before|current)-).+\.txt$/.test(name) ||
    ['README.md', 'network.sh', 'validate.sh', 'archive.mjs', 'summarize.mjs',
      'summary.json', 'tables.md', 'preliminary-summary.json', 'base.cpu', 'base.mem',
      'base-profile.txt', 'base-handler-cpu.txt', 'focused-first.txt', 'focused-second.txt',
      'focused-baseline.txt', 'go-test-final.txt', 'go-vet-final.txt',
      'openldap-differential-final.txt'].includes(name)) copy(name);
}
copy('validate-final.log', 'validate-final.log.txt');
const changed = ['internal/server/search_small_nonroot.go',
  'internal/server/search_small_nonroot_identity_test.go',
  'internal/server/search_small_nonroot_identity_bench_test.go'];
let patch = '';
for (const file of changed) {
  if (file === changed[0]) {
    patch += execFileSync('git', ['diff', '984ada3', '--', file], {cwd: source, encoding: 'utf8'});
  } else {
    try {execFileSync('git', ['diff', '--no-index', '--', '/dev/null', file], {cwd: source, encoding: 'utf8'});}
    catch (error) {
      if (error.status !== 1) throw error;
      patch += error.stdout;
    }
  }
}
fs.writeFileSync(path.join(dest, 'source-from-984ada3.patch'), patch);
const binaries = {before: '/var/tmp/ldap-go-perf-20260930-r21/current', current: path.join(root, 'current')};
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
console.log(`Archived ${manifest.length} evidence files.`);
