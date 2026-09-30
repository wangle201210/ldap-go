import fs from 'node:fs';
import path from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

const root = '/var/tmp/ldap-go-perf-20260930-r25-lazy-get';
const source = '/var/tmp/ldap-go-direct-get-20260930';
const repo = '/Users/wanna/mine/github/ldap-go';
const dest = path.join(repo, 'docs/evidence/performance-20260930-r25');
fs.mkdirSync(dest, {recursive: true});
const copy = (from, to = from) => {
  fs.mkdirSync(path.dirname(path.join(dest, to)), {recursive: true});
  fs.copyFileSync(path.join(root, from), path.join(dest, to));
};
for (const mode of ['final-default', 'final-explicit', 'final-swap', 'explicit-aa', 'explicit-swap']) {
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
  if (/^(group-|transient-).+\.txt$/.test(name) ||
    ['README.md', 'network.sh', 'validate.sh', 'archive.mjs', 'summary.json', 'tables.md',
      'focused-first.txt', 'focused.txt', 'go-test.txt', 'go-vet.txt',
      'openldap-differential.txt', 'stored-check.patch'].includes(name)) copy(name);
}
copy('validate.log', 'validate.log.txt');
fs.writeFileSync(path.join(dest, 'source-from-47f5bad.patch'), execFileSync('git',
  ['diff', '47f5bad', '--', 'internal/server', 'internal/storage'], {cwd: source}));
const binaries = {before: '/var/tmp/ldap-go-perf-20260930-r22/current', current: path.join(root, 'current')};
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
