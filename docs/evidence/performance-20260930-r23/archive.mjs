import fs from 'node:fs';
import path from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

const root = '/var/tmp/ldap-go-perf-20260930-r23-input';
const repo = '/Users/wanna/mine/github/ldap-go';
const dest = path.join(repo, 'docs/evidence/performance-20260930-r23');
fs.mkdirSync(dest, {recursive: true});
const copy = (from, to = from) => {
  const output = path.join(dest, to);
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.copyFileSync(path.join(root, from), output);
};
for (const dir of ['network-final-default', 'network-final-explicit', 'network-final-swap', 'tls-ldaps', 'tls-starttls']) {
  for (const name of ['hot', 'groups', ...(dir.startsWith('tls-') ? ['smoke'] : [])]) {
    const data = fs.readFileSync(path.join(root, dir, `${name}.json`));
    const parsed = JSON.parse(data);
    if (parsed.error || parsed.cleanup_done.length !== parsed.config.endpoints.length) throw new Error(`Incomplete ${dir}/${name}`);
    fs.mkdirSync(path.join(dest, dir), {recursive: true});
    fs.writeFileSync(path.join(dest, dir, `${name}.json.gz`), gzipSync(data));
  }
  copy(`${dir}/validation.tsv`);
  copy(`${dir}.log`, `${dir}.log.txt`);
  if (dir.startsWith('tls-')) copy(`${dir}/cert.pem`);
}
for (const name of ['README.md', 'network.sh', 'tls-network.sh', 'summarize.mjs', 'summarize-tls.mjs', 'archive.mjs',
  'summary.json', 'tables.md', 'tls-summary.json', 'tls-tables.md', 'unit-first.txt',
  'focused-first.txt', 'focused-second.txt', 'cli-buffer-tests.txt', 'candidate-vet.txt',
  'tool-tests-first.txt', 'tool-tests-final.txt', 'tool-vet.txt']) copy(name);
const candidateFiles = ['internal/server/tcp_input.go', 'internal/server/tcp_input_test.go',
  'internal/server/tcp_input_tls_test.go', 'internal/server/tcp_input_sasl_test.go',
  'internal/server/tcp_input_integration_test.go', 'internal/server/server.go',
  'cmd/ldap-go/main.go', 'cmd/ldap-go/serve_tcp_input_test.go'];
const candidatePatch = execFileSync('git', ['diff', '3b0cd35', 'cbf335d', '--', ...candidateFiles], {cwd: repo});
fs.writeFileSync(path.join(dest, 'unshipped-input-from-3b0cd35.patch'), candidatePatch);
const toolPatch = execFileSync('git', ['diff', '3b0cd35', '6ebae9b', '--', 'internal/cmd/ldapcommonbench'], {cwd: repo});
fs.writeFileSync(path.join(dest, 'shipped-tool-from-3b0cd35.patch'), toolPatch);
const binaries = {production: '/var/tmp/ldap-go-perf-20260930-r22/current',
  'unshipped-input': path.join(root, 'current'), 'tls-tool': path.join(root, 'ldapcommonbench-tls')};
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
console.log(`Archived ${manifest.length} evidence files, excluding private keys and credentials.`);
