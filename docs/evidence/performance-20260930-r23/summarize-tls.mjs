import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2] ?? '/var/tmp/ldap-go-perf-20260930-r23-input';
const rows = [];
let samples = 0;
for (const mode of ['ldaps', 'starttls']) {
  const dir = path.join(root, `tls-${mode}`);
  const validation = fs.readFileSync(path.join(dir, 'validation.tsv'), 'utf8').trim().split('\n');
  if (validation.length !== 3 || validation.slice(1).some(line => !line.endsWith('\t100002\t2143929969\t42712438'))) {
    throw new Error(`Invalid exports: ${mode}`);
  }
  for (const name of ['hot', 'groups']) {
    const data = JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), 'utf8'));
    if (data.error || data.cleanup_done.length !== 2 || data.samples.length !== 84 ||
        !data.config.tls_ca || Boolean(data.config.start_tls) !== (mode === 'starttls')) {
      throw new Error(`Invalid report: ${mode}/${name}`);
    }
    for (const sample of data.samples) {
      if (sample.completed !== 1000 || sample.operations !== 1000 || sample.latency_ms.length !== 1000) {
        throw new Error(`Incomplete sample: ${mode}/${name}`);
      }
      samples++;
    }
    const key = s => `${s.stage}/${s.method}/${s.members ?? 0}`;
    for (const operation of new Set(data.samples.map(key))) {
      const row = {mode, operation};
      for (const endpoint of ['ldapgo', 'openldap']) {
        const values = data.samples.filter(s => key(s) === operation && s.endpoint === endpoint).map(s => s.total_ms);
        if (values.length !== 7) throw new Error(`Missing repeat: ${mode}/${operation}/${endpoint}`);
        row[endpoint] = values.sort((a, b) => a - b)[3];
      }
      row.relative_percent = row.openldap / row.ldapgo * 100;
      rows.push(row);
    }
  }
}
fs.writeFileSync(path.join(root, 'tls-summary.json'), JSON.stringify({samples, exports: 4, rows}, null, 2) + '\n');
const lines = ['| Transport | Operation | ldap-go ms | OpenLDAP ms | Relative |', '| --- | --- | ---: | ---: | ---: |'];
for (const row of rows) lines.push(`| ${row.mode} | ${row.operation} | ${row.ldapgo.toFixed(2)} | ${row.openldap.toFixed(2)} | ${row.relative_percent.toFixed(1)}% |`);
fs.writeFileSync(path.join(root, 'tls-tables.md'), lines.join('\n') + '\n');
console.log(`Verified ${samples} TLS batches and four canonical exports.`);
