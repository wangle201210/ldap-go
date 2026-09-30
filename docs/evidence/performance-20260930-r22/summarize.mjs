import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2] ?? '/var/tmp/ldap-go-perf-20260930-r22';
const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const rows = [];
let samples = 0;
for (const mode of ['default', 'explicit', 'swap']) {
  const directory = path.join(root, `network-final-${mode}`);
  const validation = fs.readFileSync(path.join(directory, 'validation.tsv'), 'utf8').trim().split('\n');
  if (validation.length !== 4 || validation.slice(1).some(line => !line.endsWith('\t100002\t2143929969\t42712438'))) {
    throw new Error(`Invalid canonical exports: ${mode}`);
  }
  for (const workload of ['groups', 'hot']) {
    const data = JSON.parse(fs.readFileSync(path.join(directory, `${workload}.json`), 'utf8'));
    if (data.error || data.cleanup_done.length !== 3 || data.samples.length !== 126) {
      throw new Error(`Incomplete benchmark: ${mode}/${workload}`);
    }
    for (const sample of data.samples) {
      if (sample.completed !== 1000 || sample.operations !== 1000 || sample.latency_ms.length !== 1000) {
        throw new Error(`Incomplete sample: ${mode}/${workload}`);
      }
      samples++;
    }
    const key = s => `${s.stage}/${s.method}/${s.members ?? 0}`;
    for (const name of new Set(data.samples.map(key))) {
      const row = {mode, workload, name};
      for (const endpoint of ['before', 'current', 'openldap']) {
        const values = data.samples.filter(s => key(s) === name && s.endpoint === endpoint);
        if (values.length !== 7) throw new Error(`Missing repeat: ${name}/${endpoint}`);
        row[endpoint] = median(values.map(s => s.total_ms));
        row[`${endpoint}_first_batch`] = values.find(s => s.repeat === 1).total_ms;
      }
      row.reduction_percent = (1 - row.current / row.before) * 100;
      row.relative_percent = row.openldap / row.current * 100;
      rows.push(row);
    }
  }
}
fs.writeFileSync(path.join(root, 'summary.json'), JSON.stringify({samples, exports: 9, rows}, null, 2) + '\n');
const table = ['| Access | Operation | Before ms | Current ms | OpenLDAP ms | Time reduction | Relative |',
  '| --- | --- | ---: | ---: | ---: | ---: | ---: |'];
for (const row of rows) {
  table.push(`| ${row.mode} | ${row.name} | ${row.before.toFixed(2)} | ${row.current.toFixed(2)} | ${row.openldap.toFixed(2)} | ${row.reduction_percent.toFixed(1)}% | ${row.relative_percent.toFixed(1)}% |`);
}
fs.writeFileSync(path.join(root, 'tables.md'), table.join('\n') + '\n');
console.log(`Verified ${samples} batches and 9 canonical exports.`);
