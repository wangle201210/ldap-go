import { readFileSync } from 'node:fs';

const root = process.argv[2];
const mode = process.argv[3];
const groups = new Map();
const median = values => values.toSorted((a, b) => a - b)[Math.floor(values.length / 2)];
for (const side of ['before', 'current', 'openldap']) {
  for (let run = 1; run <= 3; run++) {
    const directory = `${root}/${side}-${run}`;
    const files = mode === 'writes' ? ['probe'] : mode === 'extended'
      ? ['long-dn', 'long-password'] : ['user-bind', 'fast-1', 'fast-2', 'fast-3'];
    for (const file of files) {
      const data = JSON.parse(readFileSync(`${directory}/${file}.json`, 'utf8'));
      if (data.error) throw new Error(data.error);
      const stages = Array.isArray(data) ? data : data.stages;
      for (const stage of stages) {
        if (stage.errors?.length) throw new Error(stage.errors.join('; '));
        const metric = mode === 'extended' ? `${file}/${stage.name}` : stage.name;
        if (!groups.has(metric)) groups.set(metric, { operations: stage.operations, samples: {} });
        const group = groups.get(metric);
        if (group.operations !== stage.operations) throw new Error(`operation count mismatch: ${metric}`);
        (group.samples[side] ??= []).push(stage.total_ms);
      }
    }
  }
}
const rows = [...groups].map(([metric, group]) => {
  const values = Object.fromEntries(Object.entries(group.samples).map(([side, samples]) => {
    const expected = mode === 'writes' ? 3 : 9;
    if (samples.length !== expected) throw new Error(`sample count mismatch: ${metric}/${side}`);
    return [side, median(samples)];
  }));
  return { metric, operations: group.operations, ...values,
    changePercent: (values.current / values.before - 1) * 100,
    relativePercent: 100 * values.openldap / values.current, samples: group.samples };
});
console.log(JSON.stringify(rows, null, 2));
