'use strict';
// Syntax-checks every browser script, service worker and test file.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const files = [...fs.readdirSync(path.join(root, 'js')).map(f => 'js/' + f), 'sw.js', ...fs.readdirSync(path.join(root, 'tests')).filter(f => f.endsWith('.js')).map(f => 'tests/' + f)];
let bad = 0;
for (const f of files.filter(f => f.endsWith('.js'))) {
    const r = spawnSync(process.execPath, ['--check', path.join(root, f)], { encoding: 'utf8' });
    if (r.status !== 0) { bad++; console.error('FAIL', f, '\n' + r.stderr); } else console.log('ok  ', f);
}
process.exit(bad ? 1 : 0);
