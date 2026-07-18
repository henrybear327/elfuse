'use strict';
// In-guest compute half of the elfuse-oci node image CI (minus the server): core-module loading, a few hundred small-file
// writes read back and hashed, a zlib gzip round-trip, JSON round-trip, and a
// crypto self-check. Prints one sentinel token on full success; any failure
// exits non-zero with a diagnostic. Passed to the guest via `node -e`.

const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const DIR = '/tmp/elfuse-node';
fs.mkdirSync(DIR, { recursive: true });

// fs write/read fan-out, each file read back and compared so a lost or
// corrupted file is caught.
const N = 400;
for (let i = 0; i < N; i++) {
  const p = path.join(DIR, 'f' + i);
  const body = 'elfuse-node-' + i + '\n';
  fs.writeFileSync(p, body);
  if (fs.readFileSync(p).toString() !== body) {
    console.error('file content mismatch: ' + p);
    process.exit(1);
  }
}

// zlib gzip round-trip over a non-trivial buffer.
const payload = Buffer.alloc(1 << 16, 0x61);
if (!zlib.gunzipSync(zlib.gzipSync(payload)).equals(payload)) {
  console.error('zlib round-trip mismatch');
  process.exit(1);
}

// JSON round-trip.
const doc = { items: Array.from({ length: 256 }, (_, i) => ({ k: i, v: 'tok-' + i })) };
const back = JSON.parse(JSON.stringify(doc));
if (back.items.length !== 256 || back.items[255].v !== 'tok-255') {
  console.error('json round-trip mismatch');
  process.exit(1);
}

// crypto self-check against a fixed vector.
if (crypto.createHash('sha256').update('elfuse').digest('hex') !==
    '87097914b16b96d167ef08a895d4d3f81f24267a617faca4b97c30183eb5fe02') {
  console.error('sha256 self-check failed');
  process.exit(1);
}

console.log('elfuse-oci-node-compute-ok');
