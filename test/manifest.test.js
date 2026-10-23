// From the hosted service's engine.test.js (x402-pkgguard): the manifest-parser tests (src/manifest.js ships in this repo).
// The CVSS, OSV client and scan-engine tests stay in the hosted repo (src/cvss.js, src/osv.js, src/scan.js are not here).
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest, floorVersion, detectType, readPackageList, ManifestError } from '../src/manifest.js';

test('floorVersion: npm / pip ranges -> lowest allowed version, unresolvable -> null', () => {
  assert.equal(floorVersion('^4.17.0'), '4.17.0'); assert.equal(floorVersion('~1.2'), '1.2.0'); assert.equal(floorVersion('>=2 <3'), '2.0.0');
  assert.equal(floorVersion('1.x'), '1.0.0'); assert.equal(floorVersion('=1.2.3'), '1.2.3'); assert.equal(floorVersion('1.0.0-beta.1'), '1.0.0-beta.1');
  for (const s of ['*', 'latest', 'git+https://x/y.git', 'github:a/b', 'file:../x', '<2', '', 'workspace:*']) assert.equal(floorVersion(s), null, s);
});

test('package.json: deps + dev deps, exact = pinned, ranges = floor, unresolvable = unpinned; include_dev=false', () => {
  const m = JSON.stringify({ dependencies: { lodash: '^4.17.15', a: '1.2.3', x: 'latest' }, devDependencies: { jest: '29.0.0' } });
  const { type, packages } = parseManifest(m);
  assert.equal(type, 'package.json');
  assert.deepEqual(packages.map((p) => [p.name, p.version, p.pinned, !!p.dev]), [['lodash', '4.17.15', false, false], ['a', '1.2.3', true, false], ['x', null, false, false], ['jest', '29.0.0', true, true]]);
  assert.equal(parseManifest(m, { includeDev: false }).packages.length, 3);
});

test('package-lock.json v3 and v1', () => {
  const v3 = JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/lodash': { version: '4.17.15' }, 'node_modules/a/node_modules/lodash': { version: '4.17.21' }, 'node_modules/jest': { version: '29.0.0', dev: true }, 'node_modules/l': { link: true } } });
  assert.deepEqual(parseManifest(v3).packages.map((p) => `${p.name}@${p.version}`), ['lodash@4.17.15', 'lodash@4.17.21', 'jest@29.0.0']);
  const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } } });
  assert.deepEqual(parseManifest(v1).packages.map((p) => `${p.name}@${p.version}`), ['a@1.0.0', 'b@2.0.0']);
});

test('requirements.txt, go.mod, Cargo.lock, poetry.lock, composer.lock, Pipfile.lock', () => {
  const req = parseManifest('requests==2.19.0\nflask>=1.0  # web\nnumpy\n-r other.txt\nDjango[argon2]==3.0.0 ; python_version > "3"\ngit+https://x/y.git\n');
  assert.equal(req.type, 'requirements.txt');
  assert.deepEqual(req.packages.map((p) => [p.ecosystem, p.name, p.version, p.pinned]), [['PyPI', 'requests', '2.19.0', true], ['PyPI', 'flask', '1.0.0', false], ['PyPI', 'numpy', null, false], ['PyPI', 'Django', '3.0.0', true]]);
  const go = parseManifest('module example.com/x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n\tgolang.org/x/net v0.17.0 // indirect\n)\nrequire github.com/a/b v1.0.0\n');
  assert.deepEqual(go.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`), ['Go:github.com/gin-gonic/gin@v1.6.0', 'Go:golang.org/x/net@v0.17.0', 'Go:github.com/a/b@v1.0.0']);
  const cargo = parseManifest('version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "abc"\n');
  assert.equal(cargo.type, 'Cargo.lock'); assert.deepEqual(cargo.packages.map((p) => `${p.name}@${p.version}`), ['serde@1.0.0']);
  const poetry = parseManifest('[[package]]\nname = "requests"\nversion = "2.19.0"\ndescription = "x"\n\n[package.dependencies]\nidna = ">=2"\n\n[[package]]\nname = "idna"\nversion = "2.7"\n', { filename: 'poetry.lock' });
  assert.deepEqual(poetry.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`), ['PyPI:requests@2.19.0', 'PyPI:idna@2.7']);
  const comp = parseManifest(JSON.stringify({ 'content-hash': 'x', packages: [{ name: 'guzzlehttp/guzzle', version: 'v6.0.0' }], 'packages-dev': [] }));
  assert.equal(comp.type, 'composer.lock'); assert.deepEqual(comp.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`), ['Packagist:guzzlehttp/guzzle@6.0.0']);
  const pip = parseManifest(JSON.stringify({ _meta: {}, default: { requests: { version: '==2.19.0' } }, develop: { pytest: { version: '==7.0.0' } } }));
  assert.equal(pip.type, 'Pipfile.lock'); assert.deepEqual(pip.packages.map((p) => `${p.name}@${p.version}`), ['requests@2.19.0', 'pytest@7.0.0']);
});

test('detection and errors', () => {
  assert.equal(detectType('{"name":"x","dependencies":{}}'), 'package.json');
  assert.equal(detectType('anything', 'sub/dir/requirements-dev.txt'), 'requirements.txt');
  assert.throws(() => parseManifest(''), ManifestError);
  assert.throws(() => parseManifest('{not json', { type: 'package.json' }), /not valid JSON/);
  assert.throws(() => parseManifest('{"foo": 1}'), /could not detect/);
});

test('readPackageList validates ecosystem, name, exact version and size', () => {
  assert.deepEqual(readPackageList([{ ecosystem: 'pypi', name: 'requests', version: '2.19.0' }], 5).packages[0], { ecosystem: 'PyPI', name: 'requests', version: '2.19.0', pinned: true, spec: '2.19.0' });
  assert.match(readPackageList([{ ecosystem: 'cobol', name: 'x', version: '1' }], 5).error, /ecosystem/);
  assert.match(readPackageList([{ name: 'x', version: '^1.0' }], 5).error, /exact version/);
  assert.match(readPackageList([{ name: '', version: '1.0.0' }], 5).error, /name/);
  assert.match(readPackageList(Array(6).fill({ name: 'x', version: '1.0.0' }), 5).error, /at most 5/);
  assert.match(readPackageList([], 5).error, /non-empty/);
});
