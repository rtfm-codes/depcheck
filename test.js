const { scanPackageJson, checkVulnerabilities, formatReport } = require('./src/scanner');
const fs = require('fs');
const path = require('path');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log('\x1b[32m✓ ' + name + '\x1b[0m');
    passed++;
  } catch (e) {
    console.log('\x1b[31m✗ ' + name + '\x1b[0m');
    console.log('  ' + e.message);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

// Test scanPackageJson
test('scanPackageJson returns object with dependencies', () => {
  const result = scanPackageJson('.');
  assert(typeof result === 'object', 'Should return object');
  assert('dependencies' in result || 'devDependencies' in result || 'name' in result, 'Should have deps or name');
});

test('scanPackageJson returns error for missing file', () => {
  const result = scanPackageJson('/nonexistent/path');
  assert(result.error, 'Should return error for missing file');
});

// Test checkVulnerabilities
test('checkVulnerabilities finds vulnerable lodash', () => {
  const deps = {
    dependencies: { 'lodash': '^4.17.15' },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps);
  assert(vulns.length > 0, 'Should find vulnerability');
  assert(vulns[0].name === 'lodash', 'Should be lodash');
});

test('checkVulnerabilities finds vulnerable minimist', () => {
  const deps = {
    dependencies: { 'minimist': '1.2.0' },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps);
  assert(vulns.length > 0, 'Should find vulnerability');
  assert(vulns[0].severity === 'critical', 'Should be critical');
});

test('checkVulnerabilities ignores safe versions', () => {
  const deps = {
    dependencies: { 'lodash': '^4.17.21' },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps);
  assert(vulns.length === 0, 'Should not find vulnerabilities for safe version');
});

test('checkVulnerabilities respects critical filter', () => {
  const deps = {
    dependencies: {
      'lodash': '4.17.15',
      'minimist': '1.2.0'
    },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps, { critical: true });
  assert(vulns.length === 1, 'Should only find critical');
  assert(vulns[0].name === 'minimist', 'Should be minimist');
});

test('checkVulnerabilities respects package filter', () => {
  const deps = {
    dependencies: {
      'lodash': '4.17.15',
      'minimist': '1.2.0'
    },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps, { package: 'lodash' });
  assert(vulns.length === 1, 'Should only find lodash');
  assert(vulns[0].name === 'lodash', 'Should be lodash');
});

// Test formatReport
test('formatReport returns string', () => {
  const vulns = [{ name: 'test', version: '1.0.0', severity: 'high', cve: 'CVE-2021-0000', desc: 'Test', fix: '2.0.0' }];
  const report = formatReport(vulns);
  assert(typeof report === 'string', 'Should return string');
  assert(report.includes('test'), 'Should include package name');
});

test('formatReport returns valid JSON with --json flag', () => {
  const vulns = [{ name: 'test', version: '1.0.0', severity: 'high', cve: 'CVE-2021-0000', desc: 'Test', fix: '2.0.0' }];
  const report = formatReport(vulns, { json: true });
  const parsed = JSON.parse(report);
  assert(Array.isArray(parsed), 'Should be valid JSON array');
  assert(parsed[0].name === 'test', 'Should contain vulnerability data');
});

test('formatReport shows success message when no vulnerabilities', () => {
  const report = formatReport([]);
  assert(report.includes('No vulnerabilities found'), 'Should show success message');
});

console.log('\n' + passed + '/' + (passed + failed) + ' tests passed\n');

if (failed > 0) process.exit(1);
