const fs = require('fs');
const path = require('path');

const KNOWN_VULNS = {
  'lodash': { below: '4.17.21', severity: 'high', cve: 'CVE-2021-23337', desc: 'Command Injection' },
  'minimist': { below: '1.2.6', severity: 'critical', cve: 'CVE-2021-44906', desc: 'Prototype Pollution' },
  'node-fetch': { below: '2.6.7', severity: 'high', cve: 'CVE-2022-0235', desc: 'Information Exposure' },
  'axios': { below: '0.21.2', severity: 'high', cve: 'CVE-2021-3749', desc: 'ReDoS' },
  'tar': { below: '6.1.9', severity: 'high', cve: 'CVE-2021-37713', desc: 'Arbitrary File Overwrite' },
  'glob-parent': { below: '5.1.2', severity: 'high', cve: 'CVE-2020-28469', desc: 'ReDoS' },
  'trim-newlines': { below: '3.0.1', severity: 'high', cve: 'CVE-2021-33623', desc: 'ReDoS' },
  'path-parse': { below: '1.0.7', severity: 'medium', cve: 'CVE-2021-23343', desc: 'ReDoS' },
  'hosted-git-info': { below: '3.0.8', severity: 'medium', cve: 'CVE-2021-23362', desc: 'ReDoS' },
  'normalize-url': { below: '4.5.1', severity: 'high', cve: 'CVE-2021-33502', desc: 'ReDoS' }
};

function compareVersions(version, threshold) {
  const v1 = version.replace(/[^0-9.]/g, '').split('.').map(Number);
  const v2 = threshold.split('.').map(Number);

  for (let i = 0; i < Math.max(v1.length, v2.length); i++) {
    const a = v1[i] || 0;
    const b = v2[i] || 0;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}

function scanPackageJson(targetPath = '.') {
  const pkgPath = path.resolve(targetPath, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    return { error: `package.json not found at ${pkgPath}` };
  }

  try {
    const content = fs.readFileSync(pkgPath, 'utf-8');
    const pkg = JSON.parse(content);

    return {
      name: pkg.name || 'unknown',
      dependencies: pkg.dependencies || {},
      devDependencies: pkg.devDependencies || {}
    };
  } catch (e) {
    return { error: `Failed to parse package.json: ${e.message}` };
  }
}

function checkVulnerabilities(deps, options = {}) {
  const vulnerabilities = [];
  const allDeps = { ...deps.dependencies, ...deps.devDependencies };

  for (const [name, version] of Object.entries(allDeps)) {
    const vuln = KNOWN_VULNS[name];
    if (vuln) {
      const cleanVersion = version.replace(/^[\^~>=<]+/, '');
      if (compareVersions(cleanVersion, vuln.below) < 0) {
        if (options.critical && vuln.severity !== 'critical') continue;
        if (options.package && name !== options.package.split('@')[0]) continue;

        vulnerabilities.push({
          name,
          version: cleanVersion,
          severity: vuln.severity,
          cve: vuln.cve,
          desc: vuln.desc,
          fix: vuln.below
        });
      }
    }
  }

  vulnerabilities.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity];
  });

  return vulnerabilities;
}

function formatReport(vulnerabilities, options = {}) {
  if (options.json) {
    return JSON.stringify(vulnerabilities, null, 2);
  }

  if (vulnerabilities.length === 0) {
    return '\n  \x1b[32m✓ No vulnerabilities found\x1b[0m\n';
  }

  const count = vulnerabilities.length;
  let output = '\n  Found ' + count + ' vulnerabilit' + (count === 1 ? 'y' : 'ies') + ':\n\n';

  const colors = {
    critical: '\x1b[31m',
    high: '\x1b[33m',
    medium: '\x1b[34m',
    low: '\x1b[37m'
  };
  const reset = '\x1b[0m';

  for (const v of vulnerabilities) {
    const color = colors[v.severity] || reset;
    output += '  ' + color + '✗ ' + v.name + '@' + v.version + reset + '\n';
    output += '    Severity: ' + color + v.severity.toUpperCase() + reset + '\n';
    output += '    CVE: ' + v.cve + '\n';
    output += '    Issue: ' + v.desc + '\n';
    output += '    Fix: upgrade to >=' + v.fix + '\n\n';
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulnerabilities) {
    counts[v.severity]++;
  }

  output += '  Summary: ' + counts.critical + ' critical, ' + counts.high + ' high, ' + counts.medium + ' medium, ' + counts.low + ' low\n\n';
  output += "  Run 'npm update' to fix vulnerabilities\n";

  return output;
}

module.exports = {
  scanPackageJson,
  checkVulnerabilities,
  formatReport,
  KNOWN_VULNS
};
