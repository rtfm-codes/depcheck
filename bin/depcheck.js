#!/usr/bin/env node

const { scanPackageJson, checkVulnerabilities, formatReport, KNOWN_VULNS } = require('../src/scanner');

const args = process.argv.slice(2);

function parseArgs(args) {
  const options = {
    path: '.',
    critical: false,
    json: false,
    package: null,
    help: false,
    list: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--critical' || arg === '-c') {
      options.critical = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--list' || arg === '-l') {
      options.list = true;
    } else if (arg === '--package' || arg === '-p') {
      options.package = args[++i];
    } else if (!arg.startsWith('-')) {
      options.path = arg;
    }
  }

  return options;
}

function showHelp() {
  console.log(`
  depcheck - scan dependencies for vulnerabilities. RTFM.

  Usage:
    depcheck [path] [options]

  Options:
    -c, --critical    Show only critical vulnerabilities
    --json            Output as JSON
    -p, --package     Check specific package (e.g., lodash@4.17.0)
    -l, --list        List all known vulnerabilities in database
    -h, --help        Show this help

  Examples:
    depcheck                     # scan current directory
    depcheck ./my-project        # scan specific path
    depcheck --critical          # only critical issues
    depcheck --json              # JSON output
    depcheck -p lodash           # check specific package

  Docs:    https://rtfm.codes/depcheck
  Issues:  https://github.com/rtfm-codes/depcheck/issues

  rtfm.codes - read the fine manual
`);
}

function showList() {
  console.log('\n  Known vulnerabilities database:\n');
  for (const [name, vuln] of Object.entries(KNOWN_VULNS)) {
    const color = vuln.severity === 'critical' ? '\x1b[31m' : vuln.severity === 'high' ? '\x1b[33m' : '\x1b[34m';
    const reset = '\x1b[0m';
    console.log('  ' + color + name + ' <' + vuln.below + reset);
    console.log('    ' + vuln.cve + ' - ' + vuln.desc + '\n');
  }
}

function main() {
  const options = parseArgs(args);

  if (options.help) {
    showHelp();
    process.exit(0);
  }

  if (options.list) {
    showList();
    process.exit(0);
  }

  console.log('\n  Scanning package.json...');

  const deps = scanPackageJson(options.path);

  if (deps.error) {
    console.error('\n  \x1b[31mError: ' + deps.error + '\x1b[0m\n');
    process.exit(1);
  }

  const vulns = checkVulnerabilities(deps, options);
  const report = formatReport(vulns, options);

  console.log(report);

  if (vulns.length > 0) {
    process.exit(1);
  }
}

main();
