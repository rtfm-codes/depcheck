# depcheck

Scan your dependencies for known vulnerabilities. Fast. Simple. RTFM.

## Install

```bash
npm install -g depcheck-cli
```

## Usage

```bash
# Scan current directory
depcheck

# Scan specific path
depcheck ./my-project

# Only critical vulnerabilities
depcheck --critical
depcheck -c

# JSON output
depcheck --json

# Check specific package
depcheck --package lodash
depcheck -p lodash@4.17.0

# List known vulnerabilities
depcheck --list

# Help
depcheck --help
```

## Output

```
$ depcheck

  Scanning package.json...

  Found 2 vulnerabilities:

  ✗ minimist@1.2.0
    Severity: CRITICAL
    CVE: CVE-2021-44906
    Issue: Prototype Pollution
    Fix: upgrade to >=1.2.6

  ✗ lodash@4.17.15
    Severity: HIGH
    CVE: CVE-2021-23337
    Issue: Command Injection
    Fix: upgrade to >=4.17.21

  Summary: 1 critical, 1 high, 0 medium, 0 low

  Run 'npm update' to fix vulnerabilities
```

## Exit codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities found or error

## License

MIT

---

rtfm.codes - read the fine manual
