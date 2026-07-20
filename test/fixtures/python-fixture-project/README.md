# python-fixture-project

Pins `PyYAML==5.3`, which is affected by
[GHSA-8q59-q68h-6hv4](https://github.com/advisories/GHSA-8q59-q68h-6hv4) /
[CVE-2020-14343](https://nvd.nist.gov/vuln/detail/CVE-2020-14343) (arbitrary code
execution via `yaml.load`, fixed in 5.4+). Used by `test/e2e.test.js` to verify
`cvetrace scan` reports a known CVE end-to-end for the PyPI ecosystem.
