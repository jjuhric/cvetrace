# node-fixture-project

Pins `minimist@0.0.8`, which is affected by
[GHSA-vh95-rmgr-6w4m](https://github.com/advisories/GHSA-vh95-rmgr-6w4m) /
[CVE-2020-7598](https://nvd.nist.gov/vuln/detail/CVE-2020-7598) (prototype pollution,
fixed in 0.2.1/1.2.3+). Used by `test/e2e.test.js` to verify `cvetrace scan` reports
a known CVE end-to-end.
