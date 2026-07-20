# java-fixture-project

Pins `org.apache.logging.log4j:log4j-core@2.14.1` (via a `${log4j.version}` property,
to also exercise property resolution), which is affected by
[GHSA-jfh8-c2jp-5v3q](https://github.com/advisories/GHSA-jfh8-c2jp-5v3q) /
[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) — "Log4Shell", fixed
in 2.15.0+. Used by `test/e2e.test.js` to verify `cvetrace scan` reports a known CVE
end-to-end for the Maven ecosystem.
