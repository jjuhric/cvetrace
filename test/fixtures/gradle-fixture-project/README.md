# gradle-fixture-project

Pins `org.apache.logging.log4j:log4j-core:2.14.1` via `implementation '...'`, the same
CVE-2021-44228 ("Log4Shell") package/version used in `java-fixture-project`. Includes a
real Gradle wrapper (`gradlew`/`gradlew.bat`) so `test/e2e.test.js` can verify cvetrace's
actual Gradle invocation path (not the static-parsing fallback) end-to-end. Requires Java
to be installed to run — see the root README.
