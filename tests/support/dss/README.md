# EU DSS as an independent judge

`DssJudge.java` validates a signed file with the European Commission's
[DSS](https://github.com/esig/dss) library, an implementation independent
of trebaruna, and prints one line per signature and per timestamp;
`judge.go` runs it and reads the verdict for the Go tests.
`tests/signing/integration/dss_judge_test.go` signs CAdES, XAdES, PAdES and
an ASiC-E container at their highest levels and checks what DSS says, and
`tests/signing/token/brainpool_cgo_test.go` has it judge what a card with a
Brainpool key signs (SoftHSM, cgo).

The test skips unless `DSS_LIB` names a directory holding DSS's jars and
their dependencies. `pom.xml` lists them; with Maven and Java 17 or later:

```bash
cd tests/support/dss
mvn -B dependency:copy-dependencies -DoutputDirectory="$HOME/.cache/trebaruna-dss/lib"
cd ../../..
make check-dss DSS_LIB="$HOME/.cache/trebaruna-dss/lib"
```

The test asks of each signature what a validator should find: DSS's
indication TOTAL_PASSED, the signature intact and valid with every
reference found, every timestamp's imprint matching what it seals, and
the baseline level trebaruna meant (BASELINE-LTA for the archival ones).
A detached CAdES-T carries no revocation, so offline DSS may leave it
undecided, but only for that reason.

What DSS found the first time it ran, all fixed: the ats-hash-index-v3
left SHA-256 out (0.104.1), the CAdES revocation values were not laid out
as RFC 5126 says (0.104.2), XAdES-LT lacked the signer's issuers, and no
format carried the timestamp authority's validation data (0.104.3).

The judge runs offline: no certificate is fetched and no trusted list is
read. The self-signed certificates the file carries (the tests' authority
and timestamp authority) are taken as trust anchors, so the verdict is
about the signature itself, not about a root DSS was never given.
