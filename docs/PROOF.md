# Proof of work

How Work Zone is checked, what was attacked, and what was found. Everything here can be re-run
by anyone from this repository.

## Every release

Built in the cloud from this source by [release.yml](../.github/workflows/release.yml), on Windows,
Mac and Linux. A release is only published if all of this passes on all three:

1. **Every automatic test:** 135 Python and 62 JavaScript tests. Every safety check has a test
   that proves it can say no.
2. **The packed app checks itself:** every plug label is valid, a plug is signed and verified, a
   changed byte is refused, and the dashboard is served.
3. **The official catalog is signed and re-checked** with exactly the rules a download gets.
4. Fingerprints (`SHA256SUMS.txt`) are published next to every download.

Run the tests yourself:

```bash
python -m unittest discover -s tests
node --test --test-concurrency=1 "tests/js/*.test.mjs"
python tools/launch.py --check
```

## What is tested to fail

| Attack | Result |
|---|---|
| Change any single byte of a signed plug | Refused (tested on every byte, by two separate checkers) |
| Plug tries 15 ways to escape its box (`examples/escape-test`) | All blocked |
| Plug asks for undeclared internet, files, camera, identity | Refused, logged on its report card |
| Another website or your home network tries to reach the helper | Refused (this computer only, token and origin checks) |
| A script clicks risky buttons (make key, sign, go online, devices) | Ignored: needs press-and-hold, a one-time pass, and in strict mode a typed `yes` |
| Runaway loop of risky actions | Stopped after 5 a minute |
| Fake or tampered plug in the official catalog | Refused: fingerprint, signature and official key are all checked |
| Old catalog replayed to hand out old versions | Refused |
| Download redirected to another site or to plain http | Refused |
| File names like `CON`, `..\..\`, `C:\` in dropped files | Refused |
| Hidden text-direction characters ("Trojan Source") | Refused in labels and published files |

## Independent reviews

Each security-sensitive change was reviewed by a separate reviewer who only read the code. Real
findings so far, all fixed and covered by tests:

- Risky-action confirmations could be flooded; now one question at a time, refusals count.
- Two requests at the same moment could beat the rate limit; now checked in one locked step.
- Look-alike terminal questions; now a matching code is shown in both places.
- Catalog powers list wasn't checked; now it is, and the real powers prompt always comes first.
- An old catalog could be replayed; now refused.

## Honest limits

Listed in [SECURITY.md](../SECURITY.md): one request can leave before a navigating plug is pulled;
WebRTC is removed by a patch; the gateway checks names, not resolved addresses; a plug can keep its
own frame busy. Not yet independently audited by a security firm.

## Why it's safe to publish the code

Work Zone doesn't rely on its code being secret. Its safety comes from checks that hold even when
everyone can read them (signatures, the sealed box, deny by default). The only secret is the
official signing key, which is never in this repository. Anyone who finds a crack can report it
privately (Security tab, "Report a vulnerability") so it's fixed before it's abused.
