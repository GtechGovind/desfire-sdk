# Support

## Public support

Use repository issues for reproducible defects, feature proposals, documentation problems, build
questions, and integration questions. Start with the structured issue forms when they match the
request. Before opening an issue:

1. read the [README](README.md), [coverage matrix](spec/coverage.md), and relevant binding README;
2. search existing issues for the same behavior;
3. reproduce with the newest available revision or state why that is not possible; and
4. remove keys, credentials, personal card identifiers, payment data, and restricted material.

A useful report identifies the source revision or package version, operating system and
architecture, SDK layer, transport and framing, command or workflow, expected result, actual result,
and the smallest reproducible example. State whether evidence came from a host fixture,
cross-compile, emulator, physical card/reader, or production environment.

Questions may use a blank issue when no form fits. Public support is provided on a best-effort basis;
the project does not promise a response time or provide emergency operational support.

## Private and sensitive reports

Do not disclose a suspected vulnerability in a public issue. Follow [SECURITY.md](SECURITY.md) and
use a private contact method exposed by the repository host or owner. Do not send production keys,
complete authenticated APDU traces, personal data, or vendor-restricted documents even through a
private channel unless a maintainer has established an appropriate handling process.

## Support boundary

The project can help interpret SDK behavior and reproducible source or package failures. Reader
activation, card provisioning, application authorization policy, SAM/HSM services, production key
custody, certification, and field incident response belong to the integrating organization and its
hardware or platform vendors.

The current release is not physically qualified on EV3 cards or production readers. Unsupported
operations remain listed in [spec/coverage.md](spec/coverage.md); opening a raw channel does not
convert them into supported typed workflows.
