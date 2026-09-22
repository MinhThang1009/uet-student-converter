# Security Policy

## Scope

This repository is public. The converter may process student data locally, but
real student data, accounts, passwords, and generated workbooks must never be
committed or included in public issues, pull requests, tests, or logs.

## Reporting a vulnerability

Do not open a public issue or pull request with vulnerability details, exposed
secrets, or student data. GitHub private vulnerability reporting is not enabled
for this repository, and no dedicated security contact is published. Until a
private reporting channel is available, do not disclose sensitive details
publicly. If you already have a trusted private contact method for the
maintainer, use it without sending real student data or credentials.

Once a private channel is configured, reports should include:

- description and impact;
- minimal reproduction steps using synthetic data;
- the affected version or commit;
- a mitigation proposal, if available.

Do not send real student data, credentials, or secrets in a report.

## Supported versions

The project publishes GitHub Releases, but it does not currently document a
supported-version window. Include the release tag or commit when reporting an
issue; the maintainer will state which versions receive security fixes.
