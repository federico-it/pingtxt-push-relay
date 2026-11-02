# Security policy

## Supported versions

Security fixes land on `main` and in the latest image (`ghcr.io/federico-it/pingtxt-push-relay`). Please check that
you run the latest version before reporting.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for security problems.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/federico-it/pingtxt-push-relay/security/advisories/new)
(repository → **Security** → **Report a vulnerability**). Only the maintainers can see the report.

Include the affected version, a description of the issue and its impact, steps or a proof of concept to
reproduce it, and any suggested fix.

## What to expect

- We acknowledge the report within **3 working days** and send a first assessment within **10 days**.
- We work on a fix in a private advisory and credit you when it is published, unless you prefer to stay
  anonymous.
- Please give us reasonable time to release a fix before disclosing the issue publicly. We aim for
  90 days at most.

## Scope

In scope: the relay API (hub tokens, device handles, push and Live Activity routes), its rate limits and the Docker image.

Out of scope: abuse that only reaches phones that enrolled with the attacker's own hub, problems that need an already compromised host, missing hardening of your own
reverse proxy or TLS setup, denial of service by sending large amounts of traffic, and reports from
automated scanners without a working impact.

Problems in the pingtxt hub, agent or web UI belong to
[pingtxt's security policy](https://github.com/federico-it/pingtxt/security/policy).
