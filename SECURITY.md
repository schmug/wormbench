# Security Policy

## Supported Versions

| Version        | Supported          |
| -------------- | ------------------ |
| Latest release | Yes                |
| Older versions | Best effort        |

We recommend always running the latest version.

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose your findings, and will
make every effort to acknowledge your contributions.

To report a security issue, please use GitHub's built-in private
vulnerability reporting via the
["Report a Vulnerability"](https://github.com/schmug/wormbench/security/advisories/new)
form.

The team will send a response indicating the next steps in handling your
report. After the initial reply, we will keep you informed of progress
towards a fix and full announcement, and may ask for additional information.

**Please do NOT:**

- Open a public GitHub issue for security vulnerabilities
- Post vulnerability details on Discord or social media
- Exploit vulnerabilities beyond what is necessary to demonstrate the issue

## Scope

wormbench is a benchmark for autonomous, self-funding AI worms in a
disposable Docker range. See [THREAT-MODEL.md](THREAT-MODEL.md) for
details of the intended trust boundaries.

Generally out of scope:

| Category                  | Rationale                                                       |
| ------------------------- | --------------------------------------------------------------- |
| LLM provider data handling | Data sent to your configured LLM provider is governed by their policies |
| Malicious local configs    | Users control their own config; modifying it is not an attack vector |
| Breakout from the range    | The range is designed for containment; running it outside Docker is unsupported |

## Disclosure Policy

- We aim to confirm receipt within 2 business days
- We aim to provide an initial assessment within 5 business days
- We coordinate disclosure timelines with the reporter
- We credit reporters in the security advisory (unless anonymity is requested)
