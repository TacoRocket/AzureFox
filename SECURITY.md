# Security Policy

## Supported Versions

AzureFox is currently maintained on the latest release line.

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0.0 | No |

## Reporting A Vulnerability

Please do not open public GitHub issues for suspected security vulnerabilities.

Preferred path:

- use GitHub private vulnerability reporting or a private security advisory if it is available

If private reporting is not available, contact the maintainer directly through GitHub rather than
posting a public issue with exploit details.

When reporting, please include:

- affected version
- reproduction steps
- impact and scope
- any suggested remediation or mitigation

## Scope Notes

AzureFox intentionally enumerates risky cloud posture and attack-surface signals. Reports that a
fixture, lab artifact, or intentionally documented proof environment contains insecure-by-design
test posture are generally not treated as product vulnerabilities by themselves.

Useful security reports usually involve one of these:

- accidental credential exposure in the repo or release artifacts
- supply-chain or release-process weaknesses
- output that overstates proof in a way that could mislead operators materially
- code execution, unsafe file handling, or similar implementation flaws in AzureFox itself
