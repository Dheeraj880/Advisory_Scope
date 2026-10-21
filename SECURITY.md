# Security policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability")
rather than a public issue. I aim to acknowledge reports within 3 business days.

## Scope

In scope: the `advisory-scope` code in this repository and its GitHub Actions workflows. Of
particular interest are ways untrusted input (advisory text, Terraform under review, or
model output steered by prompt injection) could bypass the deterministic checks, or reach
code execution or the filesystem.

## Supported versions

Only the latest commit on `main` is supported.
